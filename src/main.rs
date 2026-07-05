use std::{fmt::format, net::SocketAddr, sync::Arc};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use sqlx::{
    PgPool,
    postgres::PgDatabaseError,
    prelude::FromRow,
    types::chrono::{DateTime, Utc},
};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
struct Task {
    id: Uuid,
    title: String,
    description: Option<String>,
    completed: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateTaskPayload {
    title: String,
    description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdateTaskPayload {
    title: Option<String>,
    description: Option<String>,
    completed: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct User {
    id: Uuid,
    email: String,
    password_hash: String,
    password_salt: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RegisterUserPayload {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginUserPayload {
    email: String,
    password: String,
}

struct AppState {
    db_pool: PgPool,
}

#[derive(Debug, Serialize)]
enum ApiError {
    UserAlreadyExists(String),
    InvalidCredentials,
    TaskNotFound(Uuid),          // 404
    InvalidInput(String),        // 400
    DuplicateEntry(String),      // 409
    InternalServerError(String), // 500
    DbError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message, error_type) = match self {
            ApiError::UserAlreadyExists(email) => (
                StatusCode::CONFLICT,
                format!("User with email '{email}' already exists."),
                "UserAlreadyExists",
            ),
            ApiError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password".to_string(),
                "InvalidCredentials",
            ),
            ApiError::TaskNotFound(id) => (
                StatusCode::NOT_FOUND,
                format!("Task with ID {id} not found."),
                "TaskNotFound",
            ),
            ApiError::InvalidInput(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid input: {msg}."),
                "InvalidInput",
            ),
            ApiError::DuplicateEntry(id) => (
                StatusCode::CONFLICT,
                format!("Task with ID {id} already exists"),
                "DuplicateEntry",
            ),
            ApiError::InternalServerError(msg) => {
                eprintln!("Internal server error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An unexpected internal server error occured".to_string(),
                    "InternalServerError",
                )
            }
            ApiError::DbError(msg) => {
                eprintln!("Internal Server Error {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An unexpected internal server error occured.".to_string(),
                    "DatabaseError",
                )
            }
        };
        let body = Json(serde_json::json!({
            "error_code": status.as_u16(),
            "message": error_message,
            "error_type": error_type
        }));

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        eprintln!("SQLx Error: {err:?}");
        match err {
            sqlx::Error::RowNotFound => ApiError::InvalidCredentials,
            sqlx::Error::Database(db_err) => {
                // Downcast to Postgres-specific error to access .detail()
                if let Some(pg_err) = db_err.try_downcast_ref::<PgDatabaseError>() {
                    match pg_err.code() {
                        "23505" => {
                            let detail = pg_err
                                .detail()
                                .unwrap_or("A record with that unique value already exists.");
                            if detail.contains("email") {
                                ApiError::UserAlreadyExists("".to_string())
                            } else {
                                ApiError::DbError(format!("Unique constraint violated: {detail}"))
                            }
                        }
                        "23502" => ApiError::InvalidInput(format!(
                            "A required field is missing. Detail: {}",
                            pg_err.detail().unwrap_or("No specific details available.")
                        )),
                        _ => ApiError::DbError(format!("Uncategorized database error: {pg_err}")),
                    }
                } else {
                    ApiError::DbError(db_err.to_string())
                }
            }
            sqlx::Error::PoolTimedOut => ApiError::InternalServerError(
                "Database connection pool exhausted. Please try again later.".to_string(),
            ),
            sqlx::Error::Io(io_err) => {
                ApiError::InternalServerError(format!("Database I/O error: {io_err}"))
            }
            sqlx::Error::Decode(decode_err) => ApiError::InternalServerError(format!(
                "Database data decoding error. Check schema and types: {decode_err}"
            )),
            _ => ApiError::DbError(err.to_string()),
        }
    }
}

async fn register_user(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<RegisterUserPayload>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if payload.email.is_empty() || payload.password.is_empty() {
        return Err(ApiError::InvalidInput(
            "Email and password is required.".to_string(),
        ));
    }
    if !payload.email.contains('@') {
        return Err(ApiError::InvalidInput("Invalid email format.".to_string()));
    }
    if payload.password.len() < 8 {
        return Err(ApiError::InvalidInput(
            "Password must be at least 8 characters long.".to_string(),
        ));
    }

    // Generate a random salt for password hashing.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // Hash the passord
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| ApiError::InternalServerError(format!("Failed to has password: {e}")))?
        .to_string();

    // Store salt as base64 string
    let salt_b64 = general_purpose::STANDARD.encode(salt.as_str());

    // Insert new user into the database
    let created_user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (email, password_hash, password_salt)
        VALUES ($1, $2, $3)
        RETURNING id, email, password_hash, password_salt, created_at, updated_at
        "#,
        payload.email,
        password_hash,
        salt_b64
    )
    .fetch_one(&app_state.db_pool)
    .await;

    match created_user {
        Ok(user) => Ok((
            StatusCode::CREATED,
            Json(serde_json::json!(
                {
                    "message": "User registered successfully.",
                    "user_id": user.id,
                    "email": user.email
                }
            )),
        )),
        Err(sqlx::Error::Database(db_err)) => {
            if let Some(pg_err) = db_err.try_downcast_ref::<PgDatabaseError>() {
                if pg_err.code() == "23505" {
                    return Err(ApiError::UserAlreadyExists(payload.email));
                }
            }
            Err(sqlx::Error::Database(db_err.into()).into())
        }
        Err(e) => Err(e.into()),
    }
}

async fn login_user(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<LoginUserPayload>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Validation
    if payload.email.is_empty() || payload.password.is_empty() {
        return Err(ApiError::InvalidInput(
            "Email and password are required".to_string(),
        ));
    }

    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, email, password_hash, password_salt, created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&app_state.db_pool)
    .await?;

    let user = match user {
        Some(u) => u,
        None => return Err(ApiError::InvalidCredentials),
    };

    // Decode stored salt
    let salt = SaltString::from_b64(&user.password_salt);

    // Verify password
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&user.password_hash).expect("Failed to parse hash string");
    let is_valid = argon2
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok();
    if !is_valid {
        return Err(ApiError::InvalidCredentials);
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!(
            {
                "message": "Login successful",
                "user_id": user.id,
                "email": user.email
                // Add token/session info here in future sections
            }
        )),
    ))
}

async fn get_task_by_id(
    State(app_state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Task>, ApiError> {
    let task = sqlx::query_as!(
        Task,
        r#"
        SELECT id, title, description, completed, created_at, updated_at
        FROM tasks
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&app_state.db_pool)
    .await?
    .ok_or(ApiError::TaskNotFound(id))?;
    Ok(Json(task))
}

async fn create_task_handler(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<CreateTaskPayload>,
) -> Result<(StatusCode, Json<Task>), ApiError> {
    let id = Uuid::new_v4();
    let new_task = sqlx::query_as!(
        Task,
        r#"
        INSERT INTO tasks (title, description)
        VALUES ($1, $2)
        RETURNING *
        "#,
        payload.title,
        payload.description
    )
    .fetch_one(&app_state.db_pool)
    .await?;

    Ok((StatusCode::CREATED, Json(new_task)))
}

async fn get_all_tasks(
    State(app_state): State<Arc<AppState>>,
) -> Result<Json<Vec<Task>>, ApiError> {
    let tasks = sqlx::query_as!(
        Task,
        r#"
        SELECT id, title, description, completed, created_at, updated_at
        FROM tasks
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&app_state.db_pool)
    .await?;

    Ok(Json(tasks))
}

async fn update_task(
    State(app_state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateTaskPayload>,
) -> Result<Json<Task>, ApiError> {
    let updated_task = sqlx::query_as!(
        Task,
        r#"
        UPDATE tasks
        SET
            title = COALESCE($1, title),
            description = COALESCE($2, description),
            completed = COALESCE($3, completed),
            updated_at = NOW()
        WHERE id = $4
        RETURNING *
        "#,
        payload.title,
        payload.description,
        payload.completed,
        id
    )
    .fetch_optional(&app_state.db_pool)
    .await?
    .ok_or(ApiError::TaskNotFound(id))?;

    Ok(Json(updated_task))
}

async fn delete_task(
    State(app_state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let affected_rows = sqlx::query!(
        r#"
        DELETE FROM tasks
        WHERE id = $1
        "#,
        id
    )
    .execute(&app_state.db_pool)
    .await?
    .rows_affected();

    if affected_rows == 0 {
        Err(ApiError::TaskNotFound(id))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

async fn create_app() -> Router {
    dotenvy::dotenv().ok();

    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env or environment");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to PostgreSQL database!");

    println!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run database migrations!");
    println!("Database migrations completed successfully.");

    let app_state = Arc::new(AppState { db_pool: pool });

    Router::new()
        .route("/tasks/{id}", get(get_task_by_id))
        .route("/tasks", post(create_task_handler))
        .route("/tasks", get(get_all_tasks))
        .route("/tasks/{id}", put(update_task))
        .route("/tasks/{id}", delete(delete_task))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .with_state(app_state)
}

#[tokio::main]
async fn main() {
    let app = create_app();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on {addr}");

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.await).await.unwrap();
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{self, Body},
        extract::MatchedPath,
        http::{self, Method, Request, uri},
        response::Response,
    };
    use http_body_util::BodyExt;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    use super::*;

    async fn get_body_string(reponse: Response) -> String {
        let body_bytes = reponse.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    async fn get_body_json<T: for<'de> Deserialize<'de>>(response: Response) -> T {
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    #[tokio::test]
    async fn create_task_test() {
        let app = create_app();
        let payload = CreateTaskPayload {
            title: "Test Task".to_string(),
            description: Some("A task for testing".to_string()),
        };

        let json_payload = serde_json::to_string(&payload).unwrap();

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/tasks")
            .header("Content-Type", "application/json")
            .body(Body::from(json_payload))
            .unwrap();

        let response = app.await.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let created_task: Task = get_body_json(response).await;
        assert_eq!(created_task.title, "Test Task");
        assert!(!created_task.id.is_nil());
    }

    #[tokio::test]
    async fn get_all_tasks_test() {
        let app = create_app().await;

        let create_payload = CreateTaskPayload {
            title: "Task 1".to_string(),
            description: None,
        };

        let create_json = serde_json::to_string(&create_payload).unwrap();

        let create_req = Request::builder()
            .method(http::Method::POST)
            .uri("/tasks")
            .header("Content-Type", "application/json")
            .body(Body::from(create_json))
            .unwrap();

        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);

        let created_task: Task = get_body_json(create_res).await;

        let get_req = Request::builder()
            .method(http::Method::GET)
            .uri("/tasks")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let tasks: Vec<Task> = get_body_json(response).await;

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].title, "Task 1");
    }

    #[tokio::test]
    async fn get_task_by_id_success_test() {
        let app = create_app().await;

        let create_payload = CreateTaskPayload {
            title: "Specific Task".to_string(),
            description: None,
        };
        let create_json = serde_json::to_string(&create_payload).unwrap();

        let create_req = Request::builder()
            .method(http::Method::POST)
            .uri("/tasks")
            .header("Content-Type", "application/json")
            .body(Body::from(create_json))
            .unwrap();

        let created_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(created_res.status(), StatusCode::CREATED);
        let created_task: Task = get_body_json(created_res).await;

        let get_req = Request::builder()
            .uri(format!("/tasks/{}", created_task.id))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(get_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let retrieved_task: Task = get_body_json(response).await;

        assert_eq!(retrieved_task.id, created_task.id);
    }

    #[tokio::test]
    async fn get_task_by_id_not_found_test() {
        let app = create_app().await;

        let nonexistent_id = Uuid::new_v4();

        let get_req = Request::builder()
            .uri(format!("/tasks/{}", nonexistent_id))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(get_req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let error_body: serde_json::Value = get_body_json(response).await;

        assert_eq!(error_body["error_code"], 404);
    }

    #[tokio::test]
    async fn update_task_success_test() {
        let app = create_app().await;

        let create_payload = CreateTaskPayload {
            title: "Original Task".to_string(),
            description: None,
        };
        let create_json = serde_json::to_string(&create_payload).unwrap();
        let create_req = Request::builder()
            .method(http::Method::POST)
            .uri("/tasks")
            .header("Content-Type", "application/json")
            .body(Body::from(create_json))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        let created_task: Task = get_body_json(create_res).await;

        let update_payload = UpdateTaskPayload {
            title: Some("Updated Task Title".to_string()),
            description: Some("New description".to_string()),
            completed: Some(true),
        };
        let update_json = serde_json::to_string(&update_payload).unwrap();

        let update_req = Request::builder()
            .method(http::Method::PUT)
            .uri(format!("/tasks/{}", created_task.id))
            .header("Content-Type", "application/json")
            .body(Body::from(update_json))
            .unwrap();
        let response = app.oneshot(update_req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let updated_task: Task = get_body_json(response).await;
        assert_eq!(updated_task.id, created_task.id);
        assert_eq!(
            updated_task.description,
            Some("New description".to_string())
        );
        assert!(updated_task.completed);
    }

    #[tokio::test]
    async fn delete_task_success_test() {
        let app = create_app().await;

        let create_payload = CreateTaskPayload {
            title: "Task to delete".to_string(),
            description: None,
        };
        let create_json = serde_json::to_string(&create_payload).unwrap();
        let create_req = Request::builder()
            .method(http::Method::POST)
            .uri("/tasks")
            .header("Content-Type", "application/json")
            .body(Body::from(create_json))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        let created_task: Task = get_body_json(create_res).await;

        let delete_req = Request::builder()
            .method(http::Method::DELETE)
            .uri(format!("/tasks/{}", created_task.id))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(delete_req).await.unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let get_after_delete_req = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/tasks/{}", created_task.id))
            .body(Body::empty())
            .unwrap();
        let get_after_delete_res = app.oneshot(get_after_delete_req).await.unwrap();
        assert_eq!(get_after_delete_res.status(), StatusCode::NOT_FOUND);
    }
}
