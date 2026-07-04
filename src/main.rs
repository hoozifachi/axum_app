use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
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

struct AppState {
    db_pool: PgPool,
}

#[derive(Debug, Serialize)]
enum ApiError {
    TaskNotFound(Uuid),
    InvalidInput(String),
    TaskAlreadyExists(Uuid),
    InternalServerError(String),
    DbError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ApiError::TaskNotFound(id) => (
                StatusCode::NOT_FOUND,
                format!("Task with ID {id} not found."),
            ),
            ApiError::InvalidInput(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid input: {msg}."))
            }
            ApiError::TaskAlreadyExists(id) => (
                StatusCode::CONFLICT,
                format!("Task with ID {id} already exists"),
            ),
            ApiError::InternalServerError(msg) => {
                eprintln!("Internal server error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An unexpected internal server error occured".to_string(),
                )
            }
            ApiError::DbError(msg) => {
                eprintln!("Internal Server Error {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An unexpected internal server error occured.".to_string(),
                )
            }
        };
        let body = Json(serde_json::json!({
            "error_code": status.as_u16(),
            "message": error_message,
            "error_type": match status {
                StatusCode::NOT_FOUND => "NotFound",
                StatusCode::BAD_REQUEST => "InvalidInput",
                StatusCode::CONFLICT => "Conflict",
                _ => "ServerError"
            }
        }));

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        eprintln!("SQLx Error: {err:?}");
        match err {
            sqlx::Error::RowNotFound => ApiError::TaskNotFound(Uuid::nil()),
            sqlx::Error::Database(db_err) => {
                // Downcast to Postgres-specific error to access .detail()
                if let Some(pg_err) = db_err.try_downcast_ref::<PgDatabaseError>()
                    && pg_err.code() == "23505"
                {
                    return ApiError::InvalidInput(format!(
                        "Duplicate entry: {}",
                        pg_err
                            .detail()
                            .unwrap_or("A record with that unique value already exists.")
                    ));
                }

                ApiError::DbError(db_err.to_string())
            }
            _ => ApiError::DbError(err.to_string()),
        }
    }
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
