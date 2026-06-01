use axum::{http::StatusCode, response::IntoResponse};

pub(crate) async fn health_live() -> impl IntoResponse {
    StatusCode::OK
}

pub(crate) async fn health_ready() -> impl IntoResponse {
    StatusCode::OK
}

pub(crate) async fn health_cluster() -> impl IntoResponse {
    StatusCode::OK
}
