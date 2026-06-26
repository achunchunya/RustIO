// axum 处理器普遍返回 `Result<_, Response>`，Response 本身是较大的类型。
// 将其装箱反而引入额外堆分配且与框架惯用法相悖，因此在 crate 级豁免该 lint。
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod error;
pub(crate) mod io_uring_bridge;
pub mod routes;
pub mod state;

pub use routes::build_router;
pub use state::AppState;
