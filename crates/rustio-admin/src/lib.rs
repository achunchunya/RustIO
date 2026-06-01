// axum 处理器普遍返回 `Result<_, Response>`，Response 本身是较大的类型。
// 将其装箱反而引入额外堆分配且与框架惯用法相悖，因此在 crate 级豁免该 lint。
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod error;
pub mod routes;
pub mod state;

pub use routes::build_router;
pub use state::AppState;

/// 测试专用：进程级全局环境变量互斥锁。
///
/// 多个测试模块会设置同一进程级环境变量（如 `RUSTIO_DATA_DIR`），
/// 必须共享同一把锁才能在并行测试下互斥，避免相互覆盖导致的偶发失败。
#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}
