//! RustIO 服务器入口。
//!
//! ## 生产部署 TLS
//!
//! RustIO 仅监听 HTTP(TcpListener),不内置 TLS。生产环境必须在反向代理后部署:
//!
//! ### Caddy (推荐,自动 Let's Encrypt)
//! ```text
//! rustio.example.com {
//!     reverse_proxy 127.0.0.1:9000
//! }
//! ```
//!
//! ### Nginx
//! ```nginx
//! server {
//!     listen 443 ssl http2;
//!     server_name rustio.example.com;
//!     ssl_certificate     /etc/ssl/certs/rustio.pem;
//!     ssl_certificate_key /etc/ssl/private/rustio.key;
//!     location / {
//!         proxy_pass http://127.0.0.1:9000;
//!         proxy_set_header X-Forwarded-For $remote_addr;
//!         proxy_set_header X-Real-IP $remote_addr;
//!         proxy_set_header Host $host;
//!     }
//! }
//! ```
//!
//! 注意:X-Forwarded-For / X-Real-IP 用于登录速率限制的客户端 IP 识别,必须转发。
//!
//! 生产环境变量:
//! ```bash
//! export RUSTIO_JWT_SECRET="$(openssl rand -base64 48)"
//! export RUSTIO_ROOT_USER="admin"
//! export RUSTIO_ROOT_PASSWORD="$(openssl rand -base64 32)"
//! export RUSTIO_CONSOLE_PASSWORD="$(openssl rand -base64 32)"
//! export RUSTIO_CORS_ORIGIN="https://rustio.example.com"
//! ```

use std::net::SocketAddr;

use anyhow::Context;
use rustio_admin::{build_router, AppState};
use tower_http::{
    classify::ServerErrorsFailureClass,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::{error, info, Level};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let launch = parse_launch_config()?;
    if let Some(data_dir) = launch.data_dir {
        std::env::set_var("RUSTIO_DATA_DIR", data_dir);
    }
    if let Some(addr) = launch.addr {
        std::env::set_var("RUSTIO_ADDR", addr);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "rustio=debug,rustio_admin=debug,tower_http=info".into()),
        )
        .init();

    ensure_secure_startup()?;

    let state = AppState::bootstrap();
    // 启动元数据 raft:集群模式用配置的 node_id(RUSTIO_CLUSTER_NODE_ID),单机用 1。
    // 失败降级本地直写(单机仍可用)。
    let raft_node_id = if state.local_node_id > 0 {
        state.local_node_id
    } else {
        1
    };
    if let Err(err) = state.init_metadata_raft(raft_node_id).await {
        tracing::warn!("元数据 raft 启动失败,降级本地直写: {err}");
    }
    // console CORS 已下沉 build_router(仅作用于管理路由);S3 路由走 per-bucket CORS。
    let app = build_router(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(false),
                )
                .on_failure(
                    |failure: ServerErrorsFailureClass,
                     latency: std::time::Duration,
                     _span: &tracing::Span| {
                        error!(
                            classification = %failure,
                            latency_ms = latency.as_millis(),
                            "HTTP 请求失败 / HTTP request failed"
                        );
                    },
                ),
        );

    let addr = resolve_listen_addr()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("RustIO 启动成功");
    info!("管理端 Web: http://{}", addr);
    info!("管理 API: http://{}", addr);
    info!("S3 兼容端点: http://{}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// 启动期安全校验:生产环境必须显式配置 JWT 密钥与 root 凭据,否则拒绝启动。
/// 设置 `RUSTIO_ALLOW_INSECURE=1` 可显式降级为开发模式(仅本地/测试使用)。
fn ensure_secure_startup() -> anyhow::Result<()> {
    if env_flag_enabled("RUSTIO_ALLOW_INSECURE") {
        tracing::warn!(
            "⚠ RUSTIO_ALLOW_INSECURE 已启用:跳过启动安全校验,使用默认凭据/弱密钥。仅限本地开发"
        );
        return Ok(());
    }

    let mut missing = Vec::new();
    if std::env::var("RUSTIO_JWT_SECRET")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_none()
    {
        missing.push("RUSTIO_JWT_SECRET");
    }
    let has_root_user = ["RUSTIO_ROOT_USER", "MINIO_ROOT_USER"]
        .iter()
        .any(|key| std::env::var(key).is_ok_and(|v| !v.trim().is_empty()));
    if !has_root_user {
        missing.push("RUSTIO_ROOT_USER");
    }
    let has_root_password = ["RUSTIO_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD"]
        .iter()
        .any(|key| std::env::var(key).is_ok_and(|v| !v.trim().is_empty()));
    if !has_root_password {
        missing.push("RUSTIO_ROOT_PASSWORD");
    }
    if std::env::var("RUSTIO_CONSOLE_PASSWORD")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_none()
    {
        missing.push("RUSTIO_CONSOLE_PASSWORD");
    }

    if missing.is_empty() {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "拒绝以默认凭据启动:缺少环境变量 {} / refusing to start with default credentials: missing {}。\
         生产部署请设置上述变量;本地开发可设 RUSTIO_ALLOW_INSECURE=1 显式降级",
        missing.join(", "),
        missing.join(", ")
    ))
}

fn env_flag_enabled(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn resolve_listen_addr() -> anyhow::Result<SocketAddr> {
    let default_addr = "0.0.0.0:9000";
    let value = std::env::var("RUSTIO_ADDR")
        .or_else(|_| std::env::var("MINIO_ADDRESS"))
        .unwrap_or_else(|_| default_addr.to_string());
    let normalized = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.clone()
    };
    normalized
        .parse::<SocketAddr>()
        .with_context(|| format!("监听地址无效 / invalid listen address value: {value}"))
}

#[derive(Debug, Default)]
struct LaunchConfig {
    addr: Option<String>,
    data_dir: Option<String>,
}

fn parse_launch_config() -> anyhow::Result<LaunchConfig> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(|v| v == "server").unwrap_or(false) {
        args.remove(0);
    }

    let mut config = LaunchConfig::default();
    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--address" | "-a" => {
                i += 1;
                let value = args.get(i).cloned().ok_or_else(|| {
                    anyhow::anyhow!("--address 缺少参数 / --address requires a value")
                })?;
                config.addr = Some(value);
            }
            "--data-dir" => {
                i += 1;
                let value = args.get(i).cloned().ok_or_else(|| {
                    anyhow::anyhow!("--data-dir 缺少参数 / --data-dir requires a value")
                })?;
                config.data_dir = Some(value);
            }
            _ if arg.starts_with('-') => {
                return Err(anyhow::anyhow!("未知参数: {arg} / unknown argument: {arg}"));
            }
            _ => {
                if config.data_dir.is_none() {
                    config.data_dir = Some(arg.to_string());
                } else {
                    return Err(anyhow::anyhow!(
                        "重复的数据目录参数: {arg} / duplicate data directory argument: {arg}"
                    ));
                }
            }
        }
        i += 1;
    }
    Ok(config)
}

fn print_help() {
    println!("RustIO 启动命令");
    println!();
    println!("用法:");
    println!("  rustio");
    println!("  rustio server [DATA_DIR] [--address HOST:PORT]");
    println!();
    println!("示例:");
    println!("  rustio server ./data --address :9000");
    println!("  RUSTIO_ADDR=:9000 RUSTIO_DATA_DIR=./data rustio");
}
