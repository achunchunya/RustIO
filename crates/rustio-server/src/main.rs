use std::net::SocketAddr;

use anyhow::Context;
use rustio_admin::{build_router, AppState};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

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

    let state = AppState::bootstrap();
    let app = build_router(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr = resolve_listen_addr()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("RustIO 启动成功");
    info!("管理端 Web: http://{}", addr);
    info!("管理 API: http://{}", addr);
    info!("S3 兼容端点: http://{}", addr);
    info!("默认账号: admin / rustio-admin");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
