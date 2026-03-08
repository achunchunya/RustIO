use std::env;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use rustio_core::{ApiEnvelope, LoginRequest, LoginResponse};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

#[derive(Debug, Parser)]
#[command(name = "rustio")]
#[command(about = "RustIO admin CLI bootstrap")]
struct Cli {
    #[arg(long, env = "RUSTIO_ENDPOINT", default_value = "http://127.0.0.1:9000")]
    endpoint: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Cluster {
        #[command(subcommand)]
        command: ClusterCommand,
    },
    Iam {
        #[command(subcommand)]
        command: IamCommand,
    },
    Buckets {
        #[command(subcommand)]
        command: BucketCommand,
    },
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Jobs {
        #[command(subcommand)]
        command: JobCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Login {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value = "rustio-admin")]
        password: String,
    },
}

#[derive(Debug, Subcommand)]
enum SystemCommand {
    Info,
    Topology,
    Alignment,
    RaftStatus,
    MetricsSummary,
    StorageDisks,
    DiskSummary,
    MetricsPrometheus,
}

#[derive(Debug, Subcommand)]
enum ClusterCommand {
    Health,
    Nodes,
    Quotas,
}

#[derive(Debug, Subcommand)]
enum IamCommand {
    Users,
    Groups,
    Policies,
}

#[derive(Debug, Subcommand)]
enum BucketCommand {
    List,
    Replication,
}

#[derive(Debug, Subcommand)]
enum SecurityCommand {
    Config,
    Summary,
    KmsStatus,
    KmsRotationStatus,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    Events {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Query {
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        action_prefix: Option<String>,
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        resource_prefix: Option<String>,
        #[arg(long)]
        outcome: Option<String>,
        #[arg(long)]
        keyword: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        detail_key: Option<String>,
        #[arg(long)]
        detail_value: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("failed to build HTTP client")?;

    match cli.command {
        Command::System { command } => match command {
            SystemCommand::Info => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/system/info")
                    .await?,
            )?,
            SystemCommand::Topology => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/topology",
                )
                .await?,
            )?,
            SystemCommand::Alignment => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/alignment",
                )
                .await?,
            )?,
            SystemCommand::RaftStatus => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/raft/status",
                )
                .await?,
            )?,
            SystemCommand::MetricsSummary => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/metrics/summary",
                )
                .await?,
            )?,
            SystemCommand::StorageDisks => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/storage/disks",
                )
                .await?,
            )?,
            SystemCommand::DiskSummary => {
                let payload = fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/metrics/summary",
                )
                .await?;
                print_json(select_data_fields(
                    payload,
                    &["generated_at", "cluster_status", "nodes", "storage"],
                ))?;
            }
            SystemCommand::MetricsPrometheus => {
                println!("{}", fetch_text(&client, &cli.endpoint, "/metrics").await?);
            }
        },
        Command::Auth { command } => match command {
            AuthCommand::Login { username, password } => {
                let response: ApiEnvelope<LoginResponse> = client
                    .post(format!("{}/api/v1/auth/login", cli.endpoint))
                    .json(&LoginRequest {
                        username,
                        password,
                        provider: None,
                        id_token: None,
                    })
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;

                println!("access_token={}", response.data.access_token);
                println!("refresh_token={}", response.data.refresh_token);
                println!("role={}", response.data.role);
                println!("expires_at={}", response.data.expires_at);
            }
        },
        Command::Cluster { command } => match command {
            ClusterCommand::Health => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/cluster/health")
                    .await?,
            )?,
            ClusterCommand::Nodes => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/cluster/nodes")
                    .await?,
            )?,
            ClusterCommand::Quotas => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/cluster/quotas")
                    .await?,
            )?,
        },
        Command::Iam { command } => match command {
            IamCommand::Users => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/iam/users")
                    .await?,
            )?,
            IamCommand::Groups => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/iam/groups")
                    .await?,
            )?,
            IamCommand::Policies => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/iam/policies")
                    .await?,
            )?,
        },
        Command::Buckets { command } => match command {
            BucketCommand::List => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/buckets")
                    .await?,
            )?,
            BucketCommand::Replication => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/buckets/replication/status",
                )
                .await?,
            )?,
        },
        Command::Security { command } => match command {
            SecurityCommand::Config => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/security/config",
                )
                .await?,
            )?,
            SecurityCommand::Summary => {
                let payload = fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/system/metrics/summary",
                )
                .await?;
                print_json(select_data_fields(
                    payload,
                    &[
                        "generated_at",
                        "cluster_status",
                        "security",
                        "kms",
                        "iam",
                        "sessions",
                        "audit",
                    ],
                ))?;
            }
            SecurityCommand::KmsStatus => print_json(
                fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/security/kms/status",
                )
                .await?,
            )?,
            SecurityCommand::KmsRotationStatus => {
                let payload = fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    "/api/v1/security/kms/status",
                )
                .await?;
                print_json(select_data_fields(
                    payload,
                    &[
                        "healthy",
                        "last_error",
                        "last_checked_at",
                        "last_success_at",
                        "rotation_status",
                        "rotation_last_started_at",
                        "rotation_last_completed_at",
                        "rotation_last_success_at",
                        "rotation_last_failure_reason",
                        "rotation_scanned",
                        "rotation_rotated",
                        "rotation_skipped",
                        "rotation_failed",
                        "retry_recommended",
                    ],
                ))?;
            }
        },
        Command::Audit { command } => match command {
            AuditCommand::Events { limit } => {
                let payload = fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    &format!("/api/v1/audit/events?limit={limit}"),
                )
                .await?;
                print_json(payload)?;
            }
            AuditCommand::Query {
                limit,
                category,
                actor,
                action,
                action_prefix,
                resource,
                resource_prefix,
                outcome,
                keyword,
                reason,
                detail_key,
                detail_value,
                from,
                to,
            } => {
                let mut query = Vec::new();
                query.push(("limit", limit.to_string()));
                append_query_arg(&mut query, "category", category);
                append_query_arg(&mut query, "actor", actor);
                append_query_arg(&mut query, "action", action);
                append_query_arg(&mut query, "action_prefix", action_prefix);
                append_query_arg(&mut query, "resource", resource);
                append_query_arg(&mut query, "resource_prefix", resource_prefix);
                append_query_arg(&mut query, "outcome", outcome);
                append_query_arg(&mut query, "keyword", keyword);
                append_query_arg(&mut query, "reason", reason);
                append_query_arg(&mut query, "detail_key", detail_key);
                append_query_arg(&mut query, "detail_value", detail_value);
                append_query_arg(&mut query, "from", from);
                append_query_arg(&mut query, "to", to);
                let mut url = reqwest::Url::parse("http://localhost/")
                    .context("failed to initialize audit query builder")?;
                {
                    let mut pairs = url.query_pairs_mut();
                    for (key, value) in query {
                        pairs.append_pair(key, &value);
                    }
                }
                let query = url.query().unwrap_or_default().to_string();
                let payload = fetch_authed::<serde_json::Value>(
                    &client,
                    &cli.endpoint,
                    &format!("/api/v1/audit/events?{query}"),
                )
                .await?;
                print_json(payload)?;
            }
        },
        Command::Jobs { command } => match command {
            JobCommand::List => print_json(
                fetch_authed::<serde_json::Value>(&client, &cli.endpoint, "/api/v1/jobs").await?,
            )?,
        },
    }

    Ok(())
}

async fn fetch_authed<T: DeserializeOwned>(
    client: &reqwest::Client,
    endpoint: &str,
    path: &str,
) -> Result<T> {
    let token = env::var("RUSTIO_TOKEN")
        .context("set RUSTIO_TOKEN first, e.g. export RUSTIO_TOKEN=$(rustio auth login ...)")?;

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .context("failed to build authorization header")?,
    );

    let response = client
        .get(format!("{}{}", endpoint, path))
        .headers(headers)
        .send()
        .await?
        .error_for_status()?
        .json::<T>()
        .await?;

    Ok(response)
}

async fn fetch_text(client: &reqwest::Client, endpoint: &str, path: &str) -> Result<String> {
    Ok(client
        .get(format!("{}{}", endpoint, path))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

fn print_json(value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn append_query_arg(
    target: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        if !value.trim().is_empty() {
            target.push((key, value));
        }
    }
}

fn select_data_fields(payload: Value, keys: &[&str]) -> Value {
    let Some(data) = payload.get("data").and_then(Value::as_object) else {
        return payload;
    };
    let mut selected = Map::new();
    for key in keys {
        if let Some(value) = data.get(*key) {
            selected.insert((*key).to_string(), value.clone());
        }
    }
    Value::Object(selected)
}
