use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State as AxumState},
    http::HeaderMap as AxumHeaderMap,
    http::StatusCode as AxumStatusCode,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use reqwest::{header, StatusCode};
use rustio_admin::{build_router, AppState};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::sleep,
};
use tokio_rustls::TlsAcceptor;

struct AdminServer {
    base_url: String,
    client: reqwest::Client,
    state: Arc<AppState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
    data_dir: PathBuf,
    _env_guard: Option<MutexGuard<'static, ()>>,
}

#[derive(Debug, Clone)]
struct SmtpMessageRecord {
    auth_method: Option<String>,
    username: Option<String>,
    from: Option<String>,
    to: Option<String>,
    raw_message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockSmtpAuthMode {
    LoginFallback,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockSmtpTransport {
    Plain,
    StartTls,
    Tls,
}

struct MockSmtpServer {
    address: String,
    messages: Arc<Mutex<Vec<SmtpMessageRecord>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct NatsPublishRecord {
    connect_payload: Value,
    subject: String,
    payload: Value,
}

#[derive(Debug, Clone)]
enum MockNatsAuthMode {
    Token(String),
    UserPass { username: String, password: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockNatsTransport {
    Plain,
    Tls,
}

struct MockNatsServer {
    address: String,
    publishes: Arc<Mutex<Vec<NatsPublishRecord>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct ElasticsearchDocumentRecord {
    path: String,
    payload: Value,
}

struct MockElasticsearchServer {
    base_url: String,
    documents: Arc<Mutex<Vec<ElasticsearchDocumentRecord>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct HttpCaptureRecord {
    path: String,
    headers: HashMap<String, String>,
    payload: Value,
}

struct MockHttpCaptureServer {
    base_url: String,
    records: Arc<Mutex<Vec<HttpCaptureRecord>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct RedisPublishRecord {
    auth_username: Option<String>,
    channel: String,
    payload: Value,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum MockRedisAuthMode {
    None,
    Password(String),
    UserPass { username: String, password: String },
}

struct MockRedisServer {
    address: String,
    publishes: Arc<Mutex<Vec<RedisPublishRecord>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct TestTlsMaterial {
    cert_der: Vec<u8>,
    ca_pem: String,
    key_der: Vec<u8>,
}

fn test_tls_material() -> &'static TestTlsMaterial {
    static MATERIAL: OnceLock<TestTlsMaterial> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let ca_rsa = openssl::rsa::Rsa::generate(2048).expect("failed to generate test tls ca rsa");
        let ca_key = PKey::from_rsa(ca_rsa).expect("failed to wrap test tls ca key");
        let mut ca_name_builder =
            X509NameBuilder::new().expect("failed to build test tls ca subject name");
        ca_name_builder
            .append_entry_by_text("CN", "RustIO Test CA")
            .expect("failed to append test tls ca cn");
        let ca_name = ca_name_builder.build();
        let mut ca_builder = X509::builder().expect("failed to create test tls ca certificate");
        ca_builder
            .set_version(2)
            .expect("failed to set test tls ca certificate version");
        let ca_serial = BigNum::from_u32(1)
            .expect("failed to create test tls ca serial bignum")
            .to_asn1_integer()
            .expect("failed to create test tls ca serial");
        ca_builder
            .set_serial_number(&ca_serial)
            .expect("failed to set test tls ca serial");
        ca_builder
            .set_subject_name(&ca_name)
            .expect("failed to set test tls ca subject");
        ca_builder
            .set_issuer_name(&ca_name)
            .expect("failed to set test tls ca issuer");
        ca_builder
            .set_pubkey(&ca_key)
            .expect("failed to set test tls ca public key");
        let not_before = Asn1Time::days_from_now(0).expect("failed to build test tls not_before");
        let not_after = Asn1Time::days_from_now(3650).expect("failed to build test tls not_after");
        ca_builder
            .set_not_before(&not_before)
            .expect("failed to set test tls ca not_before");
        ca_builder
            .set_not_after(&not_after)
            .expect("failed to set test tls ca not_after");
        ca_builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .expect("failed to build test tls ca basic constraints"),
            )
            .expect("failed to append test tls ca basic constraints");
        ca_builder
            .append_extension(
                KeyUsage::new()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .expect("failed to build test tls ca key usage"),
            )
            .expect("failed to append test tls ca key usage");
        ca_builder
            .sign(&ca_key, MessageDigest::sha256())
            .expect("failed to sign test tls ca certificate");
        let ca_certificate = ca_builder.build();

        let server_rsa =
            openssl::rsa::Rsa::generate(2048).expect("failed to generate test tls server rsa");
        let server_key = PKey::from_rsa(server_rsa).expect("failed to wrap test tls server key");
        let mut server_name_builder =
            X509NameBuilder::new().expect("failed to build test tls server subject name");
        server_name_builder
            .append_entry_by_text("CN", "localhost")
            .expect("failed to append test tls server cn");
        let server_name = server_name_builder.build();
        let mut cert_builder = X509::builder().expect("failed to create test tls certificate");
        cert_builder
            .set_version(2)
            .expect("failed to set test tls certificate version");
        let serial = BigNum::from_u32(2)
            .expect("failed to create test tls serial bignum")
            .to_asn1_integer()
            .expect("failed to create test tls serial");
        cert_builder
            .set_serial_number(&serial)
            .expect("failed to set test tls serial");
        cert_builder
            .set_subject_name(&server_name)
            .expect("failed to set test tls subject");
        cert_builder
            .set_issuer_name(ca_certificate.subject_name())
            .expect("failed to set test tls issuer");
        cert_builder
            .set_pubkey(&server_key)
            .expect("failed to set test tls public key");
        cert_builder
            .set_not_before(&not_before)
            .expect("failed to set test tls not_before");
        cert_builder
            .set_not_after(&not_after)
            .expect("failed to set test tls not_after");
        cert_builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .build()
                    .expect("failed to build test tls basic constraints"),
            )
            .expect("failed to append test tls basic constraints");
        cert_builder
            .append_extension(
                KeyUsage::new()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .expect("failed to build test tls key usage"),
            )
            .expect("failed to append test tls key usage");
        cert_builder
            .append_extension(
                ExtendedKeyUsage::new()
                    .server_auth()
                    .build()
                    .expect("failed to build test tls extended key usage"),
            )
            .expect("failed to append test tls extended key usage");
        cert_builder
            .append_extension(
                SubjectAlternativeName::new()
                    .dns("localhost")
                    .build(&cert_builder.x509v3_context(Some(&ca_certificate), None))
                    .expect("failed to build test tls subject alt name"),
            )
            .expect("failed to append test tls subject alt name");
        cert_builder
            .sign(&ca_key, MessageDigest::sha256())
            .expect("failed to sign test tls certificate");

        let certificate = cert_builder.build();
        TestTlsMaterial {
            cert_der: certificate
                .to_der()
                .expect("failed to encode test tls certificate der"),
            ca_pem: String::from_utf8(
                ca_certificate
                    .to_pem()
                    .expect("failed to encode test tls ca pem"),
            )
            .expect("test tls ca pem should be utf8"),
            key_der: server_key
                .private_key_to_pkcs8()
                .expect("failed to encode test tls private key der"),
        }
    })
}

fn test_tls_acceptor() -> TlsAcceptor {
    static TLS_PROVIDER_INIT: OnceLock<()> = OnceLock::new();
    TLS_PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let material = test_tls_material();
    let certs = vec![CertificateDer::from(material.cert_der.clone())];
    let key = PrivatePkcs8KeyDer::from(material.key_der.clone());
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))
        .expect("failed to build test tls server config");
    TlsAcceptor::from(Arc::new(config))
}

fn write_test_alert_tls_ca(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "rustio-alert-tls-ca-{prefix}-{}-{nonce}.pem",
        std::process::id()
    ));
    std::fs::write(&path, &test_tls_material().ca_pem).expect("failed to write test tls ca file");
    path
}

impl AdminServer {
    async fn spawn() -> Self {
        let env_guard = env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "rustio-alert-delivery-external-{}-{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(&data_dir).expect("failed to create temp data dir");

        std::env::set_var("RUSTIO_DATA_DIR", &data_dir);
        std::env::set_var("RUSTIO_ROOT_USER", "rustioadmin");
        std::env::set_var("RUSTIO_ROOT_PASSWORD", "rustioadmin");
        std::env::set_var("RUSTIO_ALERT_DELIVERY_INTERVAL_MS", "100");
        std::env::set_var("RUSTIO_ALERT_DELIVERY_HTTP_TIMEOUT_MS", "2000");
        std::env::set_var("RUSTIO_ALERT_DELIVERY_RETRY_BASE_MS", "100");
        std::env::set_var("RUSTIO_ALERT_DELIVERY_RETRY_MAX_MS", "500");
        for key in [
            "RUSTIO_ALERT_SMTP_SERVER",
            "RUSTIO_ALERT_SMTP_FROM",
            "RUSTIO_ALERT_SMTP_USERNAME",
            "RUSTIO_ALERT_SMTP_PASSWORD",
            "RUSTIO_ALERT_SMTP_STARTTLS",
            "RUSTIO_ALERT_SMTP_TLS",
            "RUSTIO_ALERT_NATS_SUBJECT",
            "RUSTIO_ALERT_NATS_USERNAME",
            "RUSTIO_ALERT_NATS_PASSWORD",
            "RUSTIO_ALERT_NATS_TOKEN",
            "RUSTIO_ALERT_NATS_TLS",
            "RUSTIO_ALERT_REDIS_CHANNEL",
            "RUSTIO_ALERT_REDIS_USERNAME",
            "RUSTIO_ALERT_REDIS_PASSWORD",
            "RUSTIO_ALERT_REDIS_TLS",
            "RUSTIO_ALERT_TLS_CA_FILE",
        ] {
            std::env::remove_var(key);
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind admin listener");
        let addr = listener
            .local_addr()
            .expect("failed to read admin listen addr");
        let state = AppState::bootstrap();
        let app = build_router(Arc::clone(&state));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("failed to build admin client");
        let server = Self {
            base_url: format!("http://{addr}"),
            client,
            state,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            data_dir,
            _env_guard: Some(env_guard),
        };
        server.wait_until_ready().await;
        server
    }

    async fn wait_until_ready(&self) {
        let ready_url = format!("{}/health/ready", self.base_url);
        for _ in 0..100 {
            if let Ok(resp) = self.client.get(&ready_url).send().await {
                if resp.status() == StatusCode::OK {
                    return;
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("admin server did not become ready: {ready_url}");
    }

    async fn admin_token(&self) -> String {
        let response = self
            .client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"username":"admin","password":"rustio-admin"}"#)
            .send()
            .await
            .expect("admin login request failed");
        assert_eq!(response.status(), StatusCode::OK, "admin login failed");
        let payload = response
            .json::<Value>()
            .await
            .expect("failed to decode admin login response");
        payload
            .pointer("/data/access_token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    async fn create_channel(
        &self,
        token: &str,
        id: &str,
        name: &str,
        kind: &str,
        endpoint: &str,
    ) -> Value {
        let response = self
            .client
            .post(format!("{}/api/v1/alerts/channels", self.base_url))
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "id": id,
                    "name": name,
                    "kind": kind,
                    "endpoint": endpoint,
                    "enabled": true
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create alert channel request failed");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .json::<Value>()
            .await
            .expect("failed to decode create alert channel response")
    }

    async fn create_channel_raw(&self, token: &str, body: Value) -> Value {
        let response = self
            .client
            .post(format!("{}/api/v1/alerts/channels", self.base_url))
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .expect("create raw alert channel request failed");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .json::<Value>()
            .await
            .expect("failed to decode create raw alert channel response")
    }

    async fn test_channel(&self, token: &str, id: &str) -> Value {
        let response = self
            .client
            .post(format!(
                "{}/api/v1/alerts/channels/{}/test",
                self.base_url, id
            ))
            .bearer_auth(token)
            .send()
            .await
            .expect("test alert channel request failed");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .json::<Value>()
            .await
            .expect("failed to decode test alert channel response")
    }

    async fn create_rule(&self, token: &str, id: &str, name: &str, channel_ids: &[&str]) -> Value {
        let response = self
            .client
            .post(format!("{}/api/v1/alerts/rules", self.base_url))
            .bearer_auth(token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "id": id,
                    "name": name,
                    "metric": "cluster.capacity.used_ratio",
                    "condition": ">=",
                    "threshold": 0.1,
                    "window_minutes": 5,
                    "severity": "info",
                    "enabled": true,
                    "channels": channel_ids
                })
                .to_string(),
            )
            .send()
            .await
            .expect("create alert rule request failed");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .json::<Value>()
            .await
            .expect("failed to decode create alert rule response")
    }

    async fn simulate_rule(&self, token: &str, id: &str) -> Value {
        let response = self
            .client
            .post(format!(
                "{}/api/v1/alerts/rules/{}/simulate",
                self.base_url, id
            ))
            .bearer_auth(token)
            .send()
            .await
            .expect("simulate alert rule request failed");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .json::<Value>()
            .await
            .expect("failed to decode simulate alert rule response")
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

async fn mock_elasticsearch_ingest(
    AxumPath(path): AxumPath<String>,
    AxumState(documents): AxumState<Arc<Mutex<Vec<ElasticsearchDocumentRecord>>>>,
    Json(payload): Json<Value>,
) -> AxumStatusCode {
    documents
        .lock()
        .expect("failed to lock elasticsearch document buffer")
        .push(ElasticsearchDocumentRecord { path, payload });
    AxumStatusCode::CREATED
}

async fn mock_http_capture_ingest(
    AxumPath(path): AxumPath<String>,
    AxumState(records): AxumState<Arc<Mutex<Vec<HttpCaptureRecord>>>>,
    headers: AxumHeaderMap,
    body: Bytes,
) -> AxumStatusCode {
    let payload = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).to_string()));
    let headers = headers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_string(), value.to_string()))
        })
        .collect::<HashMap<_, _>>();
    records
        .lock()
        .expect("failed to lock http capture buffer")
        .push(HttpCaptureRecord {
            path,
            headers,
            payload,
        });
    AxumStatusCode::OK
}

impl MockElasticsearchServer {
    async fn spawn() -> Self {
        let documents = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", post(mock_elasticsearch_ingest))
            .with_state(Arc::clone(&documents));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock elasticsearch listener");
        let addr = listener
            .local_addr()
            .expect("failed to read mock elasticsearch addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Self {
            base_url: format!("http://{addr}"),
            documents,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn documents(&self) -> Vec<ElasticsearchDocumentRecord> {
        self.documents
            .lock()
            .expect("failed to lock elasticsearch document buffer")
            .clone()
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl MockHttpCaptureServer {
    async fn spawn() -> Self {
        let records = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", post(mock_http_capture_ingest))
            .with_state(Arc::clone(&records));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock http capture listener");
        let addr = listener
            .local_addr()
            .expect("failed to read mock http capture addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Self {
            base_url: format!("http://{addr}"),
            records,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn records(&self) -> Vec<HttpCaptureRecord> {
        self.records
            .lock()
            .expect("failed to lock http capture buffer")
            .clone()
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

async fn mock_redis_write<T>(
    reader: &mut BufReader<T>,
    raw: &str,
    label: &str,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    reader
        .get_mut()
        .write_all(raw.as_bytes())
        .await
        .map_err(|err| format!("write redis {label} failed: {err}"))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|err| format!("flush redis {label} failed: {err}"))
}

async fn mock_redis_read_command<T>(
    reader: &mut BufReader<T>,
) -> Result<Option<Vec<String>>, String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = String::new();
    let size = reader
        .read_line(&mut header)
        .await
        .map_err(|err| format!("read redis command header failed: {err}"))?;
    if size == 0 {
        return Ok(None);
    }
    let header = header.trim();
    let count = header
        .strip_prefix('*')
        .ok_or_else(|| format!("unexpected redis array header: {header}"))?
        .parse::<usize>()
        .map_err(|err| format!("invalid redis array size: {err}"))?;
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bulk_header = String::new();
        reader
            .read_line(&mut bulk_header)
            .await
            .map_err(|err| format!("read redis bulk header failed: {err}"))?;
        let bulk_header = bulk_header.trim();
        let len = bulk_header
            .strip_prefix('$')
            .ok_or_else(|| format!("unexpected redis bulk header: {bulk_header}"))?
            .parse::<usize>()
            .map_err(|err| format!("invalid redis bulk size: {err}"))?;
        let mut payload = vec![0u8; len];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|err| format!("read redis bulk payload failed: {err}"))?;
        let mut terminator = [0u8; 2];
        reader
            .read_exact(&mut terminator)
            .await
            .map_err(|err| format!("read redis bulk terminator failed: {err}"))?;
        if terminator != *b"\r\n" {
            return Err("redis bulk payload terminator is invalid".to_string());
        }
        parts.push(
            String::from_utf8(payload)
                .map_err(|err| format!("decode redis bulk payload failed: {err}"))?,
        );
    }
    Ok(Some(parts))
}

async fn handle_mock_redis_session<T>(
    mut reader: BufReader<T>,
    publishes: Arc<Mutex<Vec<RedisPublishRecord>>>,
    auth_mode: MockRedisAuthMode,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let requires_auth = !matches!(auth_mode, MockRedisAuthMode::None);
    let mut authenticated_username = None::<String>;
    let mut authenticated = !requires_auth;

    while let Some(command) = mock_redis_read_command(&mut reader).await? {
        if command.is_empty() {
            return Err("redis command cannot be empty".to_string());
        }
        let name = command[0].to_ascii_uppercase();
        match name.as_str() {
            "AUTH" => match &auth_mode {
                MockRedisAuthMode::None => {
                    authenticated = true;
                    mock_redis_write(&mut reader, "+OK\r\n", "auth ok").await?;
                }
                MockRedisAuthMode::Password(expected_password) => {
                    let provided_password = match command.as_slice() {
                        [_, password] => password.as_str(),
                        [_, _, password] => password.as_str(),
                        _ => {
                            mock_redis_write(
                                &mut reader,
                                "-ERR wrong number of arguments for 'auth' command\r\n",
                                "auth arity error",
                            )
                            .await?;
                            continue;
                        }
                    };
                    if provided_password != expected_password {
                        mock_redis_write(
                            &mut reader,
                            "-WRONGPASS invalid username-password pair\r\n",
                            "auth wrongpass",
                        )
                        .await?;
                        continue;
                    }
                    authenticated = true;
                    authenticated_username = None;
                    mock_redis_write(&mut reader, "+OK\r\n", "auth ok").await?;
                }
                MockRedisAuthMode::UserPass { username, password } => {
                    let [_, provided_username, provided_password] = command.as_slice() else {
                        mock_redis_write(
                            &mut reader,
                            "-ERR wrong number of arguments for 'auth' command\r\n",
                            "auth arity error",
                        )
                        .await?;
                        continue;
                    };
                    if provided_username != username || provided_password != password {
                        mock_redis_write(
                            &mut reader,
                            "-WRONGPASS invalid username-password pair\r\n",
                            "auth wrongpass",
                        )
                        .await?;
                        continue;
                    }
                    authenticated = true;
                    authenticated_username = Some(provided_username.clone());
                    mock_redis_write(&mut reader, "+OK\r\n", "auth ok").await?;
                }
            },
            "PUBLISH" => {
                if !authenticated {
                    mock_redis_write(
                        &mut reader,
                        "-NOAUTH Authentication required.\r\n",
                        "publish noauth",
                    )
                    .await?;
                    continue;
                }
                let [_, channel, payload] = command.as_slice() else {
                    return Err(format!("unexpected redis publish command: {command:?}"));
                };
                publishes
                    .lock()
                    .expect("failed to lock redis publish buffer")
                    .push(RedisPublishRecord {
                        auth_username: authenticated_username.clone(),
                        channel: channel.clone(),
                        payload: serde_json::from_str(payload)
                            .map_err(|err| format!("decode redis payload failed: {err}"))?,
                    });
                mock_redis_write(&mut reader, ":1\r\n", "publish ok").await?;
            }
            _ => {
                mock_redis_write(&mut reader, "-ERR unknown command\r\n", "unknown command")
                    .await?;
            }
        }
    }
    Ok(())
}

impl MockRedisServer {
    async fn spawn(auth_mode: MockRedisAuthMode) -> Self {
        let publishes = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock redis listener");
        let addr = listener
            .local_addr()
            .expect("failed to read mock redis addr");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let publish_buffer = Arc::clone(&publishes);
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _)) => {
                                let publishes = Arc::clone(&publish_buffer);
                                let auth_mode = auth_mode.clone();
                                tokio::spawn(async move {
                                    let _ = handle_mock_redis_session(BufReader::new(stream), publishes, auth_mode).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
        Self {
            address: addr.to_string(),
            publishes,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn publishes(&self) -> Vec<RedisPublishRecord> {
        self.publishes
            .lock()
            .expect("failed to lock redis publish buffer")
            .clone()
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

#[derive(Clone)]
struct MockSmtpContext {
    messages: Arc<Mutex<Vec<SmtpMessageRecord>>>,
    expected_username: String,
    expected_password: String,
    auth_mode: MockSmtpAuthMode,
}

enum MockSmtpSessionOutcome<T> {
    Completed,
    Upgrade(T),
}

async fn mock_smtp_write<T>(reader: &mut BufReader<T>, raw: &str, label: &str) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    reader
        .get_mut()
        .write_all(raw.as_bytes())
        .await
        .map_err(|err| format!("write smtp {label} failed: {err}"))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|err| format!("flush smtp {label} failed: {err}"))?;
    Ok(())
}

async fn handle_mock_smtp_commands<T>(
    mut reader: BufReader<T>,
    context: &MockSmtpContext,
    send_greeting: bool,
    advertise_starttls: bool,
) -> Result<MockSmtpSessionOutcome<T>, String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if send_greeting {
        mock_smtp_write(
            &mut reader,
            "220 mock.smtp.local ESMTP ready\r\n",
            "greeting",
        )
        .await?;
    }

    let mut auth_method = None::<String>;
    let mut auth_username = None::<String>;
    let mut from = None::<String>;
    let mut to = None::<String>;

    loop {
        let mut line = String::new();
        let size = reader
            .read_line(&mut line)
            .await
            .map_err(|err| format!("read smtp command failed: {err}"))?;
        if size == 0 {
            return Ok(MockSmtpSessionOutcome::Completed);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.eq_ignore_ascii_case("EHLO rustio.local")
            || trimmed.eq_ignore_ascii_case("HELO rustio.local")
        {
            let response = if advertise_starttls {
                "250-mock.smtp.local\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n"
            } else {
                "250-mock.smtp.local\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n"
            };
            mock_smtp_write(&mut reader, response, "ehlo response").await?;
            continue;
        }
        if advertise_starttls && trimmed.eq_ignore_ascii_case("STARTTLS") {
            mock_smtp_write(
                &mut reader,
                "220 2.0.0 Ready to start TLS\r\n",
                "starttls response",
            )
            .await?;
            return Ok(MockSmtpSessionOutcome::Upgrade(reader.into_inner()));
        }
        if trimmed.starts_with("AUTH PLAIN ") {
            if context.auth_mode == MockSmtpAuthMode::Plain {
                let encoded = trimmed.trim_start_matches("AUTH PLAIN ").trim();
                let decoded = String::from_utf8(
                    BASE64
                        .decode(encoded)
                        .map_err(|err| format!("decode smtp plain auth failed: {err}"))?,
                )
                .map_err(|err| format!("utf8 smtp plain auth failed: {err}"))?;
                let parts = decoded.split('\0').collect::<Vec<_>>();
                if parts.len() < 3
                    || parts[1] != context.expected_username
                    || parts[2] != context.expected_password
                {
                    mock_smtp_write(
                        &mut reader,
                        "535 5.7.8 invalid auth\r\n",
                        "plain auth invalid",
                    )
                    .await?;
                    continue;
                }
                auth_method = Some("plain".to_string());
                auth_username = Some(context.expected_username.clone());
                mock_smtp_write(
                    &mut reader,
                    "235 2.7.0 authenticated\r\n",
                    "plain auth success",
                )
                .await?;
            } else {
                mock_smtp_write(
                    &mut reader,
                    "504 5.7.4 unsupported auth\r\n",
                    "plain auth rejection",
                )
                .await?;
            }
            continue;
        }
        if trimmed.eq_ignore_ascii_case("AUTH LOGIN") {
            auth_method = Some("login".to_string());
            mock_smtp_write(
                &mut reader,
                "334 VXNlcm5hbWU6\r\n",
                "login username challenge",
            )
            .await?;

            let mut username_line = String::new();
            reader
                .read_line(&mut username_line)
                .await
                .map_err(|err| format!("read smtp username failed: {err}"))?;
            let username = String::from_utf8(
                BASE64
                    .decode(username_line.trim())
                    .map_err(|err| format!("decode smtp username failed: {err}"))?,
            )
            .map_err(|err| format!("utf8 smtp username failed: {err}"))?;
            auth_username = Some(username.clone());
            if username != context.expected_username {
                mock_smtp_write(
                    &mut reader,
                    "535 5.7.8 invalid username\r\n",
                    "invalid username",
                )
                .await?;
                continue;
            }

            mock_smtp_write(
                &mut reader,
                "334 UGFzc3dvcmQ6\r\n",
                "login password challenge",
            )
            .await?;

            let mut password_line = String::new();
            reader
                .read_line(&mut password_line)
                .await
                .map_err(|err| format!("read smtp password failed: {err}"))?;
            let password = String::from_utf8(
                BASE64
                    .decode(password_line.trim())
                    .map_err(|err| format!("decode smtp password failed: {err}"))?,
            )
            .map_err(|err| format!("utf8 smtp password failed: {err}"))?;
            if password != context.expected_password {
                mock_smtp_write(
                    &mut reader,
                    "535 5.7.8 invalid password\r\n",
                    "invalid password",
                )
                .await?;
                continue;
            }

            mock_smtp_write(
                &mut reader,
                "235 2.7.0 authenticated\r\n",
                "login auth success",
            )
            .await?;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("MAIL FROM:<") {
            from = Some(value.trim_end_matches('>').to_string());
            mock_smtp_write(&mut reader, "250 2.1.0 sender ok\r\n", "mail from response").await?;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("RCPT TO:<") {
            to = Some(value.trim_end_matches('>').to_string());
            mock_smtp_write(&mut reader, "250 2.1.5 recipient ok\r\n", "rcpt response").await?;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("DATA") {
            mock_smtp_write(
                &mut reader,
                "354 end with <CRLF>.<CRLF>\r\n",
                "data response",
            )
            .await?;

            let mut raw_message = String::new();
            loop {
                let mut message_line = String::new();
                let size = reader
                    .read_line(&mut message_line)
                    .await
                    .map_err(|err| format!("read smtp data line failed: {err}"))?;
                if size == 0 {
                    return Err("smtp data terminated unexpectedly".to_string());
                }
                let message_trimmed = message_line.trim_end_matches(['\r', '\n']);
                if message_trimmed == "." {
                    break;
                }
                raw_message.push_str(message_trimmed);
                raw_message.push('\n');
            }
            context
                .messages
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(SmtpMessageRecord {
                    auth_method: auth_method.clone(),
                    username: auth_username.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    raw_message,
                });
            mock_smtp_write(&mut reader, "250 2.0.0 queued\r\n", "queued response").await?;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("QUIT") {
            mock_smtp_write(&mut reader, "221 2.0.0 bye\r\n", "quit response").await?;
            return Ok(MockSmtpSessionOutcome::Completed);
        }

        mock_smtp_write(
            &mut reader,
            "500 5.5.2 unsupported\r\n",
            "unsupported response",
        )
        .await?;
    }
}

async fn handle_mock_smtp_connection(
    stream: TcpStream,
    context: MockSmtpContext,
    transport: MockSmtpTransport,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), String> {
    match transport {
        MockSmtpTransport::Plain => {
            match handle_mock_smtp_commands(BufReader::new(stream), &context, true, false).await? {
                MockSmtpSessionOutcome::Completed => Ok(()),
                MockSmtpSessionOutcome::Upgrade(_) => {
                    Err("plain smtp session unexpectedly requested STARTTLS".to_string())
                }
            }
        }
        MockSmtpTransport::StartTls => {
            let acceptor = tls_acceptor
                .ok_or_else(|| "starttls smtp transport missing tls acceptor".to_string())?;
            match handle_mock_smtp_commands(BufReader::new(stream), &context, true, true).await? {
                MockSmtpSessionOutcome::Completed => Ok(()),
                MockSmtpSessionOutcome::Upgrade(stream) => {
                    let tls_stream = acceptor
                        .accept(stream)
                        .await
                        .map_err(|err| format!("accept smtp starttls failed: {err}"))?;
                    match handle_mock_smtp_commands(
                        BufReader::new(tls_stream),
                        &context,
                        false,
                        false,
                    )
                    .await?
                    {
                        MockSmtpSessionOutcome::Completed => Ok(()),
                        MockSmtpSessionOutcome::Upgrade(_) => {
                            Err("smtp session attempted nested STARTTLS upgrade".to_string())
                        }
                    }
                }
            }
        }
        MockSmtpTransport::Tls => {
            let acceptor =
                tls_acceptor.ok_or_else(|| "smtps transport missing tls acceptor".to_string())?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|err| format!("accept smtps connection failed: {err}"))?;
            match handle_mock_smtp_commands(BufReader::new(tls_stream), &context, true, false)
                .await?
            {
                MockSmtpSessionOutcome::Completed => Ok(()),
                MockSmtpSessionOutcome::Upgrade(_) => {
                    Err("smtps session unexpectedly requested STARTTLS".to_string())
                }
            }
        }
    }
}

impl MockSmtpServer {
    async fn spawn(
        expected_username: &str,
        expected_password: &str,
        auth_mode: MockSmtpAuthMode,
    ) -> Self {
        Self::spawn_with_transport(
            expected_username,
            expected_password,
            auth_mode,
            MockSmtpTransport::Plain,
        )
        .await
    }

    async fn spawn_with_transport(
        expected_username: &str,
        expected_password: &str,
        auth_mode: MockSmtpAuthMode,
        transport: MockSmtpTransport,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock smtp listener");
        let address = listener
            .local_addr()
            .expect("failed to read mock smtp addr");
        let messages = Arc::new(Mutex::new(Vec::<SmtpMessageRecord>::new()));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let context = MockSmtpContext {
            messages: Arc::clone(&messages),
            expected_username: expected_username.to_string(),
            expected_password: expected_password.to_string(),
            auth_mode,
        };
        let tls_acceptor = match transport {
            MockSmtpTransport::Plain => None,
            MockSmtpTransport::StartTls | MockSmtpTransport::Tls => Some(test_tls_acceptor()),
        };
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else { break; };
                        let context = context.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            let _ = handle_mock_smtp_connection(stream, context, transport, tls_acceptor).await;
                        });
                    }
                }
            }
        });
        Self {
            address: format!("localhost:{}", address.port()),
            messages,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn messages(&self) -> Vec<SmtpMessageRecord> {
        self.messages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

async fn handle_mock_nats_session<T>(
    mut reader: BufReader<T>,
    publishes: Arc<Mutex<Vec<NatsPublishRecord>>>,
    auth_mode: MockNatsAuthMode,
    tls_required: bool,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let info_line = format!("INFO {{\"auth_required\":true,\"tls_required\":{tls_required}}}\r\n");
    reader
        .get_mut()
        .write_all(info_line.as_bytes())
        .await
        .map_err(|err| format!("write nats info failed: {err}"))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|err| format!("flush nats info failed: {err}"))?;

    let mut connect_line = String::new();
    reader
        .read_line(&mut connect_line)
        .await
        .map_err(|err| format!("read nats connect failed: {err}"))?;
    let connect_payload = connect_line
        .trim()
        .strip_prefix("CONNECT ")
        .ok_or_else(|| format!("unexpected nats connect line: {connect_line}"))
        .and_then(|raw| {
            serde_json::from_str::<Value>(raw)
                .map_err(|err| format!("decode nats connect failed: {err}"))
        })?;
    match &auth_mode {
        MockNatsAuthMode::Token(expected_token) => {
            let auth_token = connect_payload
                .get("auth_token")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if auth_token != expected_token {
                reader
                    .get_mut()
                    .write_all(b"-ERR 'invalid token'\r\n")
                    .await
                    .map_err(|err| format!("write nats auth error failed: {err}"))?;
                reader
                    .get_mut()
                    .flush()
                    .await
                    .map_err(|err| format!("flush nats auth error failed: {err}"))?;
                return Ok(());
            }
        }
        MockNatsAuthMode::UserPass { username, password } => {
            let actual_username = connect_payload
                .get("user")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let actual_password = connect_payload
                .get("pass")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if actual_username != username || actual_password != password {
                reader
                    .get_mut()
                    .write_all(b"-ERR 'invalid user/pass'\r\n")
                    .await
                    .map_err(|err| format!("write nats auth error failed: {err}"))?;
                reader
                    .get_mut()
                    .flush()
                    .await
                    .map_err(|err| format!("flush nats auth error failed: {err}"))?;
                return Ok(());
            }
        }
    }

    let mut pub_line = String::new();
    reader
        .read_line(&mut pub_line)
        .await
        .map_err(|err| format!("read nats pub line failed: {err}"))?;
    let mut pub_parts = pub_line.split_whitespace();
    let command = pub_parts.next().unwrap_or_default();
    let subject = pub_parts.next().unwrap_or_default().to_string();
    let len = pub_parts
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| format!("invalid nats pub length: {pub_line}"))?;
    if command != "PUB" || subject.is_empty() {
        return Err(format!("unexpected nats pub line: {pub_line}"));
    }

    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|err| format!("read nats payload failed: {err}"))?;
    let mut payload_crlf = [0u8; 2];
    reader
        .read_exact(&mut payload_crlf)
        .await
        .map_err(|err| format!("read nats payload terminator failed: {err}"))?;

    let mut ping_line = String::new();
    reader
        .read_line(&mut ping_line)
        .await
        .map_err(|err| format!("read nats ping failed: {err}"))?;
    if ping_line.trim() != "PING" {
        return Err(format!("unexpected nats ping line: {ping_line}"));
    }

    publishes
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(NatsPublishRecord {
            connect_payload,
            subject,
            payload: serde_json::from_slice::<Value>(&payload)
                .map_err(|err| format!("decode nats payload failed: {err}"))?,
        });
    reader
        .get_mut()
        .write_all(b"PONG\r\n")
        .await
        .map_err(|err| format!("write nats pong failed: {err}"))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|err| format!("flush nats pong failed: {err}"))?;
    Ok(())
}

async fn handle_mock_nats_connection(
    stream: TcpStream,
    publishes: Arc<Mutex<Vec<NatsPublishRecord>>>,
    auth_mode: MockNatsAuthMode,
    transport: MockNatsTransport,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), String> {
    match transport {
        MockNatsTransport::Plain => {
            handle_mock_nats_session(BufReader::new(stream), publishes, auth_mode, false).await
        }
        MockNatsTransport::Tls => {
            let acceptor = tls_acceptor
                .ok_or_else(|| "nats tls transport missing tls acceptor".to_string())?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|err| format!("accept nats tls connection failed: {err}"))?;
            handle_mock_nats_session(BufReader::new(tls_stream), publishes, auth_mode, true).await
        }
    }
}

impl MockNatsServer {
    async fn spawn(auth_mode: MockNatsAuthMode) -> Self {
        Self::spawn_with_transport(auth_mode, MockNatsTransport::Plain).await
    }

    async fn spawn_with_transport(
        auth_mode: MockNatsAuthMode,
        transport: MockNatsTransport,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock nats listener");
        let address = listener
            .local_addr()
            .expect("failed to read mock nats addr");
        let publishes = Arc::new(Mutex::new(Vec::<NatsPublishRecord>::new()));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let publish_state = Arc::clone(&publishes);
        let tls_acceptor = match transport {
            MockNatsTransport::Plain => None,
            MockNatsTransport::Tls => Some(test_tls_acceptor()),
        };
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else { break; };
                        let publishes = Arc::clone(&publish_state);
                        let auth_mode = auth_mode.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            let _ = handle_mock_nats_connection(stream, publishes, auth_mode, transport, tls_acceptor).await;
                        });
                    }
                }
            }
        });
        Self {
            address: format!("localhost:{}", address.port()),
            publishes,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn publishes(&self) -> Vec<NatsPublishRecord> {
        self.publishes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

fn smtp_payload_from_raw_message(raw_message: &str) -> Value {
    let (_, json_body) = raw_message
        .split_once("\n\n")
        .expect("smtp message should contain blank line before json body");
    serde_json::from_str::<Value>(json_body.trim())
        .expect("smtp message json payload should decode")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_delivery_external_smtp_and_nats_live_regression() {
    let server = AdminServer::spawn().await;
    let smtp = MockSmtpServer::spawn("ops-user", "ops-pass", MockSmtpAuthMode::LoginFallback).await;
    let nats = MockNatsServer::spawn(MockNatsAuthMode::Token("ops-token".to_string())).await;

    std::env::set_var("RUSTIO_ALERT_SMTP_USERNAME", "ops-user");
    std::env::set_var("RUSTIO_ALERT_SMTP_PASSWORD", "ops-pass");
    std::env::set_var("RUSTIO_ALERT_SMTP_FROM", "rustio-alert@example.internal");
    std::env::set_var("RUSTIO_ALERT_NATS_TOKEN", "ops-token");

    let token = server.admin_token().await;

    let smtp_channel = server
        .create_channel(
            &token,
            "smtp-live",
            "smtp-live",
            "email",
            &format!("smtp://{}/ops@example.com", smtp.address),
        )
        .await;
    assert_eq!(
        smtp_channel.pointer("/data/id").and_then(Value::as_str),
        Some("smtp-live")
    );

    let nats_channel = server
        .create_channel(
            &token,
            "nats-live",
            "nats-live",
            "nats",
            &format!("nats://{}/ops.alerts", nats.address),
        )
        .await;
    assert_eq!(
        nats_channel.pointer("/data/id").and_then(Value::as_str),
        Some("nats-live")
    );

    let smtp_test = server.test_channel(&token, "smtp-live").await;
    assert_eq!(
        smtp_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    assert_eq!(smtp_test.pointer("/data/error"), Some(&Value::Null));

    let nats_test = server.test_channel(&token, "nats-live").await;
    assert_eq!(
        nats_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    assert_eq!(nats_test.pointer("/data/error"), Some(&Value::Null));

    let smtp_messages = smtp.messages();
    assert_eq!(
        smtp_messages.len(),
        1,
        "smtp direct test should send one message"
    );
    assert_eq!(smtp_messages[0].auth_method.as_deref(), Some("login"));
    assert_eq!(smtp_messages[0].username.as_deref(), Some("ops-user"));
    assert_eq!(
        smtp_messages[0].from.as_deref(),
        Some("rustio-alert@example.internal")
    );
    assert_eq!(smtp_messages[0].to.as_deref(), Some("ops@example.com"));
    let smtp_direct_payload = smtp_payload_from_raw_message(&smtp_messages[0].raw_message);
    assert_eq!(
        smtp_direct_payload.get("kind").and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        smtp_direct_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-live")
    );

    let nats_publishes = nats.publishes();
    assert_eq!(
        nats_publishes.len(),
        1,
        "nats direct test should publish once"
    );
    assert_eq!(
        nats_publishes[0]
            .connect_payload
            .get("auth_token")
            .and_then(Value::as_str),
        Some("ops-token")
    );
    assert_eq!(nats_publishes[0].subject, "ops.alerts");
    assert_eq!(
        nats_publishes[0]
            .payload
            .get("kind")
            .and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        nats_publishes[0]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("nats-live")
    );

    let create_rule = server
        .create_rule(
            &token,
            "rule-live-delivery",
            "rule-live-delivery",
            &["smtp-live", "nats-live"],
        )
        .await;
    assert_eq!(
        create_rule.pointer("/data/id").and_then(Value::as_str),
        Some("rule-live-delivery")
    );

    let simulate = server.simulate_rule(&token, "rule-live-delivery").await;
    let history_id = simulate
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("simulate response should contain history id")
        .to_string();
    assert_eq!(
        simulate.pointer("/data/status").and_then(Value::as_str),
        Some("firing")
    );

    let mut delivered = false;
    for _ in 0..80 {
        let smtp_count = smtp.messages().len();
        let nats_count = nats.publishes().len();
        let queue = server.state.alert_delivery_queue.read().await.clone();
        let done_count = queue
            .iter()
            .filter(|item| item.history_id == history_id && item.status == "done")
            .count();
        if smtp_count >= 2 && nats_count >= 2 && done_count >= 2 {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        delivered,
        "queued alert deliveries should reach smtp and nats"
    );

    let smtp_messages = smtp.messages();
    assert_eq!(
        smtp_messages.len(),
        2,
        "smtp should receive direct + queued delivery"
    );
    let smtp_queued_payload = smtp_payload_from_raw_message(&smtp_messages[1].raw_message);
    assert_eq!(
        smtp_queued_payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        smtp_queued_payload.get("rule_id").and_then(Value::as_str),
        Some("rule-live-delivery")
    );
    assert_eq!(
        smtp_queued_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-live")
    );

    let nats_publishes = nats.publishes();
    assert_eq!(
        nats_publishes.len(),
        2,
        "nats should receive direct + queued delivery"
    );
    assert_eq!(
        nats_publishes[1]
            .connect_payload
            .get("auth_token")
            .and_then(Value::as_str),
        Some("ops-token")
    );
    assert_eq!(nats_publishes[1].subject, "ops.alerts");
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("rule_id")
            .and_then(Value::as_str),
        Some("rule-live-delivery")
    );
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("nats-live")
    );

    let channels = server.state.alert_channels.read().await.clone();
    let smtp_channel = channels
        .iter()
        .find(|channel| channel.id == "smtp-live")
        .expect("smtp channel should exist");
    assert_eq!(smtp_channel.status, "healthy");
    assert!(smtp_channel.error.is_none());
    let nats_channel = channels
        .iter()
        .find(|channel| channel.id == "nats-live")
        .expect("nats channel should exist");
    assert_eq!(nats_channel.status, "healthy");
    assert!(nats_channel.error.is_none());

    let queue = server.state.alert_delivery_queue.read().await.clone();
    let history_queue = queue
        .iter()
        .filter(|item| item.history_id == history_id)
        .collect::<Vec<_>>();
    assert_eq!(history_queue.len(), 2);
    assert!(
        history_queue.iter().all(|item| item.status == "done"),
        "all queued deliveries should be marked done"
    );

    let metrics_summary = server
        .client
        .get(format!("{}/api/v1/system/metrics/summary", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .expect("metrics summary request should complete");
    assert_eq!(metrics_summary.status(), StatusCode::OK);
    let metrics_summary = metrics_summary
        .json::<Value>()
        .await
        .expect("metrics summary response should be json");
    assert!(
        metrics_summary
            .pointer("/data/alerts/channels_total")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            >= 2,
        "channels_total should include at least the configured delivery channels"
    );
    assert!(
        metrics_summary
            .pointer("/data/alerts/delivery_done")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            >= 2,
        "delivery_done should include queued deliveries"
    );
    assert_eq!(
        metrics_summary.pointer("/data/alerts/delivery_failed"),
        Some(&json!(0))
    );
    assert!(
        metrics_summary
            .pointer("/data/audit/alert_events_total")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            >= 1,
        "alert audit events should be visible in summary"
    );

    let audit_rows = server
        .client
        .get(format!(
            "{}/api/v1/audit/events?category=alerts&detail_key=channel_id&detail_value=smtp-live",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("filtered audit request should complete");
    assert_eq!(audit_rows.status(), StatusCode::OK);
    let audit_rows = audit_rows
        .json::<Value>()
        .await
        .expect("filtered audit response should be json");
    assert!(
        audit_rows
            .pointer("/data")
            .and_then(Value::as_array)
            .map(|rows| !rows.is_empty())
            .unwrap_or(false),
        "alert delivery audit filter should find smtp-live records"
    );

    nats.stop().await;
    smtp.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_delivery_external_smtp_plain_and_nats_userpass_live_regression() {
    let server = AdminServer::spawn().await;
    let smtp = MockSmtpServer::spawn("plain-user", "plain-pass", MockSmtpAuthMode::Plain).await;
    let nats = MockNatsServer::spawn(MockNatsAuthMode::UserPass {
        username: "nats-user".to_string(),
        password: "nats-pass".to_string(),
    })
    .await;

    std::env::set_var("RUSTIO_ALERT_SMTP_USERNAME", "plain-user");
    std::env::set_var("RUSTIO_ALERT_SMTP_PASSWORD", "plain-pass");
    std::env::set_var("RUSTIO_ALERT_SMTP_FROM", "rustio-alert@example.internal");
    std::env::set_var("RUSTIO_ALERT_NATS_USERNAME", "nats-user");
    std::env::set_var("RUSTIO_ALERT_NATS_PASSWORD", "nats-pass");

    let token = server.admin_token().await;

    let smtp_channel = server
        .create_channel(
            &token,
            "smtp-plain-live",
            "smtp-plain-live",
            "email",
            &format!("smtp://{}/plain@example.com", smtp.address),
        )
        .await;
    assert_eq!(
        smtp_channel.pointer("/data/id").and_then(Value::as_str),
        Some("smtp-plain-live")
    );

    let nats_channel = server
        .create_channel(
            &token,
            "nats-userpass-live",
            "nats-userpass-live",
            "nats",
            &format!("nats://{}/ops.userpass", nats.address),
        )
        .await;
    assert_eq!(
        nats_channel.pointer("/data/id").and_then(Value::as_str),
        Some("nats-userpass-live")
    );

    let smtp_test = server.test_channel(&token, "smtp-plain-live").await;
    assert_eq!(
        smtp_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    let nats_test = server.test_channel(&token, "nats-userpass-live").await;
    assert_eq!(
        nats_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );

    let smtp_messages = smtp.messages();
    assert_eq!(smtp_messages.len(), 1);
    assert_eq!(smtp_messages[0].auth_method.as_deref(), Some("plain"));
    assert_eq!(smtp_messages[0].username.as_deref(), Some("plain-user"));
    assert_eq!(smtp_messages[0].to.as_deref(), Some("plain@example.com"));
    let smtp_direct_payload = smtp_payload_from_raw_message(&smtp_messages[0].raw_message);
    assert_eq!(
        smtp_direct_payload.get("kind").and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        smtp_direct_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-plain-live")
    );

    let nats_publishes = nats.publishes();
    assert_eq!(nats_publishes.len(), 1);
    assert_eq!(
        nats_publishes[0]
            .connect_payload
            .get("user")
            .and_then(Value::as_str),
        Some("nats-user")
    );
    assert_eq!(
        nats_publishes[0]
            .connect_payload
            .get("pass")
            .and_then(Value::as_str),
        Some("nats-pass")
    );
    assert!(
        nats_publishes[0]
            .connect_payload
            .get("auth_token")
            .is_none(),
        "user/pass branch should not send auth_token"
    );
    assert_eq!(nats_publishes[0].subject, "ops.userpass");
    assert_eq!(
        nats_publishes[0]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("nats-userpass-live")
    );

    let create_rule = server
        .create_rule(
            &token,
            "rule-live-delivery-userpass",
            "rule-live-delivery-userpass",
            &["smtp-plain-live", "nats-userpass-live"],
        )
        .await;
    assert_eq!(
        create_rule.pointer("/data/id").and_then(Value::as_str),
        Some("rule-live-delivery-userpass")
    );

    let simulate = server
        .simulate_rule(&token, "rule-live-delivery-userpass")
        .await;
    let history_id = simulate
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("simulate response should contain history id")
        .to_string();

    let mut delivered = false;
    for _ in 0..80 {
        let smtp_count = smtp.messages().len();
        let nats_count = nats.publishes().len();
        let queue = server.state.alert_delivery_queue.read().await.clone();
        let done_count = queue
            .iter()
            .filter(|item| item.history_id == history_id && item.status == "done")
            .count();
        if smtp_count >= 2 && nats_count >= 2 && done_count >= 2 {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(delivered, "queued user/pass deliveries should complete");

    let smtp_messages = smtp.messages();
    assert_eq!(smtp_messages.len(), 2);
    assert_eq!(smtp_messages[1].auth_method.as_deref(), Some("plain"));
    let smtp_queued_payload = smtp_payload_from_raw_message(&smtp_messages[1].raw_message);
    assert_eq!(
        smtp_queued_payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        smtp_queued_payload.get("rule_id").and_then(Value::as_str),
        Some("rule-live-delivery-userpass")
    );
    assert_eq!(
        smtp_queued_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-plain-live")
    );

    let nats_publishes = nats.publishes();
    assert_eq!(nats_publishes.len(), 2);
    assert_eq!(
        nats_publishes[1]
            .connect_payload
            .get("user")
            .and_then(Value::as_str),
        Some("nats-user")
    );
    assert_eq!(
        nats_publishes[1]
            .connect_payload
            .get("pass")
            .and_then(Value::as_str),
        Some("nats-pass")
    );
    assert!(
        nats_publishes[1]
            .connect_payload
            .get("auth_token")
            .is_none(),
        "queued user/pass branch should not send auth_token"
    );
    assert_eq!(nats_publishes[1].subject, "ops.userpass");
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("rule_id")
            .and_then(Value::as_str),
        Some("rule-live-delivery-userpass")
    );
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("nats-userpass-live")
    );

    let channels = server.state.alert_channels.read().await.clone();
    let smtp_channel = channels
        .iter()
        .find(|channel| channel.id == "smtp-plain-live")
        .expect("smtp plain channel should exist");
    assert_eq!(smtp_channel.status, "healthy");
    assert!(smtp_channel.error.is_none());
    let nats_channel = channels
        .iter()
        .find(|channel| channel.id == "nats-userpass-live")
        .expect("nats user/pass channel should exist");
    assert_eq!(nats_channel.status, "healthy");
    assert!(nats_channel.error.is_none());

    let queue = server.state.alert_delivery_queue.read().await.clone();
    let history_queue = queue
        .iter()
        .filter(|item| item.history_id == history_id)
        .collect::<Vec<_>>();
    assert_eq!(history_queue.len(), 2);
    assert!(history_queue.iter().all(|item| item.status == "done"));

    nats.stop().await;
    smtp.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_delivery_external_redis_and_elasticsearch_live_regression() {
    let server = AdminServer::spawn().await;
    let redis = MockRedisServer::spawn(MockRedisAuthMode::Password("redis-pass".to_string())).await;
    let elasticsearch = MockElasticsearchServer::spawn().await;

    let token = server.admin_token().await;

    let redis_channel = server
        .create_channel(
            &token,
            "redis-live",
            "redis-live",
            "redis",
            &format!("redis://:redis-pass@{}/ops.redis", redis.address),
        )
        .await;
    assert_eq!(
        redis_channel.pointer("/data/id").and_then(Value::as_str),
        Some("redis-live")
    );

    let elastic_channel = server
        .create_channel(
            &token,
            "elasticsearch-live",
            "elasticsearch-live",
            "elasticsearch",
            &format!("{}/rustio-alerts/_doc", elasticsearch.base_url),
        )
        .await;
    assert_eq!(
        elastic_channel.pointer("/data/id").and_then(Value::as_str),
        Some("elasticsearch-live")
    );

    let redis_test = server.test_channel(&token, "redis-live").await;
    assert_eq!(
        redis_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    assert_eq!(redis_test.pointer("/data/error"), Some(&Value::Null));

    let elastic_test = server.test_channel(&token, "elasticsearch-live").await;
    assert_eq!(
        elastic_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    assert_eq!(elastic_test.pointer("/data/error"), Some(&Value::Null));

    let redis_publishes = redis.publishes();
    assert_eq!(redis_publishes.len(), 1);
    assert!(redis_publishes[0].auth_username.is_none());
    assert_eq!(redis_publishes[0].channel, "ops.redis");
    assert_eq!(
        redis_publishes[0]
            .payload
            .get("kind")
            .and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        redis_publishes[0]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("redis-live")
    );

    let elastic_docs = elasticsearch.documents();
    assert_eq!(elastic_docs.len(), 1);
    assert_eq!(elastic_docs[0].path, "rustio-alerts/_doc");
    assert_eq!(
        elastic_docs[0].payload.get("kind").and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        elastic_docs[0]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("elasticsearch-live")
    );

    let create_rule = server
        .create_rule(
            &token,
            "rule-live-delivery-redis-elastic",
            "rule-live-delivery-redis-elastic",
            &["redis-live", "elasticsearch-live"],
        )
        .await;
    assert_eq!(
        create_rule.pointer("/data/id").and_then(Value::as_str),
        Some("rule-live-delivery-redis-elastic")
    );

    let simulate = server
        .simulate_rule(&token, "rule-live-delivery-redis-elastic")
        .await;
    let history_id = simulate
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("simulate response should contain history id")
        .to_string();

    let mut delivered = false;
    for _ in 0..80 {
        let redis_count = redis.publishes().len();
        let elastic_count = elasticsearch.documents().len();
        let queue = server.state.alert_delivery_queue.read().await.clone();
        let done_count = queue
            .iter()
            .filter(|item| item.history_id == history_id && item.status == "done")
            .count();
        if redis_count >= 2 && elastic_count >= 2 && done_count >= 2 {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        delivered,
        "queued redis and elasticsearch deliveries should complete"
    );

    let redis_publishes = redis.publishes();
    assert_eq!(redis_publishes.len(), 2);
    assert_eq!(redis_publishes[1].channel, "ops.redis");
    assert_eq!(
        redis_publishes[1]
            .payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        redis_publishes[1]
            .payload
            .get("rule_id")
            .and_then(Value::as_str),
        Some("rule-live-delivery-redis-elastic")
    );
    assert_eq!(
        redis_publishes[1]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("redis-live")
    );

    let elastic_docs = elasticsearch.documents();
    assert_eq!(elastic_docs.len(), 2);
    assert_eq!(elastic_docs[1].path, "rustio-alerts/_doc");
    assert_eq!(
        elastic_docs[1]
            .payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        elastic_docs[1]
            .payload
            .get("rule_id")
            .and_then(Value::as_str),
        Some("rule-live-delivery-redis-elastic")
    );
    assert_eq!(
        elastic_docs[1]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("elasticsearch-live")
    );

    let channels = server.state.alert_channels.read().await.clone();
    let redis_channel = channels
        .iter()
        .find(|channel| channel.id == "redis-live")
        .expect("redis channel should exist");
    assert_eq!(redis_channel.status, "healthy");
    assert!(redis_channel.error.is_none());
    let elastic_channel = channels
        .iter()
        .find(|channel| channel.id == "elasticsearch-live")
        .expect("elasticsearch channel should exist");
    assert_eq!(elastic_channel.status, "healthy");
    assert!(elastic_channel.error.is_none());

    let queue = server.state.alert_delivery_queue.read().await.clone();
    let history_queue = queue
        .iter()
        .filter(|item| item.history_id == history_id)
        .collect::<Vec<_>>();
    assert_eq!(history_queue.len(), 2);
    assert!(history_queue.iter().all(|item| item.status == "done"));

    elasticsearch.stop().await;
    redis.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_delivery_external_kafka_and_rabbitmq_http_templates_regression() {
    let server = AdminServer::spawn().await;
    let capture = MockHttpCaptureServer::spawn().await;
    let token = server.admin_token().await;

    let kafka_channel = server
        .create_channel_raw(
            &token,
            json!({
                "id": "kafka-live",
                "name": "kafka-live",
                "kind": "kafka",
                "endpoint": format!("{}/topics/rustio-alerts", capture.base_url),
                "enabled": true,
                "payload_template": r#"{"channel":"{{channel_id}}","kind":"{{kind}}"}"#,
                "header_template": {
                    "x-rustio-channel": "{{channel_id}}"
                }
            }),
        )
        .await;
    assert_eq!(
        kafka_channel.pointer("/data/id").and_then(Value::as_str),
        Some("kafka-live")
    );

    let rabbitmq_channel = server
        .create_channel_raw(
            &token,
            json!({
                "id": "rabbitmq-live",
                "name": "rabbitmq-live",
                "kind": "rabbitmq",
                "endpoint": format!("{}/api/exchanges/%2F/rustio/publish?routing_key=ops.alerts", capture.base_url),
                "enabled": true,
                "payload_template": r#"channel={{channel_id}}"#,
                "header_template": {
                    "x-rustio-kind": "{{kind}}"
                }
            }),
        )
        .await;
    assert_eq!(
        rabbitmq_channel.pointer("/data/id").and_then(Value::as_str),
        Some("rabbitmq-live")
    );

    let kafka_test = server.test_channel(&token, "kafka-live").await;
    assert_eq!(
        kafka_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    let rabbitmq_test = server.test_channel(&token, "rabbitmq-live").await;
    assert_eq!(
        rabbitmq_test
            .pointer("/data/status")
            .and_then(Value::as_str),
        Some("healthy")
    );

    let records = capture.records();
    assert_eq!(records.len(), 2);
    let kafka_record = records
        .iter()
        .find(|record| record.path == "topics/rustio-alerts")
        .expect("kafka record should exist");
    assert_eq!(
        kafka_record.headers.get("content-type").map(String::as_str),
        Some("application/vnd.kafka.json.v2+json")
    );
    assert_eq!(
        kafka_record
            .headers
            .get("x-rustio-channel")
            .map(String::as_str),
        Some("kafka-live")
    );
    assert_eq!(
        kafka_record.payload.pointer("/records/0/value/channel"),
        Some(&json!("kafka-live"))
    );
    assert_eq!(
        kafka_record.payload.pointer("/records/0/value/kind"),
        Some(&json!("channel-test"))
    );

    let rabbitmq_record = records
        .iter()
        .find(|record| record.payload.get("routing_key") == Some(&json!("ops.alerts")))
        .expect("rabbitmq record should exist");
    assert_eq!(
        rabbitmq_record
            .headers
            .get("x-rustio-kind")
            .map(String::as_str),
        Some("channel-test")
    );
    assert_eq!(
        rabbitmq_record.payload.get("routing_key"),
        Some(&json!("ops.alerts"))
    );
    assert_eq!(
        rabbitmq_record.payload.get("payload"),
        Some(&json!("channel=rabbitmq-live"))
    );

    capture.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_delivery_external_tls_live_regression() {
    let server = AdminServer::spawn().await;
    let ca_file = write_test_alert_tls_ca("external-live");
    let smtp_starttls = MockSmtpServer::spawn_with_transport(
        "tls-user",
        "tls-pass",
        MockSmtpAuthMode::LoginFallback,
        MockSmtpTransport::StartTls,
    )
    .await;
    let smtp_tls = MockSmtpServer::spawn_with_transport(
        "tls-user",
        "tls-pass",
        MockSmtpAuthMode::Plain,
        MockSmtpTransport::Tls,
    )
    .await;
    let nats = MockNatsServer::spawn_with_transport(
        MockNatsAuthMode::Token("tls-token".to_string()),
        MockNatsTransport::Tls,
    )
    .await;

    std::env::set_var("RUSTIO_ALERT_SMTP_USERNAME", "tls-user");
    std::env::set_var("RUSTIO_ALERT_SMTP_PASSWORD", "tls-pass");
    std::env::set_var("RUSTIO_ALERT_SMTP_FROM", "rustio-alert@example.internal");
    std::env::set_var("RUSTIO_ALERT_NATS_TOKEN", "tls-token");
    std::env::set_var("RUSTIO_ALERT_TLS_CA_FILE", &ca_file);

    let token = server.admin_token().await;

    let starttls_channel = server
        .create_channel(
            &token,
            "smtp-starttls-live",
            "smtp-starttls-live",
            "email",
            &format!(
                "smtp+starttls://{}/starttls@example.com",
                smtp_starttls.address
            ),
        )
        .await;
    assert_eq!(
        starttls_channel.pointer("/data/id").and_then(Value::as_str),
        Some("smtp-starttls-live")
    );

    let smtps_channel = server
        .create_channel(
            &token,
            "smtp-tls-live",
            "smtp-tls-live",
            "email",
            &format!("smtps://{}/tls@example.com", smtp_tls.address),
        )
        .await;
    assert_eq!(
        smtps_channel.pointer("/data/id").and_then(Value::as_str),
        Some("smtp-tls-live")
    );

    let nats_channel = server
        .create_channel(
            &token,
            "nats-tls-live",
            "nats-tls-live",
            "nats",
            &format!("natss://{}/ops.tls", nats.address),
        )
        .await;
    assert_eq!(
        nats_channel.pointer("/data/id").and_then(Value::as_str),
        Some("nats-tls-live")
    );

    let starttls_test = server.test_channel(&token, "smtp-starttls-live").await;
    assert_eq!(
        starttls_test
            .pointer("/data/status")
            .and_then(Value::as_str),
        Some("healthy")
    );
    let smtps_test = server.test_channel(&token, "smtp-tls-live").await;
    assert_eq!(
        smtps_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );
    let nats_test = server.test_channel(&token, "nats-tls-live").await;
    assert_eq!(
        nats_test.pointer("/data/status").and_then(Value::as_str),
        Some("healthy")
    );

    let starttls_messages = smtp_starttls.messages();
    assert_eq!(starttls_messages.len(), 1);
    assert_eq!(starttls_messages[0].auth_method.as_deref(), Some("login"));
    assert_eq!(starttls_messages[0].username.as_deref(), Some("tls-user"));
    assert_eq!(
        starttls_messages[0].to.as_deref(),
        Some("starttls@example.com")
    );
    let starttls_direct_payload = smtp_payload_from_raw_message(&starttls_messages[0].raw_message);
    assert_eq!(
        starttls_direct_payload.get("kind").and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        starttls_direct_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-starttls-live")
    );

    let smtps_messages = smtp_tls.messages();
    assert_eq!(smtps_messages.len(), 1);
    assert_eq!(smtps_messages[0].auth_method.as_deref(), Some("plain"));
    assert_eq!(smtps_messages[0].username.as_deref(), Some("tls-user"));
    assert_eq!(smtps_messages[0].to.as_deref(), Some("tls@example.com"));
    let smtps_direct_payload = smtp_payload_from_raw_message(&smtps_messages[0].raw_message);
    assert_eq!(
        smtps_direct_payload.get("kind").and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        smtps_direct_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-tls-live")
    );

    let nats_publishes = nats.publishes();
    assert_eq!(nats_publishes.len(), 1);
    assert_eq!(
        nats_publishes[0]
            .connect_payload
            .get("auth_token")
            .and_then(Value::as_str),
        Some("tls-token")
    );
    assert_eq!(
        nats_publishes[0]
            .connect_payload
            .get("tls_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(nats_publishes[0].subject, "ops.tls");
    assert_eq!(
        nats_publishes[0]
            .payload
            .get("kind")
            .and_then(Value::as_str),
        Some("channel-test")
    );
    assert_eq!(
        nats_publishes[0]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("nats-tls-live")
    );

    let create_rule = server
        .create_rule(
            &token,
            "rule-live-delivery-tls",
            "rule-live-delivery-tls",
            &["smtp-starttls-live", "smtp-tls-live", "nats-tls-live"],
        )
        .await;
    assert_eq!(
        create_rule.pointer("/data/id").and_then(Value::as_str),
        Some("rule-live-delivery-tls")
    );

    let simulate = server.simulate_rule(&token, "rule-live-delivery-tls").await;
    let history_id = simulate
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("simulate response should contain history id")
        .to_string();

    let mut delivered = false;
    for _ in 0..80 {
        let starttls_count = smtp_starttls.messages().len();
        let smtps_count = smtp_tls.messages().len();
        let nats_count = nats.publishes().len();
        let queue = server.state.alert_delivery_queue.read().await.clone();
        let done_count = queue
            .iter()
            .filter(|item| item.history_id == history_id && item.status == "done")
            .count();
        if starttls_count >= 2 && smtps_count >= 2 && nats_count >= 2 && done_count >= 3 {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(delivered, "queued tls deliveries should complete");

    let starttls_messages = smtp_starttls.messages();
    assert_eq!(starttls_messages.len(), 2);
    let starttls_queued_payload = smtp_payload_from_raw_message(&starttls_messages[1].raw_message);
    assert_eq!(
        starttls_queued_payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        starttls_queued_payload
            .get("rule_id")
            .and_then(Value::as_str),
        Some("rule-live-delivery-tls")
    );
    assert_eq!(
        starttls_queued_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-starttls-live")
    );

    let smtps_messages = smtp_tls.messages();
    assert_eq!(smtps_messages.len(), 2);
    let smtps_queued_payload = smtp_payload_from_raw_message(&smtps_messages[1].raw_message);
    assert_eq!(
        smtps_queued_payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        smtps_queued_payload.get("rule_id").and_then(Value::as_str),
        Some("rule-live-delivery-tls")
    );
    assert_eq!(
        smtps_queued_payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("smtp-tls-live")
    );

    let nats_publishes = nats.publishes();
    assert_eq!(nats_publishes.len(), 2);
    assert_eq!(
        nats_publishes[1]
            .connect_payload
            .get("auth_token")
            .and_then(Value::as_str),
        Some("tls-token")
    );
    assert_eq!(
        nats_publishes[1]
            .connect_payload
            .get("tls_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(nats_publishes[1].subject, "ops.tls");
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("history_id")
            .and_then(Value::as_str),
        Some(history_id.as_str())
    );
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("rule_id")
            .and_then(Value::as_str),
        Some("rule-live-delivery-tls")
    );
    assert_eq!(
        nats_publishes[1]
            .payload
            .get("channel_id")
            .and_then(Value::as_str),
        Some("nats-tls-live")
    );

    let channels = server.state.alert_channels.read().await.clone();
    for channel_id in ["smtp-starttls-live", "smtp-tls-live", "nats-tls-live"] {
        let channel = channels
            .iter()
            .find(|channel| channel.id == channel_id)
            .unwrap_or_else(|| panic!("channel should exist: {channel_id}"));
        assert_eq!(channel.status, "healthy");
        assert!(channel.error.is_none());
    }

    let queue = server.state.alert_delivery_queue.read().await.clone();
    let history_queue = queue
        .iter()
        .filter(|item| item.history_id == history_id)
        .collect::<Vec<_>>();
    assert_eq!(history_queue.len(), 3);
    assert!(history_queue.iter().all(|item| item.status == "done"));

    nats.stop().await;
    smtp_tls.stop().await;
    smtp_starttls.stop().await;
    let _ = std::fs::remove_file(&ca_file);
    server.stop().await;
}
