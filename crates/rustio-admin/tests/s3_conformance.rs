use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path as AxumPath, State},
    http::HeaderMap as AxumHeaderMap,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{Duration as ChronoDuration, Utc};
use md5::Md5;
use reqwest::{header, Method, StatusCode};
use rustio_admin::{build_router, AppState};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::sleep};

const BASIC_AUTH_HEADER: &str = "Basic cnVzdGlvYWRtaW46cnVzdGlvYWRtaW4=";

struct TestServer {
    base_url: String,
    client: reqwest::Client,
    state: Arc<AppState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
    data_dir: PathBuf,
    _env_guard: Option<MutexGuard<'static, ()>>,
}

struct MockKmsServer {
    base_url: String,
    state: Arc<MockKmsState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct MockKmsState {
    generic_ciphertexts: Mutex<HashMap<String, String>>,
    vault_ciphertexts: Mutex<HashMap<String, String>>,
    kes_ciphertexts: Mutex<HashMap<String, String>>,
    requests: Mutex<Vec<MockKmsRequest>>,
}

#[derive(Debug, Clone)]
struct MockKmsRequest {
    provider: String,
    operation: String,
    key_id: Option<String>,
    authorization: Option<String>,
    vault_token: Option<String>,
    kes_api_key: Option<String>,
    context: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct GenericEncryptRequest {
    key_id: String,
    plaintext_base64: String,
    context: Value,
}

#[derive(Debug, Serialize)]
struct GenericEncryptResponse {
    ciphertext_base64: String,
}

#[derive(Debug, Deserialize)]
struct GenericDecryptRequest {
    ciphertext_base64: String,
    context: Value,
}

#[derive(Debug, Serialize)]
struct GenericDecryptResponse {
    plaintext_base64: String,
}

#[derive(Debug, Deserialize)]
struct VaultEncryptRequest {
    plaintext: String,
    context: Option<String>,
}

#[derive(Debug, Serialize)]
struct VaultEncryptResponseEnvelope {
    data: VaultEncryptResponse,
}

#[derive(Debug, Serialize)]
struct VaultEncryptResponse {
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct VaultDecryptRequest {
    ciphertext: String,
    context: Option<String>,
}

#[derive(Debug, Serialize)]
struct VaultDecryptResponseEnvelope {
    data: VaultDecryptResponse,
}

#[derive(Debug, Serialize)]
struct VaultDecryptResponse {
    plaintext: String,
}

#[derive(Debug, Deserialize)]
struct KesGenerateRequest {
    plaintext: String,
    length: usize,
    associated_data: Option<String>,
}

#[derive(Debug, Serialize)]
struct KesGenerateResponse {
    plaintext: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct KesDecryptRequest {
    ciphertext: String,
    associated_data: Option<String>,
}

#[derive(Debug, Serialize)]
struct KesDecryptResponse {
    plaintext: String,
}

fn decode_kms_context_base64(raw: Option<&str>) -> Option<Value> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let bytes = BASE64.decode(raw).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

fn record_kms_request(
    state: &MockKmsState,
    provider: &str,
    operation: &str,
    key_id: Option<String>,
    headers: &AxumHeaderMap,
    context: Option<Value>,
) {
    state
        .requests
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(MockKmsRequest {
            provider: provider.to_string(),
            operation: operation.to_string(),
            key_id,
            authorization: headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
            vault_token: headers
                .get("x-vault-token")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
            kes_api_key: headers
                .get("x-kes-api-key")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string()),
            context,
        });
}

async fn mock_kms_generic_encrypt(
    State(state): State<Arc<MockKmsState>>,
    headers: AxumHeaderMap,
    Json(body): Json<GenericEncryptRequest>,
) -> Json<GenericEncryptResponse> {
    let ciphertext = format!("generic:{}:{}", body.key_id, uuid::Uuid::new_v4().simple());
    state
        .generic_ciphertexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(ciphertext.clone(), body.plaintext_base64.clone());
    record_kms_request(
        state.as_ref(),
        "generic",
        "encrypt",
        Some(body.key_id),
        &headers,
        Some(body.context),
    );
    Json(GenericEncryptResponse {
        ciphertext_base64: ciphertext,
    })
}

async fn mock_kms_generic_decrypt(
    State(state): State<Arc<MockKmsState>>,
    headers: AxumHeaderMap,
    Json(body): Json<GenericDecryptRequest>,
) -> Result<Json<GenericDecryptResponse>, axum::http::StatusCode> {
    let plaintext = state
        .generic_ciphertexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&body.ciphertext_base64)
        .cloned()
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    record_kms_request(
        state.as_ref(),
        "generic",
        "decrypt",
        None,
        &headers,
        Some(body.context),
    );
    Ok(Json(GenericDecryptResponse {
        plaintext_base64: plaintext,
    }))
}

async fn mock_kms_vault_encrypt(
    State(state): State<Arc<MockKmsState>>,
    headers: AxumHeaderMap,
    AxumPath(key_id): AxumPath<String>,
    Json(body): Json<VaultEncryptRequest>,
) -> Json<VaultEncryptResponseEnvelope> {
    let ciphertext = format!("vault:v1:{}:{}", key_id, uuid::Uuid::new_v4().simple());
    state
        .vault_ciphertexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(ciphertext.clone(), body.plaintext.clone());
    record_kms_request(
        state.as_ref(),
        "vault-transit",
        "encrypt",
        Some(key_id),
        &headers,
        decode_kms_context_base64(body.context.as_deref()),
    );
    Json(VaultEncryptResponseEnvelope {
        data: VaultEncryptResponse { ciphertext },
    })
}

async fn mock_kms_vault_decrypt(
    State(state): State<Arc<MockKmsState>>,
    headers: AxumHeaderMap,
    AxumPath(key_id): AxumPath<String>,
    Json(body): Json<VaultDecryptRequest>,
) -> Result<Json<VaultDecryptResponseEnvelope>, axum::http::StatusCode> {
    let plaintext = state
        .vault_ciphertexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&body.ciphertext)
        .cloned()
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    record_kms_request(
        state.as_ref(),
        "vault-transit",
        "decrypt",
        Some(key_id),
        &headers,
        decode_kms_context_base64(body.context.as_deref()),
    );
    Ok(Json(VaultDecryptResponseEnvelope {
        data: VaultDecryptResponse { plaintext },
    }))
}

async fn mock_kms_kes_generate(
    State(state): State<Arc<MockKmsState>>,
    headers: AxumHeaderMap,
    AxumPath(key_id): AxumPath<String>,
    Json(body): Json<KesGenerateRequest>,
) -> Json<KesGenerateResponse> {
    let ciphertext = format!("kes:{}:{}", key_id, uuid::Uuid::new_v4().simple());
    state
        .kes_ciphertexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(ciphertext.clone(), body.plaintext.clone());
    let context = decode_kms_context_base64(body.associated_data.as_deref());
    record_kms_request(
        state.as_ref(),
        "kes",
        "encrypt",
        Some(key_id),
        &headers,
        context,
    );
    assert_eq!(body.length, 32, "kes generate should request 32-byte keys");
    Json(KesGenerateResponse {
        plaintext: body.plaintext,
        ciphertext,
    })
}

async fn mock_kms_kes_decrypt(
    State(state): State<Arc<MockKmsState>>,
    headers: AxumHeaderMap,
    AxumPath(key_id): AxumPath<String>,
    Json(body): Json<KesDecryptRequest>,
) -> Result<Json<KesDecryptResponse>, axum::http::StatusCode> {
    let plaintext = state
        .kes_ciphertexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&body.ciphertext)
        .cloned()
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    let context = decode_kms_context_base64(body.associated_data.as_deref());
    record_kms_request(
        state.as_ref(),
        "kes",
        "decrypt",
        Some(key_id),
        &headers,
        context,
    );
    Ok(Json(KesDecryptResponse { plaintext }))
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

impl MockKmsServer {
    async fn spawn() -> Self {
        let state = Arc::new(MockKmsState::default());
        let app = Router::new()
            .route("/v1/crypto/encrypt", post(mock_kms_generic_encrypt))
            .route("/v1/crypto/decrypt", post(mock_kms_generic_decrypt))
            .route("/v1/transit/encrypt/{key_id}", post(mock_kms_vault_encrypt))
            .route("/v1/transit/decrypt/{key_id}", post(mock_kms_vault_decrypt))
            .route("/v1/key/generate/{key_id}", post(mock_kms_kes_generate))
            .route("/v1/key/decrypt/{key_id}", post(mock_kms_kes_decrypt))
            .with_state(Arc::clone(&state));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock kms listener");
        let addr = listener
            .local_addr()
            .expect("failed to read mock kms listen addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let server = Self {
            base_url: format!("http://{addr}"),
            state,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        };
        server.wait_until_ready().await;
        server
    }

    async fn wait_until_ready(&self) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build mock kms client");
        for _ in 0..100 {
            if client
                .post(format!("{}/v1/crypto/encrypt", self.base_url))
                .json(&json!({
                    "key_id": "ready-check",
                    "plaintext_base64": BASE64.encode("ready"),
                    "context": {}
                }))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("mock kms did not become ready");
    }

    fn requests(&self) -> Vec<MockKmsRequest> {
        self.state
            .requests
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

impl TestServer {
    async fn spawn() -> Self {
        let env_guard = env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "rustio-s3-regression-{}-{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(&data_dir).expect("failed to create temp data dir");

        std::env::set_var("RUSTIO_DATA_DIR", &data_dir);
        std::env::set_var("RUSTIO_ROOT_USER", "rustioadmin");
        std::env::set_var("RUSTIO_ROOT_PASSWORD", "rustioadmin");
        for key in [
            "RUSTIO_KMS_EXTERNAL_ENABLED",
            "RUSTIO_KMS_PROVIDER",
            "RUSTIO_KMS_TOKEN",
        ] {
            std::env::remove_var(key);
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind random local port");
        let addr = listener.local_addr().expect("failed to read listen addr");
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
            .expect("failed to build reqwest client");
        let base_url = format!("http://{addr}");
        let server = Self {
            base_url,
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
        panic!("server did not become ready: {ready_url}");
    }

    fn s3(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.base_url, path))
            .header(header::AUTHORIZATION, BASIC_AUTH_HEADER)
    }

    async fn admin_token(&self) -> String {
        let login_resp = self
            .client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"username":"admin","password":"rustio-admin"}"#)
            .send()
            .await
            .expect("admin login request failed");
        assert_eq!(login_resp.status(), StatusCode::OK, "admin login failed");
        let payload = login_resp
            .json::<serde_json::Value>()
            .await
            .expect("failed to decode admin login response");
        payload
            .pointer("/data/access_token")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string()
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

fn basic_auth_header(access_key: &str, secret_key: &str) -> String {
    format!(
        "Basic {}",
        BASE64.encode(format!("{access_key}:{secret_key}"))
    )
}

fn sse_customer_material(key: &[u8]) -> (String, String) {
    (BASE64.encode(key), BASE64.encode(Md5::digest(key)))
}

fn xml_tag(body: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = body.find(&start_tag)?;
    let from = start + start_tag.len();
    let tail = &body[from..];
    let end = tail.find(&end_tag)?;
    Some(tail[..end].to_string())
}

#[derive(Debug)]
struct EventStreamMessage {
    event_type: String,
    payload: Vec<u8>,
}

fn parse_event_stream_headers(bytes: &[u8]) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let name_len = bytes[cursor] as usize;
        cursor += 1;
        let name = String::from_utf8_lossy(&bytes[cursor..cursor + name_len]).to_string();
        cursor += name_len;
        let value_type = bytes[cursor];
        cursor += 1;
        assert_eq!(value_type, 7, "only string headers are expected");
        let value_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        let value = String::from_utf8_lossy(&bytes[cursor..cursor + value_len]).to_string();
        cursor += value_len;
        headers.insert(name, value);
    }
    headers
}

fn decode_event_stream(bytes: &[u8]) -> Vec<EventStreamMessage> {
    let mut messages = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let total_len = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .expect("event stream total length"),
        ) as usize;
        let headers_len = u32::from_be_bytes(
            bytes[cursor + 4..cursor + 8]
                .try_into()
                .expect("event stream headers length"),
        ) as usize;
        let headers_start = cursor + 12;
        let headers_end = headers_start + headers_len;
        let payload_end = cursor + total_len - 4;
        let headers = parse_event_stream_headers(&bytes[headers_start..headers_end]);
        messages.push(EventStreamMessage {
            event_type: headers.get(":event-type").cloned().unwrap_or_default(),
            payload: bytes[headers_end..payload_end].to_vec(),
        });
        cursor += total_len;
    }
    messages
}

async fn assert_s3_error(resp: reqwest::Response, status: StatusCode, code: &str) {
    let actual_status = resp.status();
    let body = resp.text().await.expect("failed to read error body");
    assert_eq!(actual_status, status, "unexpected status body={body}");
    let actual_code = xml_tag(&body, "Code").unwrap_or_default();
    assert_eq!(actual_code, code, "unexpected S3 error code body={body}");
}

async fn assert_s3_error_message(
    resp: reqwest::Response,
    status: StatusCode,
    code: &str,
    message: &str,
) {
    let actual_status = resp.status();
    let body = resp.text().await.expect("failed to read error body");
    assert_eq!(actual_status, status, "unexpected status body={body}");
    let actual_code = xml_tag(&body, "Code").unwrap_or_default();
    assert_eq!(actual_code, code, "unexpected S3 error code body={body}");
    let actual_message = xml_tag(&body, "Message").unwrap_or_default();
    assert_eq!(
        actual_message, message,
        "unexpected S3 error message body={body}"
    );
}

async fn wait_for_condition<F>(mut predicate: F, message: &str)
where
    F: FnMut() -> bool,
{
    for _ in 0..120 {
        if predicate() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("{message}");
}

fn backdate_created_at(path: &PathBuf, days: i64) {
    let mut payload = serde_json::from_slice::<Value>(
        &std::fs::read(path).expect("failed to read json file for backdate"),
    )
    .expect("failed to decode json file for backdate");
    payload["created_at"] = Value::String(
        (Utc::now() - ChronoDuration::days(days))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    );
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&payload).expect("failed to encode backdated json"),
    )
    .expect("failed to write backdated json");
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_conformance_regression_matrix() {
    let server = TestServer::spawn().await;
    let bucket = "sdk-regression-bucket";
    let object = "regression/object.txt";
    let meta_object = "regression/meta.txt";
    let copy_source_object = "regression/copy-source.txt";
    let copy_target_object = "regression/copy-target.txt";
    let lock_object = "regression/lock.txt";
    let sse_default_object = "regression/sse-default.txt";
    let sse_kms_object = "regression/sse-kms.txt";
    let sse_multipart_object = "regression/sse-multipart.txt";

    // Missing auth should be denied on S3 routes.
    let no_auth = server
        .client
        .put(format!("{}/{}", server.base_url, "unauthorized-bucket"))
        .send()
        .await
        .expect("request failed");
    assert_s3_error(no_auth, StatusCode::FORBIDDEN, "AccessDenied").await;

    // Bucket create + duplicate create.
    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let create_bucket_dup = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("duplicate create bucket failed");
    assert_s3_error(
        create_bucket_dup,
        StatusCode::CONFLICT,
        "BucketAlreadyOwnedByYou",
    )
    .await;

    // Head bucket should include region header.
    let head_bucket = server
        .s3(Method::HEAD, &format!("/{bucket}"))
        .send()
        .await
        .expect("head bucket failed");
    assert_eq!(head_bucket.status(), StatusCode::OK);
    assert_eq!(
        head_bucket
            .headers()
            .get("x-amz-bucket-region")
            .and_then(|v| v.to_str().ok()),
        Some("us-east-1")
    );

    // Invalid list-type should return InvalidArgument.
    let list_invalid = server
        .s3(Method::GET, &format!("/{bucket}?list-type=3"))
        .send()
        .await
        .expect("list invalid request failed");
    assert_s3_error(list_invalid, StatusCode::BAD_REQUEST, "InvalidArgument").await;

    // ListObjectsV2 pagination + delimiter/common-prefixes.
    for (key, body) in [
        ("paging/a.txt", "a"),
        ("paging/b.txt", "b"),
        ("paging/sub/c.txt", "c"),
    ] {
        let put = server
            .s3(Method::PUT, &format!("/{bucket}/{key}"))
            .body(body)
            .send()
            .await
            .expect("put paging object failed");
        assert_eq!(put.status(), StatusCode::OK);
    }

    let list_v2_page1 = server
        .s3(
            Method::GET,
            &format!("/{bucket}?list-type=2&prefix=paging/&delimiter=/&max-keys=2"),
        )
        .send()
        .await
        .expect("list v2 page1 failed");
    assert_eq!(list_v2_page1.status(), StatusCode::OK);
    let list_v2_page1_xml = list_v2_page1.text().await.expect("read list v2 page1");
    assert!(
        list_v2_page1_xml.contains("<Key>paging/a.txt</Key>")
            && list_v2_page1_xml.contains("<Key>paging/b.txt</Key>"),
        "unexpected list v2 page1 XML: {list_v2_page1_xml}"
    );
    assert!(
        list_v2_page1_xml.contains("<IsTruncated>true</IsTruncated>"),
        "page1 should be truncated: {list_v2_page1_xml}"
    );
    let continuation_token =
        xml_tag(&list_v2_page1_xml, "NextContinuationToken").unwrap_or_default();
    assert!(
        !continuation_token.is_empty(),
        "missing NextContinuationToken: {list_v2_page1_xml}"
    );

    let list_v2_page2 = server
        .s3(
            Method::GET,
            &format!(
                "/{bucket}?list-type=2&prefix=paging/&delimiter=/&continuation-token={continuation_token}"
            ),
        )
        .send()
        .await
        .expect("list v2 page2 failed");
    assert_eq!(list_v2_page2.status(), StatusCode::OK);
    let list_v2_page2_xml = list_v2_page2.text().await.expect("read list v2 page2");
    assert!(
        list_v2_page2_xml.contains("<CommonPrefixes><Prefix>paging/sub/</Prefix></CommonPrefixes>"),
        "page2 should contain common-prefix paging/sub/: {list_v2_page2_xml}"
    );
    assert!(
        list_v2_page2_xml.contains("<IsTruncated>false</IsTruncated>"),
        "page2 should not be truncated: {list_v2_page2_xml}"
    );

    let list_v1_delimiter = server
        .s3(
            Method::GET,
            &format!("/{bucket}?prefix=paging/&delimiter=/"),
        )
        .send()
        .await
        .expect("list v1 delimiter failed");
    assert_eq!(list_v1_delimiter.status(), StatusCode::OK);
    let list_v1_delimiter_xml = list_v1_delimiter.text().await.expect("read list v1");
    assert!(
        list_v1_delimiter_xml
            .contains("<CommonPrefixes><Prefix>paging/sub/</Prefix></CommonPrefixes>"),
        "list v1 should contain common-prefix paging/sub/: {list_v1_delimiter_xml}"
    );

    // Put two versions and capture latest version id.
    let put_v1 = server
        .s3(Method::PUT, &format!("/{bucket}/{object}"))
        .body("v1-body")
        .send()
        .await
        .expect("put v1 failed");
    assert_eq!(put_v1.status(), StatusCode::OK);
    let v1_id = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!v1_id.is_empty(), "missing version id for v1");

    let put_v2 = server
        .s3(Method::PUT, &format!("/{bucket}/{object}"))
        .body("v2-body")
        .send()
        .await
        .expect("put v2 failed");
    assert_eq!(put_v2.status(), StatusCode::OK);
    let v2_id = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!v2_id.is_empty(), "missing version id for v2");
    assert_ne!(v1_id, v2_id, "version id should change between puts");

    // Get latest object body.
    let get_latest = server
        .s3(Method::GET, &format!("/{bucket}/{object}"))
        .send()
        .await
        .expect("get latest failed");
    assert_eq!(get_latest.status(), StatusCode::OK);
    let latest_etag = get_latest
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!latest_etag.is_empty(), "latest object should include etag");
    assert_eq!(
        get_latest.text().await.expect("failed to read get body"),
        "v2-body"
    );

    // Range + conditional headers for object GET/HEAD.
    let range_get = server
        .s3(Method::GET, &format!("/{bucket}/{object}"))
        .header(header::RANGE, "bytes=0-1")
        .send()
        .await
        .expect("range get failed");
    assert_eq!(range_get.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range_get
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok()),
        Some("bytes 0-1/7")
    );
    assert_eq!(
        range_get.text().await.expect("failed to read range body"),
        "v2"
    );

    let invalid_range = server
        .s3(Method::GET, &format!("/{bucket}/{object}"))
        .header(header::RANGE, "bytes=999-")
        .send()
        .await
        .expect("invalid range request failed");
    assert_s3_error(
        invalid_range,
        StatusCode::RANGE_NOT_SATISFIABLE,
        "InvalidRange",
    )
    .await;

    let not_modified = server
        .s3(Method::GET, &format!("/{bucket}/{object}"))
        .header(header::IF_NONE_MATCH, latest_etag.as_str())
        .send()
        .await
        .expect("if-none-match request failed");
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

    let precondition_failed = server
        .s3(Method::GET, &format!("/{bucket}/{object}"))
        .header(header::IF_MATCH, "\"deadbeef\"")
        .send()
        .await
        .expect("if-match failure request failed");
    assert_s3_error(
        precondition_failed,
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
    )
    .await;

    let head_not_modified = server
        .s3(Method::HEAD, &format!("/{bucket}/{object}"))
        .header(header::IF_NONE_MATCH, latest_etag.as_str())
        .send()
        .await
        .expect("head if-none-match request failed");
    assert_eq!(head_not_modified.status(), StatusCode::NOT_MODIFIED);

    // Put object metadata + object tagging APIs.
    let put_meta = server
        .s3(Method::PUT, &format!("/{bucket}/{meta_object}"))
        .header("x-amz-meta-owner", "qa")
        .header("x-amz-meta-purpose", "s3-conformance")
        .header("x-amz-tagging", "env=dev&team=platform")
        .body("meta-body")
        .send()
        .await
        .expect("put meta object failed");
    assert_eq!(put_meta.status(), StatusCode::OK);
    let meta_version_id = put_meta
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        !meta_version_id.is_empty(),
        "meta object version id missing"
    );

    let head_meta = server
        .s3(Method::HEAD, &format!("/{bucket}/{meta_object}"))
        .send()
        .await
        .expect("head meta object failed");
    assert_eq!(head_meta.status(), StatusCode::OK);
    assert_eq!(
        head_meta
            .headers()
            .get("x-amz-meta-owner")
            .and_then(|v| v.to_str().ok()),
        Some("qa")
    );
    assert_eq!(
        head_meta
            .headers()
            .get("x-amz-meta-purpose")
            .and_then(|v| v.to_str().ok()),
        Some("s3-conformance")
    );
    assert_eq!(
        head_meta
            .headers()
            .get("x-amz-tagging-count")
            .and_then(|v| v.to_str().ok()),
        Some("2")
    );

    let get_obj_tagging = server
        .s3(Method::GET, &format!("/{bucket}/{meta_object}?tagging"))
        .send()
        .await
        .expect("get object tagging failed");
    assert_eq!(get_obj_tagging.status(), StatusCode::OK);
    let get_obj_tagging_xml = get_obj_tagging
        .text()
        .await
        .expect("read object tagging xml failed");
    assert!(
        get_obj_tagging_xml.contains("<Key>env</Key><Value>dev</Value>")
            && get_obj_tagging_xml.contains("<Key>team</Key><Value>platform</Value>"),
        "unexpected object tagging xml: {get_obj_tagging_xml}"
    );

    let put_obj_tagging_xml = r#"<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#;
    let put_obj_tagging = server
        .s3(Method::PUT, &format!("/{bucket}/{meta_object}?tagging"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(put_obj_tagging_xml.to_string())
        .send()
        .await
        .expect("put object tagging failed");
    assert_eq!(put_obj_tagging.status(), StatusCode::OK);

    let get_obj_tagging_v = server
        .s3(
            Method::GET,
            &format!("/{bucket}/{meta_object}?tagging&versionId={meta_version_id}"),
        )
        .send()
        .await
        .expect("get version object tagging failed");
    assert_eq!(get_obj_tagging_v.status(), StatusCode::OK);
    let get_obj_tagging_v_xml = get_obj_tagging_v
        .text()
        .await
        .expect("read version object tagging xml failed");
    assert!(
        get_obj_tagging_v_xml.contains("<Key>env</Key><Value>prod</Value>"),
        "unexpected version object tagging xml: {get_obj_tagging_v_xml}"
    );

    let delete_obj_tagging = server
        .s3(Method::DELETE, &format!("/{bucket}/{meta_object}?tagging"))
        .send()
        .await
        .expect("delete object tagging failed");
    assert_eq!(delete_obj_tagging.status(), StatusCode::NO_CONTENT);

    let get_obj_tagging_empty = server
        .s3(Method::GET, &format!("/{bucket}/{meta_object}?tagging"))
        .send()
        .await
        .expect("get empty object tagging failed");
    assert_eq!(get_obj_tagging_empty.status(), StatusCode::OK);
    let get_obj_tagging_empty_xml = get_obj_tagging_empty
        .text()
        .await
        .expect("read empty object tagging xml failed");
    assert!(
        !get_obj_tagging_empty_xml.contains("<Tag>"),
        "tagging should be empty after delete: {get_obj_tagging_empty_xml}"
    );

    // Bucket default encryption + object SSE headers.
    let put_bucket_encryption_xml = r#"<?xml version="1.0" encoding="UTF-8"?><ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"#;
    let put_bucket_encryption = server
        .s3(Method::PUT, &format!("/{bucket}?encryption"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(put_bucket_encryption_xml.to_string())
        .send()
        .await
        .expect("put bucket encryption failed");
    assert_eq!(put_bucket_encryption.status(), StatusCode::OK);

    let put_sse_default = server
        .s3(Method::PUT, &format!("/{bucket}/{sse_default_object}"))
        .body("sse-default-body")
        .send()
        .await
        .expect("put default sse object failed");
    assert_eq!(put_sse_default.status(), StatusCode::OK);
    assert_eq!(
        put_sse_default
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );

    let head_sse_default = server
        .s3(Method::HEAD, &format!("/{bucket}/{sse_default_object}"))
        .send()
        .await
        .expect("head default sse object failed");
    assert_eq!(head_sse_default.status(), StatusCode::OK);
    assert_eq!(
        head_sse_default
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );

    let get_sse_default = server
        .s3(Method::GET, &format!("/{bucket}/{sse_default_object}"))
        .send()
        .await
        .expect("get default sse object failed");
    assert_eq!(get_sse_default.status(), StatusCode::OK);
    assert_eq!(
        get_sse_default
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("AES256")
    );
    assert_eq!(
        get_sse_default
            .text()
            .await
            .expect("read default sse object body failed"),
        "sse-default-body"
    );

    let put_sse_kms = server
        .s3(Method::PUT, &format!("/{bucket}/{sse_kms_object}"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-aws-kms-key-id", "qa-kms-key")
        .body("sse-kms-body")
        .send()
        .await
        .expect("put kms sse object failed");
    assert_eq!(put_sse_kms.status(), StatusCode::OK);
    assert_eq!(
        put_sse_kms
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        put_sse_kms
            .headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|v| v.to_str().ok()),
        Some("qa-kms-key")
    );

    let init_sse_multipart = server
        .s3(
            Method::POST,
            &format!("/{bucket}/{sse_multipart_object}?uploads"),
        )
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-aws-kms-key-id", "qa-kms-mpu")
        .send()
        .await
        .expect("init sse multipart failed");
    assert_eq!(init_sse_multipart.status(), StatusCode::OK);
    assert_eq!(
        init_sse_multipart
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("aws:kms")
    );
    let init_sse_multipart_xml = init_sse_multipart
        .text()
        .await
        .expect("read init sse multipart body failed");
    let sse_upload_id = xml_tag(&init_sse_multipart_xml, "UploadId").unwrap_or_default();
    assert!(!sse_upload_id.is_empty(), "missing sse multipart upload id");

    let sse_part1 = server
        .s3(
            Method::PUT,
            &format!("/{bucket}/{sse_multipart_object}?uploadId={sse_upload_id}&partNumber=1"),
        )
        .body("kms-")
        .send()
        .await
        .expect("upload sse multipart part1 failed");
    assert_eq!(sse_part1.status(), StatusCode::OK);
    let sse_part1_etag = sse_part1
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();

    let sse_part2 = server
        .s3(
            Method::PUT,
            &format!("/{bucket}/{sse_multipart_object}?uploadId={sse_upload_id}&partNumber=2"),
        )
        .body("multipart")
        .send()
        .await
        .expect("upload sse multipart part2 failed");
    assert_eq!(sse_part2.status(), StatusCode::OK);
    let sse_part2_etag = sse_part2
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();

    let sse_complete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"{sse_part1_etag}"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"{sse_part2_etag}"</ETag></Part></CompleteMultipartUpload>"#
    );
    let sse_complete = server
        .s3(
            Method::POST,
            &format!("/{bucket}/{sse_multipart_object}?uploadId={sse_upload_id}"),
        )
        .header(header::CONTENT_TYPE, "application/xml")
        .body(sse_complete_xml)
        .send()
        .await
        .expect("complete sse multipart failed");
    assert_eq!(sse_complete.status(), StatusCode::OK);
    assert_eq!(
        sse_complete
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        sse_complete
            .headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|v| v.to_str().ok()),
        Some("qa-kms-mpu")
    );

    let head_sse_multipart = server
        .s3(Method::HEAD, &format!("/{bucket}/{sse_multipart_object}"))
        .send()
        .await
        .expect("head sse multipart object failed");
    assert_eq!(head_sse_multipart.status(), StatusCode::OK);
    assert_eq!(
        head_sse_multipart
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        head_sse_multipart
            .headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|v| v.to_str().ok()),
        Some("qa-kms-mpu")
    );

    // CopyObject preconditions + metadata/tagging directives.
    let put_copy_source = server
        .s3(Method::PUT, &format!("/{bucket}/{copy_source_object}"))
        .header("x-amz-meta-color", "blue")
        .header("x-amz-tagging", "stage=source")
        .body("copy-source-body")
        .send()
        .await
        .expect("put copy source failed");
    assert_eq!(put_copy_source.status(), StatusCode::OK);
    let source_version_id = put_copy_source
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        !source_version_id.is_empty(),
        "copy source version id missing"
    );

    let head_copy_source = server
        .s3(Method::HEAD, &format!("/{bucket}/{copy_source_object}"))
        .send()
        .await
        .expect("head copy source failed");
    assert_eq!(head_copy_source.status(), StatusCode::OK);
    let source_etag = head_copy_source
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!source_etag.is_empty(), "copy source etag missing");

    let copy_ok = server
        .s3(Method::PUT, &format!("/{bucket}/{copy_target_object}"))
        .header(
            "x-amz-copy-source",
            format!("/{bucket}/{copy_source_object}"),
        )
        .header("x-amz-copy-source-if-match", source_etag.as_str())
        .header("x-amz-metadata-directive", "REPLACE")
        .header("x-amz-tagging-directive", "REPLACE")
        .header("x-amz-meta-color", "red")
        .header("x-amz-tagging", "stage=target")
        .send()
        .await
        .expect("copy with directives failed");
    assert_eq!(copy_ok.status(), StatusCode::OK);
    let copy_ok_xml = copy_ok.text().await.expect("read copy xml failed");
    assert!(
        copy_ok_xml.contains("<CopyObjectResult"),
        "unexpected copy result xml: {copy_ok_xml}"
    );

    let head_copy_target = server
        .s3(Method::HEAD, &format!("/{bucket}/{copy_target_object}"))
        .send()
        .await
        .expect("head copy target failed");
    assert_eq!(head_copy_target.status(), StatusCode::OK);
    assert_eq!(
        head_copy_target
            .headers()
            .get("x-amz-meta-color")
            .and_then(|v| v.to_str().ok()),
        Some("red")
    );
    assert_eq!(
        head_copy_target
            .headers()
            .get("x-amz-tagging-count")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );

    let get_copy_target_tagging = server
        .s3(
            Method::GET,
            &format!("/{bucket}/{copy_target_object}?tagging"),
        )
        .send()
        .await
        .expect("get copy target tagging failed");
    assert_eq!(get_copy_target_tagging.status(), StatusCode::OK);
    let get_copy_target_tagging_xml = get_copy_target_tagging
        .text()
        .await
        .expect("read copy target tagging failed");
    assert!(
        get_copy_target_tagging_xml.contains("<Key>stage</Key><Value>target</Value>"),
        "unexpected copy target tagging xml: {get_copy_target_tagging_xml}"
    );

    let copy_precondition_failed = server
        .s3(
            Method::PUT,
            &format!("/{bucket}/regression/copy-precondition-fail.txt"),
        )
        .header(
            "x-amz-copy-source",
            format!("/{bucket}/{copy_source_object}"),
        )
        .header("x-amz-copy-source-if-match", "\"deadbeef\"")
        .send()
        .await
        .expect("copy precondition failure request failed");
    assert_s3_error(
        copy_precondition_failed,
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
    )
    .await;

    // Version list should contain historical versions.
    let versions = server
        .s3(Method::GET, &format!("/{bucket}?versions"))
        .send()
        .await
        .expect("list versions failed");
    assert_eq!(versions.status(), StatusCode::OK);
    let versions_xml = versions.text().await.expect("failed to read versions body");
    assert!(
        versions_xml.contains("<ListVersionsResult"),
        "unexpected versions XML: {versions_xml}"
    );
    assert!(
        versions_xml.contains(&v1_id),
        "v1 should exist in versions result: {versions_xml}"
    );
    assert!(
        versions_xml.contains(&v2_id),
        "v2 should exist in versions result: {versions_xml}"
    );

    // Delete current object should create a delete marker.
    let delete_latest = server
        .s3(Method::DELETE, &format!("/{bucket}/{object}"))
        .send()
        .await
        .expect("delete latest failed");
    assert_eq!(delete_latest.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        delete_latest
            .headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );

    // Getting without version should now be NoSuchKey.
    let get_deleted_current = server
        .s3(Method::GET, &format!("/{bucket}/{object}"))
        .send()
        .await
        .expect("get deleted current failed");
    assert_s3_error(get_deleted_current, StatusCode::NOT_FOUND, "NoSuchKey").await;

    // But the previous version must still be retrievable.
    let get_version = server
        .s3(
            Method::GET,
            &format!("/{bucket}/{object}?versionId={v2_id}"),
        )
        .send()
        .await
        .expect("get version failed");
    assert_eq!(get_version.status(), StatusCode::OK);
    assert_eq!(
        get_version
            .text()
            .await
            .expect("failed to read version body"),
        "v2-body"
    );

    // Multipart upload complete flow.
    let init_multipart = server
        .s3(Method::POST, &format!("/{bucket}/multipart.txt?uploads"))
        .send()
        .await
        .expect("init multipart failed");
    assert_eq!(init_multipart.status(), StatusCode::OK);
    let init_xml = init_multipart
        .text()
        .await
        .expect("failed to read init multipart body");
    let upload_id = xml_tag(&init_xml, "UploadId").unwrap_or_default();
    assert!(!upload_id.is_empty(), "missing multipart upload id");

    let part1 = server
        .s3(
            Method::PUT,
            &format!("/{bucket}/multipart.txt?uploadId={upload_id}&partNumber=1"),
        )
        .body("hello ")
        .send()
        .await
        .expect("upload part1 failed");
    assert_eq!(part1.status(), StatusCode::OK);
    let part1_etag = part1
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();
    assert!(!part1_etag.is_empty(), "missing etag for part1");

    let part2 = server
        .s3(
            Method::PUT,
            &format!("/{bucket}/multipart.txt?uploadId={upload_id}&partNumber=2"),
        )
        .body("world")
        .send()
        .await
        .expect("upload part2 failed");
    assert_eq!(part2.status(), StatusCode::OK);
    let part2_etag = part2
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();
    assert!(!part2_etag.is_empty(), "missing etag for part2");

    let list_parts = server
        .s3(
            Method::GET,
            &format!("/{bucket}/multipart.txt?uploadId={upload_id}"),
        )
        .send()
        .await
        .expect("list parts failed");
    assert_eq!(list_parts.status(), StatusCode::OK);
    let parts_xml = list_parts.text().await.expect("failed to read parts xml");
    assert!(
        parts_xml.contains("<PartNumber>1</PartNumber>")
            && parts_xml.contains("<PartNumber>2</PartNumber>"),
        "missing uploaded parts in list response: {parts_xml}"
    );

    let complete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"{part1_etag}"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"{part2_etag}"</ETag></Part></CompleteMultipartUpload>"#
    );
    let complete = server
        .s3(
            Method::POST,
            &format!("/{bucket}/multipart.txt?uploadId={upload_id}"),
        )
        .header(header::CONTENT_TYPE, "application/xml")
        .body(complete_xml)
        .send()
        .await
        .expect("complete multipart failed");
    assert_eq!(complete.status(), StatusCode::OK);
    let complete_result = complete
        .text()
        .await
        .expect("failed to read complete multipart body");
    assert!(
        complete_result.contains("<CompleteMultipartUploadResult"),
        "unexpected complete result xml: {complete_result}"
    );

    let get_multipart_object = server
        .s3(Method::GET, &format!("/{bucket}/multipart.txt"))
        .send()
        .await
        .expect("get multipart object failed");
    assert_eq!(get_multipart_object.status(), StatusCode::OK);
    assert_eq!(
        get_multipart_object
            .text()
            .await
            .expect("failed to read multipart object body"),
        "hello world"
    );

    // Multipart error branch: complete request references missing part.
    let init_bad = server
        .s3(
            Method::POST,
            &format!("/{bucket}/multipart-bad.txt?uploads"),
        )
        .send()
        .await
        .expect("init multipart bad failed");
    let init_bad_xml = init_bad
        .text()
        .await
        .expect("failed to read init bad multipart body");
    let bad_upload_id = xml_tag(&init_bad_xml, "UploadId").unwrap_or_default();
    assert!(!bad_upload_id.is_empty(), "missing bad upload id");

    let upload_bad_part = server
        .s3(
            Method::PUT,
            &format!("/{bucket}/multipart-bad.txt?uploadId={bad_upload_id}&partNumber=1"),
        )
        .body("only-part-1")
        .send()
        .await
        .expect("upload bad part failed");
    assert_eq!(upload_bad_part.status(), StatusCode::OK);

    let bad_complete_body = r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload><Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>"#;
    let bad_complete = server
        .s3(
            Method::POST,
            &format!("/{bucket}/multipart-bad.txt?uploadId={bad_upload_id}"),
        )
        .header(header::CONTENT_TYPE, "application/xml")
        .body(bad_complete_body.to_string())
        .send()
        .await
        .expect("bad complete request failed");
    assert_s3_error(bad_complete, StatusCode::BAD_REQUEST, "InvalidPart").await;

    let abort_bad_upload = server
        .s3(
            Method::DELETE,
            &format!("/{bucket}/multipart-bad.txt?uploadId={bad_upload_id}"),
        )
        .send()
        .await
        .expect("abort bad upload failed");
    assert_eq!(abort_bad_upload.status(), StatusCode::NO_CONTENT);

    let abort_not_exist = server
        .s3(
            Method::DELETE,
            &format!("/{bucket}/multipart-missing.txt?uploadId=missing-upload-id"),
        )
        .send()
        .await
        .expect("abort missing upload request failed");
    assert_s3_error(abort_not_exist, StatusCode::NOT_FOUND, "NoSuchUpload").await;

    // DeleteObjects boundaries.
    let empty_delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></Delete>"#;
    let delete_empty = server
        .s3(Method::POST, &format!("/{bucket}?delete"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(empty_delete_xml.to_string())
        .send()
        .await
        .expect("delete empty request failed");
    assert_s3_error(delete_empty, StatusCode::BAD_REQUEST, "MalformedXML").await;

    let mut too_many = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for idx in 0..1001 {
        too_many.push_str(&format!("<Object><Key>too-many-{idx}</Key></Object>"));
    }
    too_many.push_str("</Delete>");
    let delete_too_many = server
        .s3(Method::POST, &format!("/{bucket}?delete"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(too_many)
        .send()
        .await
        .expect("delete too-many request failed");
    assert_s3_error(delete_too_many, StatusCode::BAD_REQUEST, "MalformedXML").await;

    let delete_mixed_xml = r#"<?xml version="1.0" encoding="UTF-8"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Object><Key></Key></Object><Object><Key>multipart.txt</Key></Object></Delete>"#;
    let delete_mixed = server
        .s3(Method::POST, &format!("/{bucket}?delete"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(delete_mixed_xml.to_string())
        .send()
        .await
        .expect("delete mixed request failed");
    assert_eq!(delete_mixed.status(), StatusCode::OK);
    let delete_mixed_result = delete_mixed
        .text()
        .await
        .expect("failed to read delete mixed result");
    assert!(
        delete_mixed_result.contains("<Error>")
            && delete_mixed_result.contains("<Code>InvalidArgument</Code>")
            && delete_mixed_result.contains("<Deleted>"),
        "unexpected delete mixed result: {delete_mixed_result}"
    );

    // Retention/legal-hold malformed XML behavior.
    let put_lock_object = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}"))
        .body("lock-body")
        .send()
        .await
        .expect("put lock object failed");
    assert_eq!(put_lock_object.status(), StatusCode::OK);

    let bad_retention = r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockRetention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>INVALID</Mode><RetainUntilDate>2035-01-01T00:00:00Z</RetainUntilDate></ObjectLockRetention>"#;
    let put_bad_retention = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}?retention"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(bad_retention.to_string())
        .send()
        .await
        .expect("put bad retention failed");
    assert_s3_error(put_bad_retention, StatusCode::BAD_REQUEST, "MalformedXML").await;

    let bad_legal_hold = r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>INVALID</Status></ObjectLockLegalHold>"#;
    let put_bad_legal_hold = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}?legal-hold"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(bad_legal_hold.to_string())
        .send()
        .await
        .expect("put bad legal hold failed");
    assert_s3_error(put_bad_legal_hold, StatusCode::BAD_REQUEST, "MalformedXML").await;

    let future_retention = r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockRetention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>GOVERNANCE</Mode><RetainUntilDate>2035-01-01T00:00:00Z</RetainUntilDate></ObjectLockRetention>"#;
    let put_retention = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}?retention"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(future_retention.to_string())
        .send()
        .await
        .expect("put retention failed");
    assert_eq!(put_retention.status(), StatusCode::OK);

    let legal_hold_on = r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></ObjectLockLegalHold>"#;
    let put_legal_hold_on = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}?legal-hold"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(legal_hold_on.to_string())
        .send()
        .await
        .expect("put legal hold on failed");
    assert_eq!(put_legal_hold_on.status(), StatusCode::OK);

    let delete_legal_hold = server
        .s3(Method::DELETE, &format!("/{bucket}/{lock_object}"))
        .send()
        .await
        .expect("delete legal hold object failed");
    assert_s3_error_message(
        delete_legal_hold,
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "访问被拒绝 / Object is under legal hold",
    )
    .await;

    let overwrite_legal_hold = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}"))
        .body("lock-body-overwrite")
        .send()
        .await
        .expect("overwrite legal hold object failed");
    assert_s3_error_message(
        overwrite_legal_hold,
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "访问被拒绝 / Object is under legal hold",
    )
    .await;

    let legal_hold_off = r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>OFF</Status></ObjectLockLegalHold>"#;
    let put_legal_hold_off = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}?legal-hold"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(legal_hold_off.to_string())
        .send()
        .await
        .expect("put legal hold off failed");
    assert_eq!(put_legal_hold_off.status(), StatusCode::OK);

    let delete_retention = server
        .s3(Method::DELETE, &format!("/{bucket}/{lock_object}"))
        .send()
        .await
        .expect("delete retention object failed");
    assert_s3_error_message(
        delete_retention,
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "访问被拒绝 / Object retention period has not expired",
    )
    .await;

    let overwrite_retention = server
        .s3(Method::PUT, &format!("/{bucket}/{lock_object}"))
        .body("lock-body-overwrite")
        .send()
        .await
        .expect("overwrite retention object failed");
    assert_s3_error_message(
        overwrite_retention,
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "访问被拒绝 / Object retention period has not expired",
    )
    .await;

    // Bucket delete should fail when bucket is not empty.
    let delete_non_empty_bucket = server
        .s3(Method::DELETE, &format!("/{bucket}"))
        .send()
        .await
        .expect("delete non-empty bucket failed");
    assert_s3_error(
        delete_non_empty_bucket,
        StatusCode::CONFLICT,
        "BucketNotEmpty",
    )
    .await;

    // Signature boundary: malformed/invalid signed requests should map to S3 errors.
    let sig_mismatch = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(
            header::AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=rustioadmin/20260305/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef",
        )
        .header("x-amz-date", "20260305T010203Z")
        .header(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .send()
        .await
        .expect("signature mismatch request failed");
    assert_s3_error(sig_mismatch, StatusCode::FORBIDDEN, "SignatureDoesNotMatch").await;

    let invalid_access_key = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(
            header::AUTHORIZATION,
            "AWS invalid-access-key:any-signature",
        )
        .send()
        .await
        .expect("invalid access key request failed");
    assert_s3_error(
        invalid_access_key,
        StatusCode::FORBIDDEN,
        "InvalidAccessKeyId",
    )
    .await;

    // STS expired token should return ExpiredToken.
    let bootstrap_sts = {
        let sessions = server.state.sts_sessions.read().await;
        sessions
            .first()
            .cloned()
            .expect("bootstrap sts session missing")
    };
    let active_basic = format!(
        "Basic {}",
        BASE64.encode(format!(
            "{}:{}",
            bootstrap_sts.access_key, bootstrap_sts.secret_key
        ))
    );
    let sts_missing_token = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(header::AUTHORIZATION, active_basic.clone())
        .send()
        .await
        .expect("sts missing token request failed");
    assert_s3_error(sts_missing_token, StatusCode::FORBIDDEN, "AccessDenied").await;

    let sts_invalid_token = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(header::AUTHORIZATION, active_basic.clone())
        .header("x-amz-security-token", "invalid-security-token")
        .send()
        .await
        .expect("sts invalid token request failed");
    assert_s3_error_message(
        sts_invalid_token,
        StatusCode::FORBIDDEN,
        "InvalidToken",
        "令牌无效 / The security token included in the request is invalid",
    )
    .await;

    let sts_invalid_token_query = server
        .client
        .get(format!(
            "{}/{bucket}?list-type=2&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}%2F20260305%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260305T010203Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Security-Token=invalid-security-token&X-Amz-Signature=deadbeef",
            server.base_url, bootstrap_sts.access_key
        ))
        .send()
        .await
        .expect("sts invalid token query auth request failed");
    assert_s3_error(
        sts_invalid_token_query,
        StatusCode::FORBIDDEN,
        "InvalidToken",
    )
    .await;

    {
        let mut sessions = server.state.sts_sessions.write().await;
        if let Some(session) = sessions
            .iter_mut()
            .find(|item| item.session_id == bootstrap_sts.session_id)
        {
            session.expires_at = Utc::now() - ChronoDuration::minutes(1);
        }
    }
    let expired_sts = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(header::AUTHORIZATION, active_basic)
        .header("x-amz-security-token", bootstrap_sts.session_token.clone())
        .send()
        .await
        .expect("expired sts request failed");
    assert_s3_error(expired_sts, StatusCode::FORBIDDEN, "ExpiredToken").await;

    let expired_sts_query = server
        .client
        .get(format!(
            "{}/{bucket}?list-type=2&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}%2F20260305%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260305T010203Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef",
            server.base_url, bootstrap_sts.access_key
        ))
        .send()
        .await
        .expect("expired sts query auth request failed");
    assert_s3_error(expired_sts_query, StatusCode::FORBIDDEN, "ExpiredToken").await;

    let expired_sts_sigv4 = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential={}/20260305/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef",
                bootstrap_sts.access_key
            ),
        )
        .header("x-amz-date", "20260305T010203Z")
        .header(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .header("x-amz-security-token", bootstrap_sts.session_token)
        .send()
        .await
        .expect("expired sts sigv4 request failed");
    assert_s3_error(expired_sts_sigv4, StatusCode::FORBIDDEN, "ExpiredToken").await;

    // External KMS strict mode: invalid endpoint should fail SSE-KMS request instead of local fallback.
    std::env::set_var("RUSTIO_KMS_EXTERNAL_ENABLED", "true");
    std::env::set_var("RUSTIO_KMS_PROVIDER", "generic");
    let admin_token = server.admin_token().await;
    let update_security = server
        .client
        .patch(format!("{}/api/v1/security/config", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"kms_endpoint":"invalid-kms-endpoint","sse_mode":"SSE-KMS"}"#)
        .send()
        .await
        .expect("security update request failed");
    assert_eq!(
        update_security.status(),
        StatusCode::OK,
        "security update failed"
    );
    let kms_external_object = "regression/kms-external-strict.txt";
    let put_kms_external = server
        .s3(Method::PUT, &format!("/{bucket}/{kms_external_object}"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "qa-kms-external",
        )
        .body("kms-external-body")
        .send()
        .await
        .expect("put kms external strict object failed");
    assert_s3_error(
        put_kms_external,
        StatusCode::SERVICE_UNAVAILABLE,
        "KMSNotConfigured",
    )
    .await;

    let update_security_unavailable = server
        .client
        .patch(format!("{}/api/v1/security/config", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"kms_endpoint":"http://127.0.0.1:9","sse_mode":"SSE-KMS"}"#)
        .send()
        .await
        .expect("security update unavailable endpoint request failed");
    assert_eq!(
        update_security_unavailable.status(),
        StatusCode::OK,
        "security update unavailable endpoint failed"
    );
    let kms_unavailable_object = "regression/kms-unavailable.txt";
    let put_kms_unavailable = server
        .s3(Method::PUT, &format!("/{bucket}/{kms_unavailable_object}"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "qa-kms-unavailable",
        )
        .body("kms-unavailable-body")
        .send()
        .await
        .expect("put kms unavailable object failed");
    assert_s3_error(
        put_kms_unavailable,
        StatusCode::SERVICE_UNAVAILABLE,
        "KMSUnavailable",
    )
    .await;
    std::env::remove_var("RUSTIO_KMS_EXTERNAL_ENABLED");
    std::env::remove_var("RUSTIO_KMS_PROVIDER");

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_advanced_object_apis_regression() {
    let server = TestServer::spawn().await;
    let bucket = "advanced-object-apis";
    let attrs_key = "reports/attributes.csv";
    let csv_select_key = "reports/select.csv";
    let json_select_key = "reports/select.jsonl";

    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let attrs_body = "quarter,owner,total\nq1,alice,12\n".to_string();
    let put_attrs = server
        .s3(Method::PUT, &format!("/{bucket}/{attrs_key}"))
        .body(attrs_body.clone())
        .send()
        .await
        .expect("put attributes object failed");
    assert_eq!(put_attrs.status(), StatusCode::OK);
    let attrs_etag = put_attrs
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();

    let get_attrs = server
        .s3(Method::GET, &format!("/{bucket}/{attrs_key}?attributes"))
        .header(
            "x-amz-object-attributes",
            "ETag,ObjectSize,StorageClass,Checksum,ObjectParts",
        )
        .send()
        .await
        .expect("get object attributes request failed");
    assert_eq!(get_attrs.status(), StatusCode::OK);
    let attrs_xml = get_attrs
        .text()
        .await
        .expect("get object attributes xml should be readable");
    assert!(
        attrs_xml.contains(&format!("&quot;{attrs_etag}&quot;")),
        "get object attributes should include etag: {attrs_xml}"
    );
    assert_eq!(
        xml_tag(&attrs_xml, "ObjectSize"),
        Some(attrs_body.len().to_string())
    );
    assert_eq!(
        xml_tag(&attrs_xml, "StorageClass"),
        Some("STANDARD".to_string())
    );
    assert_eq!(xml_tag(&attrs_xml, "PartsCount"), Some("1".to_string()));
    assert!(
        xml_tag(&attrs_xml, "ChecksumSHA256")
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "get object attributes should include checksum: {attrs_xml}"
    );

    let csv_body = "alice,team-a,9\nbob,team-b,5\ncarol,team-a,7\n";
    let put_csv = server
        .s3(Method::PUT, &format!("/{bucket}/{csv_select_key}"))
        .body(csv_body.to_string())
        .send()
        .await
        .expect("put csv select object failed");
    assert_eq!(put_csv.status(), StatusCode::OK);

    let csv_select_request = r#"<?xml version="1.0" encoding="UTF-8"?>
<SelectObjectContentRequest>
  <Expression>SELECT s._1, s._3 FROM S3Object s WHERE s._2 = 'team-a'</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization>
    <CSV>
      <FileHeaderInfo>NONE</FileHeaderInfo>
    </CSV>
    <CompressionType>NONE</CompressionType>
  </InputSerialization>
  <OutputSerialization>
    <CSV />
  </OutputSerialization>
</SelectObjectContentRequest>"#;

    let csv_select = server
        .s3(
            Method::POST,
            &format!("/{bucket}/{csv_select_key}?select&select-type=2"),
        )
        .header(header::CONTENT_TYPE, "application/xml")
        .body(csv_select_request.to_string())
        .send()
        .await
        .expect("csv select object content failed");
    assert_eq!(csv_select.status(), StatusCode::OK);
    assert_eq!(
        csv_select
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.amazon.eventstream")
    );
    let csv_events = decode_event_stream(
        &csv_select
            .bytes()
            .await
            .expect("csv select event stream should be readable"),
    );
    let csv_records = csv_events
        .iter()
        .find(|message| message.event_type == "Records")
        .expect("csv select should include records event");
    assert_eq!(
        String::from_utf8_lossy(&csv_records.payload),
        "alice,9\ncarol,7\n"
    );
    assert!(
        csv_events
            .iter()
            .any(|message| message.event_type == "Stats"),
        "csv select should include stats event"
    );
    assert!(
        csv_events.iter().any(|message| message.event_type == "End"),
        "csv select should include end event"
    );

    let json_body = r#"{"name":"alice","team":"a","score":9}
{"name":"bob","team":"b","score":5}
{"name":"carol","team":"a","score":7}
"#;
    let put_json = server
        .s3(Method::PUT, &format!("/{bucket}/{json_select_key}"))
        .body(json_body.to_string())
        .send()
        .await
        .expect("put json select object failed");
    assert_eq!(put_json.status(), StatusCode::OK);

    let json_select_request = r#"<?xml version="1.0" encoding="UTF-8"?>
<SelectObjectContentRequest>
  <Expression>SELECT s.name, s.score FROM S3Object s WHERE s.team = 'a'</Expression>
  <ExpressionType>SQL</ExpressionType>
  <InputSerialization>
    <JSON>
      <Type>LINES</Type>
    </JSON>
    <CompressionType>NONE</CompressionType>
  </InputSerialization>
  <OutputSerialization>
    <JSON />
  </OutputSerialization>
</SelectObjectContentRequest>"#;

    let json_select = server
        .s3(
            Method::POST,
            &format!("/{bucket}/{json_select_key}?select&select-type=2"),
        )
        .header(header::CONTENT_TYPE, "application/xml")
        .body(json_select_request.to_string())
        .send()
        .await
        .expect("json select object content failed");
    assert_eq!(json_select.status(), StatusCode::OK);
    let json_events = decode_event_stream(
        &json_select
            .bytes()
            .await
            .expect("json select event stream should be readable"),
    );
    let json_records = json_events
        .iter()
        .find(|message| message.event_type == "Records")
        .expect("json select should include records event");
    assert_eq!(
        String::from_utf8_lossy(&json_records.payload),
        "{\"name\":\"alice\",\"score\":9}\n{\"name\":\"carol\",\"score\":7}\n"
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_sse_customer_regression() {
    let server = TestServer::spawn().await;
    let bucket = "sse-c-regression";
    let source_key = "secret/source.txt";
    let copied_key = "secret/copied.txt";
    let customer_key = *b"0123456789abcdef0123456789abcdef";
    let destination_key = *b"fedcba9876543210fedcba9876543210";
    let (customer_key_b64, customer_key_md5) = sse_customer_material(&customer_key);
    let (destination_key_b64, destination_key_md5) = sse_customer_material(&destination_key);

    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create sse-c bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let put_sse_customer = server
        .s3(Method::PUT, &format!("/{bucket}/{source_key}"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-server-side-encryption-customer-key",
            customer_key_b64.as_str(),
        )
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            customer_key_md5.as_str(),
        )
        .body("sse-c-body")
        .send()
        .await
        .expect("put sse-c object failed");
    assert_eq!(put_sse_customer.status(), StatusCode::OK);
    assert_eq!(
        put_sse_customer
            .headers()
            .get("x-amz-server-side-encryption-customer-algorithm")
            .and_then(|value| value.to_str().ok()),
        Some("AES256")
    );
    assert_eq!(
        put_sse_customer
            .headers()
            .get("x-amz-server-side-encryption-customer-key-md5")
            .and_then(|value| value.to_str().ok()),
        Some(customer_key_md5.as_str())
    );
    assert!(
        put_sse_customer
            .headers()
            .get("x-amz-server-side-encryption")
            .is_none(),
        "sse-c response must not expose x-amz-server-side-encryption"
    );

    let get_missing_headers = server
        .s3(Method::GET, &format!("/{bucket}/{source_key}"))
        .send()
        .await
        .expect("get sse-c object without headers failed");
    assert_s3_error(
        get_missing_headers,
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
    )
    .await;

    let get_wrong_headers = server
        .s3(Method::GET, &format!("/{bucket}/{source_key}"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-server-side-encryption-customer-key",
            destination_key_b64.as_str(),
        )
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            destination_key_md5.as_str(),
        )
        .send()
        .await
        .expect("get sse-c object with wrong headers failed");
    assert_s3_error(get_wrong_headers, StatusCode::BAD_REQUEST, "InvalidRequest").await;

    let head_sse_customer = server
        .s3(Method::HEAD, &format!("/{bucket}/{source_key}"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-server-side-encryption-customer-key",
            customer_key_b64.as_str(),
        )
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            customer_key_md5.as_str(),
        )
        .send()
        .await
        .expect("head sse-c object failed");
    assert_eq!(head_sse_customer.status(), StatusCode::OK);
    assert_eq!(
        head_sse_customer
            .headers()
            .get("x-amz-server-side-encryption-customer-algorithm")
            .and_then(|value| value.to_str().ok()),
        Some("AES256")
    );
    assert_eq!(
        head_sse_customer
            .headers()
            .get("x-amz-server-side-encryption-customer-key-md5")
            .and_then(|value| value.to_str().ok()),
        Some(customer_key_md5.as_str())
    );

    let get_sse_customer = server
        .s3(Method::GET, &format!("/{bucket}/{source_key}"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-server-side-encryption-customer-key",
            customer_key_b64.as_str(),
        )
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            customer_key_md5.as_str(),
        )
        .send()
        .await
        .expect("get sse-c object failed");
    assert_eq!(get_sse_customer.status(), StatusCode::OK);
    assert_eq!(
        get_sse_customer
            .headers()
            .get("x-amz-server-side-encryption-customer-key-md5")
            .and_then(|value| value.to_str().ok()),
        Some(customer_key_md5.as_str())
    );
    assert_eq!(
        get_sse_customer
            .text()
            .await
            .expect("read sse-c object body failed"),
        "sse-c-body"
    );

    let copy_sse_customer = server
        .s3(Method::PUT, &format!("/{bucket}/{copied_key}"))
        .header("x-amz-copy-source", format!("/{bucket}/{source_key}"))
        .header(
            "x-amz-copy-source-server-side-encryption-customer-algorithm",
            "AES256",
        )
        .header(
            "x-amz-copy-source-server-side-encryption-customer-key",
            customer_key_b64.as_str(),
        )
        .header(
            "x-amz-copy-source-server-side-encryption-customer-key-md5",
            customer_key_md5.as_str(),
        )
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-server-side-encryption-customer-key",
            destination_key_b64.as_str(),
        )
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            destination_key_md5.as_str(),
        )
        .send()
        .await
        .expect("copy sse-c object failed");
    assert_eq!(copy_sse_customer.status(), StatusCode::OK);
    assert_eq!(
        copy_sse_customer
            .headers()
            .get("x-amz-server-side-encryption-customer-key-md5")
            .and_then(|value| value.to_str().ok()),
        Some(destination_key_md5.as_str())
    );

    let get_copied_sse_customer = server
        .s3(Method::GET, &format!("/{bucket}/{copied_key}"))
        .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .header(
            "x-amz-server-side-encryption-customer-key",
            destination_key_b64.as_str(),
        )
        .header(
            "x-amz-server-side-encryption-customer-key-md5",
            destination_key_md5.as_str(),
        )
        .send()
        .await
        .expect("get copied sse-c object failed");
    assert_eq!(get_copied_sse_customer.status(), StatusCode::OK);
    assert_eq!(
        get_copied_sse_customer
            .text()
            .await
            .expect("read copied sse-c body failed"),
        "sse-c-body"
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_lifecycle_tiering_regression() {
    std::env::set_var("RUSTIO_LIFECYCLE_INTERVAL_MS", "100");
    std::env::set_var("RUSTIO_ASYNC_JOB_WORKER_INTERVAL_MS", "100");
    let server = TestServer::spawn().await;
    let admin_token = server.admin_token().await;

    let remote_tier_root = server.data_dir.join("remote-tier-warm");
    let remote_tier_resp = server
        .client
        .put(format!("{}/api/v1/storage/tiers", server.base_url))
        .bearer_auth(&admin_token)
        .json(&json!([{
            "name": "WARM",
            "endpoint": remote_tier_root.to_string_lossy().to_string(),
            "prefix": "tiered",
            "storage_class": "WARM",
            "enabled": true
        }]))
        .send()
        .await
        .expect("remote tier update request failed");
    assert_eq!(remote_tier_resp.status(), StatusCode::OK);

    let current_bucket = "sdk-tier-current";
    let current_key = "archive/current.txt";
    let create_current = server
        .client
        .post(format!("{}/api/v1/buckets", server.base_url))
        .bearer_auth(&admin_token)
        .json(&json!({
            "name": current_bucket,
            "tenant_id": "default",
            "versioning": false,
            "object_lock": false,
            "ilm_policy": null,
            "replication_policy": null
        }))
        .send()
        .await
        .expect("create current bucket failed");
    assert_eq!(create_current.status(), StatusCode::OK);

    let current_lifecycle = server
        .client
        .put(format!(
            "{}/api/v1/buckets/{current_bucket}/lifecycle",
            server.base_url
        ))
        .bearer_auth(&admin_token)
        .json(&json!([{
            "id": "tier-current",
            "prefix": "archive/",
            "status": "Enabled",
            "expiration_days": null,
            "noncurrent_expiration_days": null,
            "transition_days": 1,
            "transition_tier": "WARM",
            "noncurrent_transition_days": null,
            "noncurrent_transition_tier": null
        }]))
        .send()
        .await
        .expect("current lifecycle update failed");
    assert_eq!(current_lifecycle.status(), StatusCode::OK);

    let put_current = server
        .client
        .put(format!(
            "{}/api/v1/buckets/{current_bucket}/objects/{current_key}",
            server.base_url
        ))
        .bearer_auth(&admin_token)
        .body("tier-current-payload")
        .send()
        .await
        .expect("put current object failed");
    assert_eq!(put_current.status(), StatusCode::OK);

    let current_meta_path = server
        .data_dir
        .join(current_bucket)
        .join(".rustio_meta")
        .join(format!("{current_key}.json"));
    let current_hot_path = server.data_dir.join(current_bucket).join(current_key);
    backdate_created_at(&current_meta_path, 2);

    wait_for_condition(
        || {
            let Ok(bytes) = std::fs::read(&current_meta_path) else {
                return false;
            };
            let Ok(meta) = serde_json::from_slice::<Value>(&bytes) else {
                return false;
            };
            meta.pointer("/remote_tier/tier").and_then(Value::as_str) == Some("WARM")
                && meta.pointer("/storage_class").and_then(Value::as_str) == Some("WARM")
        },
        "current object did not transition to remote tier metadata",
    )
    .await;
    let current_version_id = serde_json::from_slice::<Value>(
        &std::fs::read(&current_meta_path).expect("failed to read transitioned current meta"),
    )
    .expect("failed to decode transitioned current meta")
    .pointer("/version_id")
    .and_then(Value::as_str)
    .unwrap_or_default()
    .to_string();
    let current_remote_path = remote_tier_root
        .join(current_bucket)
        .join("tiered")
        .join(sha256_hex(current_key))
        .join(format!("{current_version_id}.bin"));
    wait_for_condition(
        || current_remote_path.exists() && !current_hot_path.exists(),
        "current object did not transition to remote tier",
    )
    .await;

    let get_current = server
        .s3(Method::GET, &format!("/{current_bucket}/{current_key}"))
        .send()
        .await
        .expect("get transitioned current object failed");
    assert_eq!(get_current.status(), StatusCode::OK);
    assert_eq!(
        get_current
            .headers()
            .get("x-amz-storage-class")
            .and_then(|value| value.to_str().ok()),
        Some("WARM")
    );
    assert_eq!(
        get_current
            .text()
            .await
            .expect("failed to read transitioned current payload"),
        "tier-current-payload"
    );

    let head_current = server
        .s3(Method::HEAD, &format!("/{current_bucket}/{current_key}"))
        .send()
        .await
        .expect("head transitioned current object failed");
    assert_eq!(head_current.status(), StatusCode::OK);
    assert_eq!(
        head_current
            .headers()
            .get("x-amz-storage-class")
            .and_then(|value| value.to_str().ok()),
        Some("WARM")
    );
    assert!(
        head_current.headers().get("x-amz-restore").is_none(),
        "unexpected restore header before restore request",
    );

    let restore_current = server
        .s3(Method::POST, &format!("/{current_bucket}/{current_key}?restore"))
        .header(header::CONTENT_TYPE, "application/xml")
        .body(
            r#"<?xml version="1.0" encoding="UTF-8"?><RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>3</Days><GlacierJobParameters><Tier>Standard</Tier></GlacierJobParameters><Description>warm current object</Description></RestoreRequest>"#,
        )
        .send()
        .await
        .expect("restore transitioned current object failed");
    assert_eq!(restore_current.status(), StatusCode::ACCEPTED);
    assert_eq!(
        restore_current
            .headers()
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok()),
        Some(current_version_id.as_str())
    );
    wait_for_condition(
        || current_hot_path.exists(),
        "restored current object hot payload missing",
    )
    .await;

    let head_current_restored = server
        .s3(Method::HEAD, &format!("/{current_bucket}/{current_key}"))
        .send()
        .await
        .expect("head restored current object failed");
    assert_eq!(head_current_restored.status(), StatusCode::OK);
    let current_restore_header = head_current_restored
        .headers()
        .get("x-amz-restore")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        current_restore_header.contains(r#"ongoing-request="false""#)
            && current_restore_header.contains("expiry-date="),
        "unexpected current restore header: {current_restore_header}",
    );

    let list_current = server
        .s3(Method::GET, &format!("/{current_bucket}?list-type=2"))
        .send()
        .await
        .expect("list transitioned current bucket failed");
    assert_eq!(list_current.status(), StatusCode::OK);
    let list_current_body = list_current
        .text()
        .await
        .expect("failed to read current list body");
    assert!(
        list_current_body.contains("<StorageClass>WARM</StorageClass>"),
        "unexpected current list body: {list_current_body}"
    );

    let noncurrent_bucket = "sdk-tier-noncurrent";
    let noncurrent_key = "archive/noncurrent.txt";
    let create_noncurrent = server
        .client
        .post(format!("{}/api/v1/buckets", server.base_url))
        .bearer_auth(&admin_token)
        .json(&json!({
            "name": noncurrent_bucket,
            "tenant_id": "default",
            "versioning": true,
            "object_lock": false,
            "ilm_policy": null,
            "replication_policy": null
        }))
        .send()
        .await
        .expect("create noncurrent bucket failed");
    assert_eq!(create_noncurrent.status(), StatusCode::OK);

    let noncurrent_lifecycle = server
        .client
        .put(format!(
            "{}/api/v1/buckets/{noncurrent_bucket}/lifecycle",
            server.base_url
        ))
        .bearer_auth(&admin_token)
        .json(&json!([{
            "id": "tier-noncurrent",
            "prefix": "archive/",
            "status": "Enabled",
            "expiration_days": null,
            "noncurrent_expiration_days": null,
            "transition_days": null,
            "transition_tier": null,
            "noncurrent_transition_days": 1,
            "noncurrent_transition_tier": "WARM"
        }]))
        .send()
        .await
        .expect("noncurrent lifecycle update failed");
    assert_eq!(noncurrent_lifecycle.status(), StatusCode::OK);

    for body in ["tier-version-one", "tier-version-two"] {
        let put_noncurrent = server
            .client
            .put(format!(
                "{}/api/v1/buckets/{noncurrent_bucket}/objects/{noncurrent_key}",
                server.base_url
            ))
            .bearer_auth(&admin_token)
            .body(body)
            .send()
            .await
            .expect("put noncurrent object failed");
        assert_eq!(put_noncurrent.status(), StatusCode::OK);
    }

    let versions_resp = server
        .client
        .get(format!(
            "{}/api/v1/buckets/{noncurrent_bucket}/objects/versions",
            server.base_url
        ))
        .bearer_auth(&admin_token)
        .query(&[("key", noncurrent_key)])
        .send()
        .await
        .expect("list admin versions failed");
    assert_eq!(versions_resp.status(), StatusCode::OK);
    let versions_body = versions_resp
        .json::<Value>()
        .await
        .expect("failed to decode admin versions");
    let archived_version_id = versions_body["data"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| !item["is_latest"].as_bool().unwrap_or(false))
        })
        .and_then(|item| item["version_id"].as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        !archived_version_id.is_empty(),
        "expected archived version id in {versions_body}"
    );

    let archived_meta_path = server
        .data_dir
        .join(noncurrent_bucket)
        .join(".rustio_versions")
        .join(sha256_hex(noncurrent_key))
        .join(format!("{archived_version_id}.json"));
    let archived_local_path = server
        .data_dir
        .join(noncurrent_bucket)
        .join(".rustio_versions")
        .join(sha256_hex(noncurrent_key))
        .join(format!("{archived_version_id}.bin"));
    backdate_created_at(&archived_meta_path, 2);

    wait_for_condition(
        || {
            let Ok(bytes) = std::fs::read(&archived_meta_path) else {
                return false;
            };
            let Ok(meta) = serde_json::from_slice::<Value>(&bytes) else {
                return false;
            };
            meta.pointer("/remote_tier/tier").and_then(Value::as_str) == Some("WARM")
                && meta.pointer("/storage_class").and_then(Value::as_str) == Some("WARM")
        },
        "noncurrent object did not transition to remote tier",
    )
    .await;

    let noncurrent_remote_path = remote_tier_root
        .join(noncurrent_bucket)
        .join("tiered")
        .join(sha256_hex(noncurrent_key))
        .join(format!("{archived_version_id}.bin"));
    wait_for_condition(
        || noncurrent_remote_path.exists() && !archived_local_path.exists(),
        "noncurrent remote tier payload missing",
    )
    .await;

    let get_noncurrent = server
        .s3(
            Method::GET,
            &format!("/{noncurrent_bucket}/{noncurrent_key}?versionId={archived_version_id}"),
        )
        .send()
        .await
        .expect("get transitioned noncurrent object failed");
    assert_eq!(get_noncurrent.status(), StatusCode::OK);
    assert_eq!(
        get_noncurrent
            .headers()
            .get("x-amz-storage-class")
            .and_then(|value| value.to_str().ok()),
        Some("WARM")
    );
    assert!(
        get_noncurrent.headers().get("x-amz-restore").is_none(),
        "unexpected noncurrent restore header before restore request",
    );
    assert_eq!(
        get_noncurrent
            .text()
            .await
            .expect("failed to read transitioned noncurrent payload"),
        "tier-version-one"
    );

    let restore_noncurrent = server
        .s3(
            Method::POST,
            &format!(
                "/{noncurrent_bucket}/{noncurrent_key}?restore&versionId={archived_version_id}"
            ),
        )
        .header(header::CONTENT_TYPE, "application/xml")
        .body(
            r#"<?xml version="1.0" encoding="UTF-8"?><RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>5</Days><Tier>Bulk</Tier><Description>warm archived version</Description></RestoreRequest>"#,
        )
        .send()
        .await
        .expect("restore transitioned noncurrent object failed");
    assert_eq!(restore_noncurrent.status(), StatusCode::ACCEPTED);
    assert_eq!(
        restore_noncurrent
            .headers()
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok()),
        Some(archived_version_id.as_str())
    );
    wait_for_condition(
        || archived_local_path.exists(),
        "restored noncurrent object hot payload missing",
    )
    .await;

    let head_noncurrent_restored = server
        .s3(
            Method::HEAD,
            &format!("/{noncurrent_bucket}/{noncurrent_key}?versionId={archived_version_id}"),
        )
        .send()
        .await
        .expect("head restored noncurrent object failed");
    assert_eq!(head_noncurrent_restored.status(), StatusCode::OK);
    let noncurrent_restore_header = head_noncurrent_restored
        .headers()
        .get("x-amz-restore")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        noncurrent_restore_header.contains(r#"ongoing-request="false""#)
            && noncurrent_restore_header.contains("expiry-date="),
        "unexpected noncurrent restore header: {noncurrent_restore_header}",
    );

    let list_versions = server
        .s3(Method::GET, &format!("/{noncurrent_bucket}?versions"))
        .send()
        .await
        .expect("list versions request failed");
    assert_eq!(list_versions.status(), StatusCode::OK);
    let list_versions_body = list_versions
        .text()
        .await
        .expect("failed to read versions body");
    assert!(
        list_versions_body.contains("<StorageClass>WARM</StorageClass>"),
        "unexpected list versions body: {list_versions_body}"
    );

    let inventory_resp = server
        .client
        .get(format!("{}/api/v1/storage/inventory", server.base_url))
        .bearer_auth(&admin_token)
        .query(&[("remote_only", "true")])
        .send()
        .await
        .expect("storage inventory request failed");
    assert_eq!(inventory_resp.status(), StatusCode::OK);
    let inventory_body = inventory_resp
        .json::<Value>()
        .await
        .expect("failed to decode storage inventory response");
    let inventory_items = inventory_body["data"]
        .as_array()
        .expect("inventory response should be array");
    let current_inventory = inventory_items
        .iter()
        .find(|item| {
            item["bucket"].as_str() == Some(current_bucket)
                && item["object_key"].as_str() == Some(current_key)
                && item["is_current"].as_bool() == Some(true)
        })
        .expect("current restored inventory entry should exist");
    assert_eq!(current_inventory["remote_tier"].as_str(), Some("WARM"));
    assert_eq!(current_inventory["restored"].as_bool(), Some(true));
    assert!(current_inventory["restore_expiry"].as_str().is_some());

    let archived_inventory = inventory_items
        .iter()
        .find(|item| {
            item["bucket"].as_str() == Some(noncurrent_bucket)
                && item["object_key"].as_str() == Some(noncurrent_key)
                && item["version_id"].as_str() == Some(archived_version_id.as_str())
                && item["is_current"].as_bool() == Some(false)
        })
        .expect("archived restored inventory entry should exist");
    assert_eq!(archived_inventory["remote_tier"].as_str(), Some("WARM"));
    assert_eq!(archived_inventory["restored"].as_bool(), Some(true));
    assert!(archived_inventory["restore_expiry"].as_str().is_some());

    let inventory_noncurrent_only = server
        .client
        .get(format!("{}/api/v1/storage/inventory", server.base_url))
        .bearer_auth(&admin_token)
        .query(&[
            ("bucket", noncurrent_bucket),
            ("noncurrent_only", "true"),
            ("remote_only", "true"),
            ("limit", "1"),
        ])
        .send()
        .await
        .expect("filtered storage inventory request failed");
    assert_eq!(inventory_noncurrent_only.status(), StatusCode::OK);
    let inventory_noncurrent_only_body = inventory_noncurrent_only
        .json::<Value>()
        .await
        .expect("failed to decode filtered inventory response");
    let filtered_items = inventory_noncurrent_only_body["data"]
        .as_array()
        .expect("filtered inventory should be array");
    assert_eq!(filtered_items.len(), 1);
    assert_eq!(
        filtered_items[0]["version_id"].as_str(),
        Some(archived_version_id.as_str())
    );
    assert_eq!(filtered_items[0]["is_current"].as_bool(), Some(false));

    server.stop().await;
    std::env::remove_var("RUSTIO_LIFECYCLE_INTERVAL_MS");
    std::env::remove_var("RUSTIO_ASYNC_JOB_WORKER_INTERVAL_MS");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_external_kms_generic_vault_and_kes_success_regression() {
    let server = TestServer::spawn().await;
    let kms = MockKmsServer::spawn().await;
    let bucket = "kms-success-bucket";
    let generic_object = "regression/kms-generic-success.txt";
    let vault_object = "regression/kms-vault-success.txt";
    let kes_object = "regression/kms-kes-success.txt";

    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    std::env::set_var("RUSTIO_KMS_EXTERNAL_ENABLED", "true");
    std::env::set_var("RUSTIO_KMS_TOKEN", "kms-shared-token");
    std::env::set_var("RUSTIO_KMS_PROVIDER", "generic");

    let admin_token = server.admin_token().await;
    let update_security = server
        .client
        .patch(format!("{}/api/v1/security/config", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "kms_endpoint": kms.base_url.clone(),
                "sse_mode": "SSE-KMS"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("security update request failed");
    assert_eq!(
        update_security.status(),
        StatusCode::OK,
        "security update failed"
    );

    let put_generic = server
        .s3(Method::PUT, &format!("/{bucket}/{generic_object}"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "qa-kms-generic-success",
        )
        .body("kms-generic-body")
        .send()
        .await
        .expect("put generic kms object failed");
    assert_eq!(put_generic.status(), StatusCode::OK);

    let get_generic = server
        .s3(Method::GET, &format!("/{bucket}/{generic_object}"))
        .send()
        .await
        .expect("get generic kms object failed");
    assert_eq!(get_generic.status(), StatusCode::OK);
    assert_eq!(
        get_generic
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|value| value.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        get_generic
            .headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|value| value.to_str().ok()),
        Some("qa-kms-generic-success")
    );
    assert_eq!(
        get_generic
            .text()
            .await
            .expect("generic kms object body should be readable"),
        "kms-generic-body"
    );

    let generic_meta = server
        .state
        .object_meta
        .read()
        .await
        .get(&(bucket.to_string(), generic_object.to_string()))
        .cloned()
        .expect("generic kms object metadata should exist");
    assert_eq!(generic_meta.encryption.algorithm, "aws:kms");
    assert_eq!(
        generic_meta.encryption.kms_key_id.as_deref(),
        Some("qa-kms-generic-success")
    );
    assert!(
        generic_meta
            .encryption
            .wrapped_key_base64
            .as_deref()
            .is_some_and(|value| value.starts_with("kms-generic:")),
        "generic kms object should use remote wrapped key"
    );

    std::env::set_var("RUSTIO_KMS_PROVIDER", "vault-transit");
    let put_vault = server
        .s3(Method::PUT, &format!("/{bucket}/{vault_object}"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "qa-kms-vault-success",
        )
        .body("kms-vault-body")
        .send()
        .await
        .expect("put vault kms object failed");
    assert_eq!(put_vault.status(), StatusCode::OK);

    let get_vault = server
        .s3(Method::GET, &format!("/{bucket}/{vault_object}"))
        .send()
        .await
        .expect("get vault kms object failed");
    assert_eq!(get_vault.status(), StatusCode::OK);
    assert_eq!(
        get_vault
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|value| value.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        get_vault
            .headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|value| value.to_str().ok()),
        Some("qa-kms-vault-success")
    );
    assert_eq!(
        get_vault
            .text()
            .await
            .expect("vault kms object body should be readable"),
        "kms-vault-body"
    );

    let vault_meta = server
        .state
        .object_meta
        .read()
        .await
        .get(&(bucket.to_string(), vault_object.to_string()))
        .cloned()
        .expect("vault kms object metadata should exist");
    assert_eq!(vault_meta.encryption.algorithm, "aws:kms");
    assert_eq!(
        vault_meta.encryption.kms_key_id.as_deref(),
        Some("qa-kms-vault-success")
    );
    assert!(
        vault_meta
            .encryption
            .wrapped_key_base64
            .as_deref()
            .is_some_and(|value| value.starts_with("kms-vault:")),
        "vault kms object should use remote wrapped key"
    );

    std::env::set_var("RUSTIO_KMS_PROVIDER", "kes");
    std::env::set_var("RUSTIO_KMS_API_KEY", "kes-api-key");
    let put_kes = server
        .s3(Method::PUT, &format!("/{bucket}/{kes_object}"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "qa-kms-kes-success",
        )
        .body("kms-kes-body")
        .send()
        .await
        .expect("put kes kms object failed");
    assert_eq!(put_kes.status(), StatusCode::OK);

    let get_kes = server
        .s3(Method::GET, &format!("/{bucket}/{kes_object}"))
        .send()
        .await
        .expect("get kes kms object failed");
    assert_eq!(get_kes.status(), StatusCode::OK);
    assert_eq!(
        get_kes
            .headers()
            .get("x-amz-server-side-encryption")
            .and_then(|value| value.to_str().ok()),
        Some("aws:kms")
    );
    assert_eq!(
        get_kes
            .headers()
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .and_then(|value| value.to_str().ok()),
        Some("qa-kms-kes-success")
    );
    assert_eq!(
        get_kes
            .text()
            .await
            .expect("kes kms object body should be readable"),
        "kms-kes-body"
    );

    let kes_meta = server
        .state
        .object_meta
        .read()
        .await
        .get(&(bucket.to_string(), kes_object.to_string()))
        .cloned()
        .expect("kes kms object metadata should exist");
    assert_eq!(kes_meta.encryption.algorithm, "aws:kms");
    assert_eq!(
        kes_meta.encryption.kms_key_id.as_deref(),
        Some("qa-kms-kes-success")
    );
    assert!(
        kes_meta
            .encryption
            .wrapped_key_base64
            .as_deref()
            .is_some_and(|value| value.starts_with("kms-kes:")),
        "kes kms object should use remote wrapped key"
    );

    assert!(
        server.state.security.read().await.kms_healthy,
        "kms health should stay green after successful external wrap/unwrap"
    );

    let requests = kms
        .requests()
        .into_iter()
        .filter(|item| item.key_id.as_deref() != Some("ready-check"))
        .collect::<Vec<_>>();
    assert!(
        requests.iter().any(|item| {
            item.provider == "generic"
                && item.operation == "encrypt"
                && item.key_id.as_deref() == Some("qa-kms-generic-success")
                && item.authorization.as_deref() == Some("Bearer kms-shared-token")
                && item.vault_token.as_deref() == Some("kms-shared-token")
                && item
                    .context
                    .as_ref()
                    .and_then(|value| value.get("bucket"))
                    .and_then(|value| value.as_str())
                    == Some(bucket)
                && item
                    .context
                    .as_ref()
                    .and_then(|value| value.get("key"))
                    .and_then(|value| value.as_str())
                    == Some(generic_object)
        }),
        "generic encrypt request should include token headers and object context"
    );
    assert!(
        requests.iter().any(|item| {
            item.provider == "generic"
                && item.operation == "decrypt"
                && item.authorization.as_deref() == Some("Bearer kms-shared-token")
        }),
        "generic decrypt request should reuse token-authenticated KMS client"
    );
    assert!(
        requests.iter().any(|item| {
            item.provider == "vault-transit"
                && item.operation == "encrypt"
                && item.key_id.as_deref() == Some("qa-kms-vault-success")
                && item.authorization.as_deref() == Some("Bearer kms-shared-token")
                && item.vault_token.as_deref() == Some("kms-shared-token")
                && item
                    .context
                    .as_ref()
                    .and_then(|value| value.get("bucket"))
                    .and_then(|value| value.as_str())
                    == Some(bucket)
                && item
                    .context
                    .as_ref()
                    .and_then(|value| value.get("key"))
                    .and_then(|value| value.as_str())
                    == Some(vault_object)
        }),
        "vault transit encrypt request should include token headers and decoded object context"
    );
    assert!(
        requests.iter().any(|item| {
            item.provider == "vault-transit"
                && item.operation == "decrypt"
                && item.key_id.as_deref() == Some("qa-kms-vault-success")
        }),
        "vault transit decrypt request should be invoked during object read"
    );
    assert!(
        requests.iter().any(|item| {
            item.provider == "kes"
                && item.operation == "encrypt"
                && item.key_id.as_deref() == Some("qa-kms-kes-success")
                && item.authorization.as_deref() == Some("Bearer kms-shared-token")
                && item.vault_token.is_none()
                && item.kes_api_key.as_deref() == Some("kes-api-key")
                && item
                    .context
                    .as_ref()
                    .and_then(|value| value.get("bucket"))
                    .and_then(|value| value.as_str())
                    == Some(bucket)
                && item
                    .context
                    .as_ref()
                    .and_then(|value| value.get("key"))
                    .and_then(|value| value.as_str())
                    == Some(kes_object)
        }),
        "kes encrypt request should include bearer/api-key auth and object context"
    );
    assert!(
        requests.iter().any(|item| {
            item.provider == "kes"
                && item.operation == "decrypt"
                && item.key_id.as_deref() == Some("qa-kms-kes-success")
                && item.kes_api_key.as_deref() == Some("kes-api-key")
        }),
        "kes decrypt request should be invoked during object read"
    );

    std::env::remove_var("RUSTIO_KMS_EXTERNAL_ENABLED");
    std::env::remove_var("RUSTIO_KMS_PROVIDER");
    std::env::remove_var("RUSTIO_KMS_TOKEN");
    std::env::remove_var("RUSTIO_KMS_API_KEY");
    kms.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_service_account_policy_conditions_regression() {
    let server = TestServer::spawn().await;
    let bucket = "policy-conditions-bucket";

    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, body) in [
        ("reports/2026-03.txt", "report-body"),
        ("private/secret.txt", "secret-body"),
    ] {
        let put = server
            .s3(Method::PUT, &format!("/{bucket}/{key}"))
            .body(body)
            .send()
            .await
            .expect("put object failed");
        assert_eq!(put.status(), StatusCode::OK);
    }

    server.state.users.write().await.push(rustio_core::IamUser {
        username: "reporter".to_string(),
        display_name: "Reporter".to_string(),
        role: "readonly".to_string(),
        enabled: true,
        created_at: Utc::now(),
    });
    server
        .state
        .service_accounts
        .write()
        .await
        .push(rustio_core::ServiceAccount {
            access_key: "reporter-ak".to_string(),
            secret_key: "reporter-sk".to_string(),
            owner: "reporter".to_string(),
            created_at: Utc::now(),
            status: "enabled".to_string(),
        });
    server
        .state
        .policies
        .write()
        .await
        .push(rustio_core::IamPolicy {
            name: "reporter-prefix".to_string(),
            document: serde_json::json!({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ListReportsOnly",
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": [format!("arn:aws:s3:::{bucket}")],
                        "Condition": {
                            "StringEquals": {
                                "s3:prefix": "reports/",
                                "aws:username": "reporter"
                            }
                        }
                    },
                    {
                        "Sid": "ReadReportsOnly",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": [format!("arn:aws:s3:::{bucket}/reports/*")]
                    },
                    {
                        "Sid": "DenyPrivate",
                        "Effect": "Deny",
                        "Action": ["s3:GetObject"],
                        "Resource": [format!("arn:aws:s3:::{bucket}/private/*")]
                    }
                ]
            }),
            attached_to: vec!["reporter".to_string()],
        });

    let reporter_auth = format!("Basic {}", BASE64.encode("reporter-ak:reporter-sk"));

    let list_reports = server
        .client
        .get(format!(
            "{}/{bucket}?list-type=2&prefix=reports/",
            server.base_url
        ))
        .header(header::AUTHORIZATION, reporter_auth.clone())
        .send()
        .await
        .expect("list reports request failed");
    assert_eq!(list_reports.status(), StatusCode::OK);
    let list_reports_xml = list_reports.text().await.expect("read reports list");
    assert!(
        list_reports_xml.contains("<Key>reports/2026-03.txt</Key>"),
        "unexpected reports list xml: {list_reports_xml}"
    );

    let list_private = server
        .client
        .get(format!(
            "{}/{bucket}?list-type=2&prefix=private/",
            server.base_url
        ))
        .header(header::AUTHORIZATION, reporter_auth.clone())
        .send()
        .await
        .expect("list private request failed");
    assert_s3_error(list_private, StatusCode::FORBIDDEN, "AccessDenied").await;

    let get_reports = server
        .client
        .get(format!("{}/{bucket}/reports/2026-03.txt", server.base_url))
        .header(header::AUTHORIZATION, reporter_auth.clone())
        .send()
        .await
        .expect("get reports request failed");
    assert_eq!(get_reports.status(), StatusCode::OK);

    let get_private = server
        .client
        .get(format!("{}/{bucket}/private/secret.txt", server.base_url))
        .header(header::AUTHORIZATION, reporter_auth)
        .send()
        .await
        .expect("get private request failed");
    assert_s3_error(get_private, StatusCode::FORBIDDEN, "AccessDenied").await;

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_dynamic_service_account_and_sts_admin_api_regression() {
    let server = TestServer::spawn().await;
    let bucket = "dynamic-auth-bucket";
    let object = "reports/summary.txt";
    let admin_token = server.admin_token().await;

    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let put = server
        .s3(Method::PUT, &format!("/{bucket}/{object}"))
        .body("dynamic-auth-body")
        .send()
        .await
        .expect("put object failed");
    assert_eq!(put.status(), StatusCode::OK);

    let create_user = server
        .client
        .post(format!("{}/api/v1/iam/users", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .json(&serde_json::json!({
            "username": "dynamic-auth-user",
            "password": "dynamic-auth-pass",
            "display_name": "Dynamic Auth User",
            "role": "operator"
        }))
        .send()
        .await
        .expect("create dynamic auth user failed");
    assert_eq!(create_user.status(), StatusCode::OK);

    let create_policy = server
        .client
        .post(format!("{}/api/v1/iam/policies", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .json(&serde_json::json!({
            "name": "dynamic-auth-policy",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": [format!("arn:aws:s3:::{bucket}")]
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": [format!("arn:aws:s3:::{bucket}/reports/*")]
                    }
                ]
            }
        }))
        .send()
        .await
        .expect("create dynamic auth policy failed");
    assert_eq!(create_policy.status(), StatusCode::OK);

    let attach_policy = server
        .client
        .post(format!(
            "{}/api/v1/iam/policies/dynamic-auth-policy/attach",
            server.base_url
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .json(&serde_json::json!({ "principal": "dynamic-auth-user" }))
        .send()
        .await
        .expect("attach dynamic auth policy failed");
    assert_eq!(attach_policy.status(), StatusCode::OK);

    let create_service_account = server
        .client
        .post(format!("{}/api/v1/iam/service-accounts", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .json(&serde_json::json!({ "owner": "dynamic-auth-user" }))
        .send()
        .await
        .expect("create dynamic service account failed");
    assert_eq!(create_service_account.status(), StatusCode::OK);
    let service_account_payload = create_service_account
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode dynamic service account response");
    let service_access_key = service_account_payload
        .pointer("/data/access_key")
        .and_then(|value| value.as_str())
        .expect("dynamic service account access key should exist");
    let service_secret_key = service_account_payload
        .pointer("/data/secret_key")
        .and_then(|value| value.as_str())
        .expect("dynamic service account secret key should exist");
    let service_auth = basic_auth_header(service_access_key, service_secret_key);

    let service_list = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(header::AUTHORIZATION, service_auth.clone())
        .send()
        .await
        .expect("dynamic service account list request failed");
    assert_eq!(service_list.status(), StatusCode::OK);

    let service_get = server
        .client
        .get(format!("{}/{bucket}/{object}", server.base_url))
        .header(header::AUTHORIZATION, service_auth.clone())
        .send()
        .await
        .expect("dynamic service account get request failed");
    assert_eq!(service_get.status(), StatusCode::OK);

    let create_sts = server
        .client
        .post(format!("{}/api/v1/iam/sts/sessions", server.base_url))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .json(&serde_json::json!({
            "principal": "dynamic-auth-user",
            "ttl_minutes": 30
        }))
        .send()
        .await
        .expect("create dynamic sts failed");
    assert_eq!(create_sts.status(), StatusCode::OK);
    let sts_payload = create_sts
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode dynamic sts response");
    let sts_session_id = sts_payload
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("dynamic sts session id should exist");
    let sts_access_key = sts_payload
        .pointer("/data/access_key")
        .and_then(|value| value.as_str())
        .expect("dynamic sts access key should exist");
    let sts_secret_key = sts_payload
        .pointer("/data/secret_key")
        .and_then(|value| value.as_str())
        .expect("dynamic sts secret key should exist");
    let sts_session_token = sts_payload
        .pointer("/data/session_token")
        .and_then(|value| value.as_str())
        .expect("dynamic sts session token should exist");
    let sts_auth = basic_auth_header(sts_access_key, sts_secret_key);

    let sts_list = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(header::AUTHORIZATION, sts_auth.clone())
        .header("x-amz-security-token", sts_session_token)
        .send()
        .await
        .expect("dynamic sts list request failed");
    assert_eq!(sts_list.status(), StatusCode::OK);

    let delete_sts = server
        .client
        .delete(format!(
            "{}/api/v1/iam/sts/sessions/{}",
            server.base_url, sts_session_id
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .send()
        .await
        .expect("delete dynamic sts failed");
    assert_eq!(delete_sts.status(), StatusCode::OK);

    let revoked_sts = server
        .client
        .get(format!("{}/{bucket}?list-type=2", server.base_url))
        .header(header::AUTHORIZATION, sts_auth)
        .header("x-amz-security-token", sts_session_token)
        .send()
        .await
        .expect("revoked dynamic sts request failed");
    assert_s3_error(revoked_sts, StatusCode::FORBIDDEN, "AccessDenied").await;

    let delete_service_account = server
        .client
        .delete(format!(
            "{}/api/v1/iam/service-accounts/{}",
            server.base_url, service_access_key
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .send()
        .await
        .expect("delete dynamic service account failed");
    assert_eq!(delete_service_account.status(), StatusCode::OK);

    let revoked_service_account = server
        .client
        .get(format!("{}/{bucket}/{object}", server.base_url))
        .header(header::AUTHORIZATION, service_auth)
        .send()
        .await
        .expect("revoked dynamic service account request failed");
    assert_s3_error(
        revoked_service_account,
        StatusCode::FORBIDDEN,
        "AccessDenied",
    )
    .await;

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s3_anonymous_bucket_policy_regression() {
    let server = TestServer::spawn().await;
    let bucket = "public-policy-bucket";

    let create_bucket = server
        .s3(Method::PUT, &format!("/{bucket}"))
        .send()
        .await
        .expect("create bucket failed");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, body) in [
        ("public/readme.txt", "public-body"),
        ("private/hidden.txt", "hidden-body"),
    ] {
        let put = server
            .s3(Method::PUT, &format!("/{bucket}/{key}"))
            .body(body)
            .send()
            .await
            .expect("put object failed");
        assert_eq!(put.status(), StatusCode::OK);
    }

    server.state.bucket_policies.write().await.insert(
        bucket.to_string(),
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadPrefix",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Resource": [format!("arn:aws:s3:::{bucket}/public/*")]
                },
                {
                    "Sid": "PublicDeleteDeny",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:DeleteObject"],
                    "Resource": [format!("arn:aws:s3:::{bucket}/public/*")]
                }
            ]
        }),
    );

    let public_get = server
        .client
        .get(format!("{}/{bucket}/public/readme.txt", server.base_url))
        .send()
        .await
        .expect("anonymous public get failed");
    assert_eq!(public_get.status(), StatusCode::OK);

    let private_get = server
        .client
        .get(format!("{}/{bucket}/private/hidden.txt", server.base_url))
        .send()
        .await
        .expect("anonymous private get failed");
    assert_s3_error(private_get, StatusCode::FORBIDDEN, "AccessDenied").await;

    let public_delete = server
        .client
        .delete(format!("{}/{bucket}/public/readme.txt", server.base_url))
        .send()
        .await
        .expect("anonymous public delete failed");
    assert_s3_error(public_delete, StatusCode::FORBIDDEN, "AccessDenied").await;

    server
        .state
        .bucket_public_access_blocks
        .write()
        .await
        .insert(
            bucket.to_string(),
            rustio_core::BucketPublicAccessBlockConfig {
                block_public_acls: false,
                ignore_public_acls: false,
                block_public_policy: true,
                restrict_public_buckets: false,
            },
        );
    let blocked_public_get = server
        .client
        .get(format!("{}/{bucket}/public/readme.txt", server.base_url))
        .send()
        .await
        .expect("anonymous blocked public get failed");
    assert_s3_error(blocked_public_get, StatusCode::FORBIDDEN, "AccessDenied").await;

    server.stop().await;
}
