use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Form, Query},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration as ChronoDuration, Utc};
use futures::{SinkExt, StreamExt};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ldap3_proto::simple::{LdapFilter, LdapPartialAttribute, LdapSearchResultEntry, ServerOps};
use p256::ecdsa::SigningKey;
use percent_encoding::percent_decode_str;
use reqwest::{header, StatusCode};
use rsa::{
    pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePrivateKey, traits::PublicKeyParts, RsaPrivateKey,
};
use rustio_admin::{build_router, state::AlertDeliveryItem, AppState};
use rustio_core::{
    AlertChannel, AlertHistoryEntry, AuditEvent, BucketLifecycleRule, BucketSpec, ConsoleSession,
    IamGroup, IamPolicy, IamUser, JobStatus, KmsRotationFailedObject, ObjectRemoteTierStatus,
    RemoteTierConfig, ReplicationBacklogItem, ReplicationStatus, S3ObjectMeta, ServiceAccount,
    StsSession,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::sleep};
use tokio_util::codec::Framed;

struct AdminServer {
    base_url: String,
    client: reqwest::Client,
    state: Arc<AppState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
    data_dir: PathBuf,
    env_restore: Vec<(String, Option<String>)>,
    _env_guard: Option<MutexGuard<'static, ()>>,
}

struct MockOidcServer {
    base_url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Default)]
struct MockOidcBehavior {
    token_nonce_override: Option<String>,
    token_status_override: Option<StatusCode>,
    omit_id_token: bool,
    expected_client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EcManifestFile {
    bucket: String,
    key: String,
    total_size: u64,
    shard_size: usize,
    data_shards: usize,
    parity_shards: usize,
    shards: Vec<EcManifestShardFile>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EcManifestShardFile {
    shard_index: usize,
    disk_index: usize,
    path: PathBuf,
    checksum: String,
}

fn sha256_hex_test(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn manifest_path_for(data_dir: &PathBuf, bucket: &str, key: &str) -> PathBuf {
    data_dir
        .join(bucket)
        .join(".rustio_ec_meta")
        .join(format!("{}.json", sha256_hex_test(key.as_bytes())))
}

fn object_meta_path_for(data_dir: &PathBuf, bucket: &str, key: &str) -> PathBuf {
    data_dir
        .join(bucket)
        .join(".rustio_meta")
        .join(format!("{key}.json"))
}

fn current_object_payload_path_for(data_dir: &PathBuf, bucket: &str, key: &str) -> PathBuf {
    data_dir.join(bucket).join(key)
}

fn read_object_meta_file(data_dir: &PathBuf, bucket: &str, key: &str) -> S3ObjectMeta {
    serde_json::from_slice::<S3ObjectMeta>(
        &std::fs::read(object_meta_path_for(data_dir, bucket, key))
            .expect("object metadata should exist"),
    )
    .expect("object metadata should decode")
}

fn kms_failed_object(
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    is_current: bool,
    kms_key_id: Option<&str>,
    stage: &str,
    message: &str,
) -> KmsRotationFailedObject {
    KmsRotationFailedObject {
        bucket: bucket.to_string(),
        object_key: key.to_string(),
        version_id: version_id.map(|value| value.to_string()),
        is_current,
        kms_key_id: kms_key_id.map(|value| value.to_string()),
        retry_id: String::new(),
        stage: stage.to_string(),
        message: message.to_string(),
    }
    .normalized()
}

fn archived_object_meta_path_for(
    data_dir: &PathBuf,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> PathBuf {
    data_dir
        .join(bucket)
        .join(".rustio_versions")
        .join(sha256_hex_test(key.as_bytes()))
        .join(format!("{version_id}.json"))
}

fn archived_object_payload_path_for(
    data_dir: &PathBuf,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> PathBuf {
    data_dir
        .join(bucket)
        .join(".rustio_versions")
        .join(sha256_hex_test(key.as_bytes()))
        .join(format!("{version_id}.bin"))
}

fn read_archived_object_meta_file(
    data_dir: &PathBuf,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> S3ObjectMeta {
    serde_json::from_slice::<S3ObjectMeta>(
        &std::fs::read(archived_object_meta_path_for(
            data_dir, bucket, key, version_id,
        ))
        .expect("archived object metadata should exist"),
    )
    .expect("archived object metadata should decode")
}

fn remote_tier_payload_path_for(
    root: &PathBuf,
    bucket: &str,
    prefix: Option<&str>,
    key: &str,
    version_id: &str,
) -> PathBuf {
    let mut path = root.join(bucket);
    if let Some(prefix) = prefix {
        if !prefix.trim().is_empty() {
            path = path.join(prefix.trim());
        }
    }
    path.join(sha256_hex_test(key.as_bytes()))
        .join(format!("{version_id}.bin"))
}

fn read_manifest_file(data_dir: &PathBuf, bucket: &str, key: &str) -> EcManifestFile {
    serde_json::from_slice::<EcManifestFile>(
        &std::fs::read(manifest_path_for(data_dir, bucket, key))
            .expect("manifest should exist after object write"),
    )
    .expect("manifest should decode")
}

fn disk_ids_from_manifest(manifest: &EcManifestFile) -> Vec<String> {
    let mut shards = manifest.shards.clone();
    shards.sort_by_key(|item| item.shard_index);
    shards
        .into_iter()
        .map(|shard| format!("disk-{}", shard.disk_index))
        .collect()
}

async fn wait_for_storage_job_status(
    admin: &AdminServer,
    kind_prefix: &str,
    bucket: Option<&str>,
    key: Option<&str>,
    expected_status: &str,
) -> Value {
    let token = admin.login_access_token().await;
    for _ in 0..120 {
        let response = admin
            .client
            .get(format!("{}/api/v1/jobs", admin.base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("jobs request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .json::<Value>()
            .await
            .expect("jobs body should decode");
        let found = body
            .pointer("/data")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.pointer("/kind")
                        .and_then(Value::as_str)
                        .map(|kind| kind.starts_with(kind_prefix))
                        .unwrap_or(false)
                        && bucket
                            .map(|value| item.pointer("/bucket") == Some(&json!(value)))
                            .unwrap_or(true)
                        && key
                            .map(|value| item.pointer("/key") == Some(&json!(value)))
                            .unwrap_or(true)
                        && item.pointer("/status") == Some(&json!(expected_status))
                })
            })
            .cloned();
        if let Some(found) = found {
            return found;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "storage job was not observed: kind_prefix={kind_prefix} bucket={bucket:?} key={key:?} status={expected_status}"
    );
}

async fn wait_for_governance_disk_state(
    admin: &AdminServer,
    disk_id: &str,
    expected_state: &str,
) -> Value {
    let token = admin.login_access_token().await;
    for _ in 0..120 {
        let response = admin
            .client
            .get(format!("{}/api/v1/storage/governance", admin.base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("governance request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .json::<Value>()
            .await
            .expect("governance body should decode");
        let found = body
            .pointer("/data/disks")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.pointer("/disk_id") == Some(&json!(disk_id))
                        && item.pointer("/placement_state") == Some(&json!(expected_state))
                })
            })
            .cloned();
        if let Some(found) = found {
            return found;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("disk did not reach expected placement state: {disk_id} -> {expected_state}");
}

fn test_job_status(
    id: &str,
    kind: &str,
    status: &str,
    priority: i32,
    progress: f32,
    created_at: chrono::DateTime<Utc>,
) -> JobStatus {
    JobStatus {
        id: id.to_string(),
        kind: kind.to_string(),
        status: status.to_string(),
        priority,
        bucket: None,
        object_key: None,
        site_id: None,
        idempotency_key: id.to_string(),
        attempt: 0,
        lease_owner: None,
        lease_until: None,
        checkpoint: None,
        last_error: None,
        payload: json!({}),
        progress,
        created_at,
        updated_at: created_at,
        key: None,
        version_id: None,
        target: None,
        affected_disks: vec![],
        missing_shards: 0,
        corrupted_shards: 0,
        started_at: None,
        finished_at: None,
        attempts: 0,
        max_attempts: 0,
        next_attempt_at: None,
        error: None,
        dedupe_key: Some(id.to_string()),
        source: None,
        details: Value::Null,
    }
}

fn test_replication_backlog_item(
    id: &str,
    source_bucket: &str,
    target_site: &str,
    object_key: &str,
    rule_id: Option<&str>,
    priority: i32,
    operation: &str,
    checkpoint: u64,
    status: &str,
) -> ReplicationBacklogItem {
    let now = Utc::now();
    ReplicationBacklogItem {
        id: id.to_string(),
        source_bucket: source_bucket.to_string(),
        target_site: target_site.to_string(),
        object_key: object_key.to_string(),
        rule_id: rule_id.map(ToOwned::to_owned),
        priority,
        operation: operation.to_string(),
        checkpoint,
        idempotency_key: format!("{source_bucket}:{target_site}:{object_key}:{checkpoint}"),
        version_id: None,
        attempts: 0,
        status: status.to_string(),
        last_error: String::new(),
        lease_owner: None,
        lease_until: None,
        queued_at: now,
        last_attempt_at: now,
    }
}

fn xml_tag_text(body: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = body.find(&start_tag)? + start_tag.len();
    let end = body[start..].find(&end_tag)? + start;
    Some(body[start..end].to_string())
}

fn configure_mock_oidc_env(oidc: &MockOidcServer, client_id: &str) {
    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", client_id);
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");
}

fn configure_mock_ldap_env(ldap: &MockLdapServer) {
    std::env::set_var("RUSTIO_LDAP_ENABLED", "true");
    std::env::set_var("RUSTIO_LDAP_URL", &ldap.url);
    std::env::set_var(
        "RUSTIO_LDAP_USER_BASE_DN",
        format!("ou=users,{}", ldap.base_dn),
    );
    std::env::set_var(
        "RUSTIO_LDAP_GROUP_BASE_DN",
        format!("ou=groups,{}", ldap.base_dn),
    );
    std::env::set_var("RUSTIO_LDAP_USER_FILTER", "(uid={username})");
    std::env::set_var("RUSTIO_LDAP_GROUP_FILTER", "(member={user_dn})");
    std::env::set_var("RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE", "cn");
    std::env::set_var("RUSTIO_LDAP_DEFAULT_ROLE", "viewer");
}

struct MockOidcRsaKeyMaterial {
    private_key_der: Vec<u8>,
    n: String,
    e: String,
}

struct MockOidcEcKeyMaterial {
    private_key_der: Vec<u8>,
    x: String,
    y: String,
}

fn mock_oidc_rsa_key_material() -> &'static MockOidcRsaKeyMaterial {
    static MATERIAL: OnceLock<MockOidcRsaKeyMaterial> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let mut random = rsa::rand_core::OsRng;
        let private_key =
            RsaPrivateKey::new(&mut random, 2048).expect("failed to generate mock oidc rsa key");
        let private_key_der = private_key
            .to_pkcs1_der()
            .expect("failed to encode mock oidc rsa key")
            .as_bytes()
            .to_vec();
        MockOidcRsaKeyMaterial {
            private_key_der,
            n: URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be()),
        }
    })
}

fn mock_oidc_ec_key_material() -> &'static MockOidcEcKeyMaterial {
    static MATERIAL: OnceLock<MockOidcEcKeyMaterial> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let mut random = p256::elliptic_curve::rand_core::OsRng;
        let signing_key = SigningKey::random(&mut random);
        let private_key_der = signing_key
            .to_pkcs8_der()
            .expect("failed to encode mock oidc ec key")
            .as_bytes()
            .to_vec();
        let encoded_point = signing_key.verifying_key().to_encoded_point(false);
        let x = encoded_point
            .x()
            .expect("mock oidc ec x coordinate should exist");
        let y = encoded_point
            .y()
            .expect("mock oidc ec y coordinate should exist");
        MockOidcEcKeyMaterial {
            private_key_der,
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    })
}

#[derive(Debug, Clone)]
enum MockOidcSigningKey {
    Hs256 { secret: String },
    Rs256,
    Es256,
}

impl MockOidcSigningKey {
    fn hs256(secret: impl Into<String>) -> Self {
        Self::Hs256 {
            secret: secret.into(),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Hs256 { .. } => Algorithm::HS256,
            Self::Rs256 => Algorithm::RS256,
            Self::Es256 => Algorithm::ES256,
        }
    }

    fn discovery_alg(&self) -> &'static str {
        match self {
            Self::Hs256 { .. } => "HS256",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        match self {
            Self::Hs256 { secret } => EncodingKey::from_secret(secret.as_bytes()),
            Self::Rs256 => EncodingKey::from_rsa_der(&mock_oidc_rsa_key_material().private_key_der),
            Self::Es256 => EncodingKey::from_ec_der(&mock_oidc_ec_key_material().private_key_der),
        }
    }

    fn jwk(&self) -> Value {
        match self {
            Self::Hs256 { secret } => json!({
                "kty": "oct",
                "alg": "HS256",
                "kid": "oidc-key-1",
                "k": URL_SAFE_NO_PAD.encode(secret.as_bytes())
            }),
            Self::Rs256 => json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "oidc-key-1",
                "n": mock_oidc_rsa_key_material().n,
                "e": mock_oidc_rsa_key_material().e
            }),
            Self::Es256 => json!({
                "kty": "EC",
                "alg": "ES256",
                "use": "sig",
                "kid": "oidc-key-1",
                "crv": "P-256",
                "x": mock_oidc_ec_key_material().x,
                "y": mock_oidc_ec_key_material().y
            }),
        }
    }
}

struct MockLdapServer {
    url: String,
    base_dn: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct MockLdapDirectory {
    username: String,
    password: String,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    cn: String,
    display_name: String,
    groups: Vec<String>,
    user_ou_path: String,
    group_ou_path: String,
    include_member_of: bool,
    enable_group_search: bool,
    membership_attribute_name: String,
    membership_values_are_dns: bool,
    group_name_attribute: String,
}

impl Default for MockLdapDirectory {
    fn default() -> Self {
        Self {
            username: "alice".to_string(),
            password: "alice-pass".to_string(),
            bind_dn: None,
            bind_password: None,
            cn: "Alice Ops".to_string(),
            display_name: "Alice Ops Team".to_string(),
            groups: vec!["ops".to_string()],
            user_ou_path: "ou=users".to_string(),
            group_ou_path: "ou=groups".to_string(),
            include_member_of: false,
            enable_group_search: true,
            membership_attribute_name: "memberOf".to_string(),
            membership_values_are_dns: true,
            group_name_attribute: "cn".to_string(),
        }
    }
}

impl MockLdapDirectory {
    fn user_dn(&self, base_dn: &str) -> String {
        format!("uid={},{},{}", self.username, self.user_ou_path, base_dn)
    }

    fn group_dn(&self, group_name: &str, base_dn: &str) -> String {
        format!(
            "{}={group_name},{},{}",
            self.group_name_attribute, self.group_ou_path, base_dn
        )
    }
}

fn decode_query_param(location: &str, key: &str) -> Option<String> {
    let query = location.split('?').nth(1)?;
    query.split('&').find_map(|segment| {
        let mut split = segment.splitn(2, '=');
        let name = split.next()?.trim();
        let value = split.next()?.trim();
        (name == key).then(|| percent_decode_str(value).decode_utf8_lossy().to_string())
    })
}

fn decode_redirect_error(location: &str) -> Option<String> {
    decode_query_param(location, "error")
}

#[derive(Debug, Clone)]
struct MockOidcCodeGrant {
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct MockOidcAuthorizeQuery {
    redirect_uri: String,
    state: String,
    nonce: Option<String>,
    client_id: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MockOidcTokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
    client_secret: Option<String>,
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

impl AdminServer {
    async fn spawn() -> Self {
        Self::spawn_with_env(&[]).await
    }

    async fn spawn_with_env(overrides: &[(&str, &str)]) -> Self {
        let env_guard = env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!(
            "rustio-auth-external-{}-{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(&data_dir).expect("failed to create temp data dir");

        std::env::set_var("RUSTIO_DATA_DIR", &data_dir);
        std::env::set_var("RUSTIO_ROOT_USER", "rustioadmin");
        std::env::set_var("RUSTIO_ROOT_PASSWORD", "rustioadmin");
        let mut env_restore = Vec::with_capacity(overrides.len());
        for (key, value) in overrides {
            env_restore.push(((*key).to_string(), std::env::var(key).ok()));
            std::env::set_var(key, value);
        }
        for key in [
            "RUSTIO_OIDC_ENABLED",
            "RUSTIO_OIDC_DISCOVERY_URL",
            "RUSTIO_OIDC_ISSUER",
            "RUSTIO_OIDC_CLIENT_ID",
            "RUSTIO_OIDC_CLIENT_SECRET",
            "RUSTIO_OIDC_JWKS_URL",
            "RUSTIO_OIDC_ALLOWED_ALGS",
            "RUSTIO_OIDC_USERNAME_CLAIM",
            "RUSTIO_OIDC_GROUPS_CLAIM",
            "RUSTIO_OIDC_ROLE_CLAIM",
            "RUSTIO_OIDC_DEFAULT_ROLE",
            "RUSTIO_OIDC_GROUP_ROLE_MAP",
            "RUSTIO_OIDC_SCOPES",
            "RUSTIO_LDAP_ENABLED",
            "RUSTIO_LDAP_URL",
            "RUSTIO_LDAP_BIND_DN",
            "RUSTIO_LDAP_BIND_PASSWORD",
            "RUSTIO_LDAP_USER_BASE_DN",
            "RUSTIO_LDAP_USER_FILTER",
            "RUSTIO_LDAP_GROUP_BASE_DN",
            "RUSTIO_LDAP_GROUP_FILTER",
            "RUSTIO_LDAP_GROUP_ATTRIBUTE",
            "RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE",
            "RUSTIO_LDAP_DEFAULT_ROLE",
            "RUSTIO_LDAP_GROUP_ROLE_MAP",
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
        let base_url = format!("http://{addr}");
        let server = Self {
            base_url,
            client,
            state,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            data_dir,
            env_restore,
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

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
        for (key, previous) in self.env_restore.drain(..) {
            if let Some(value) = previous {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }

    async fn login_access_token(&self) -> String {
        let payload = self.login_response().await;
        payload
            .pointer("/data/access_token")
            .and_then(|value| value.as_str())
            .expect("access token should exist")
            .to_string()
    }

    async fn login_response(&self) -> serde_json::Value {
        self.login_response_as("admin", "rustio-admin").await
    }

    async fn login_response_as(&self, username: &str, password: &str) -> serde_json::Value {
        let response = self
            .client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "username": username,
                    "password": password
                })
                .to_string(),
            )
            .send()
            .await
            .expect("login request failed");
        assert_eq!(response.status(), StatusCode::OK);
        response
            .json::<serde_json::Value>()
            .await
            .expect("failed to decode login response")
    }
}

impl MockOidcServer {
    async fn spawn(secret: String) -> Self {
        Self::spawn_with_signing(MockOidcSigningKey::hs256(secret)).await
    }

    async fn spawn_with_signing(signing: MockOidcSigningKey) -> Self {
        Self::spawn_with_signing_and_behavior(signing, MockOidcBehavior::default()).await
    }

    async fn spawn_with_signing_and_behavior(
        signing: MockOidcSigningKey,
        behavior: MockOidcBehavior,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind oidc listener");
        let addr = listener
            .local_addr()
            .expect("failed to read oidc listen addr");
        let base_url = format!("http://{addr}");
        let issuer = base_url.clone();
        let jwks_uri = format!("{base_url}/jwks.json");
        let authorization_endpoint = format!("{base_url}/authorize");
        let token_endpoint = format!("{base_url}/token");
        let discovery_alg = signing.discovery_alg().to_string();
        let jwk = signing.jwk();
        let issued_codes = Arc::new(Mutex::new(HashMap::<String, MockOidcCodeGrant>::new()));

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get({
                    let issuer = issuer.clone();
                    let jwks_uri = jwks_uri.clone();
                    let authorization_endpoint = authorization_endpoint.clone();
                    let token_endpoint = token_endpoint.clone();
                    let discovery_alg = discovery_alg.clone();
                    move || async move {
                        Json(json!({
                            "issuer": issuer,
                            "jwks_uri": jwks_uri,
                            "authorization_endpoint": authorization_endpoint,
                            "token_endpoint": token_endpoint,
                            "id_token_signing_alg_values_supported": [discovery_alg]
                        }))
                    }
                }),
            )
            .route(
                "/jwks.json",
                get(move || {
                    let jwk = jwk.clone();
                    async move {
                        Json(json!({
                            "keys": [jwk]
                        }))
                    }
                }),
            )
            .route(
                "/authorize",
                get({
                    let issued_codes = Arc::clone(&issued_codes);
                    move |Query(query): Query<MockOidcAuthorizeQuery>| {
                        let issued_codes = Arc::clone(&issued_codes);
                        async move {
                            assert_eq!(query.client_id.as_deref(), Some("rustio-console"));
                            assert_eq!(query.code_challenge_method.as_deref(), Some("S256"));
                            assert!(
                                query
                                    .code_challenge
                                    .as_deref()
                                    .map(str::trim)
                                    .is_some_and(|value| !value.is_empty()),
                                "pkce code challenge should be present"
                            );
                            assert!(
                                query.redirect_uri.contains("/api/v1/auth/oidc/callback"),
                                "redirect_uri should point back to admin callback"
                            );

                            let code = format!("mock-code-{}", uuid::Uuid::new_v4().simple());
                            issued_codes.lock().expect("lock issued codes").insert(
                                code.clone(),
                                MockOidcCodeGrant {
                                    nonce: query.nonce.unwrap_or_default(),
                                },
                            );
                            Redirect::temporary(&format!(
                                "{}?code={}&state={}",
                                query.redirect_uri, code, query.state
                            ))
                        }
                    }
                }),
            )
            .route(
                "/token",
                post({
                    let issued_codes = Arc::clone(&issued_codes);
                    let issuer = issuer.clone();
                    let signing = signing.clone();
                    let behavior = behavior.clone();
                    move |Form(form): Form<MockOidcTokenForm>| {
                        let issued_codes = Arc::clone(&issued_codes);
                        let issuer = issuer.clone();
                        let signing = signing.clone();
                        let behavior = behavior.clone();
                        async move {
                            assert_eq!(form.grant_type, "authorization_code");
                            assert_eq!(form.client_id, "rustio-console");
                            assert!(
                                !form.redirect_uri.trim().is_empty(),
                                "redirect uri should be forwarded to token endpoint"
                            );
                            assert!(
                                !form.code_verifier.trim().is_empty(),
                                "code verifier should be present"
                            );
                            if let Some(expected_client_secret) =
                                behavior.expected_client_secret.as_deref()
                            {
                                assert_eq!(
                                    form.client_secret.as_deref(),
                                    Some(expected_client_secret),
                                    "client secret should be forwarded to token endpoint"
                                );
                            }
                            let grant = issued_codes
                                .lock()
                                .expect("lock issued codes")
                                .remove(&form.code)
                                .expect("authorization code should exist");

                            if let Some(status) = behavior.token_status_override {
                                return (
                                    status,
                                    Json(json!({
                                        "error": "mock_token_error",
                                        "error_description": "mock token endpoint error"
                                    })),
                                )
                                    .into_response();
                            }

                            let now = Utc::now();
                            let claims = OidcClaims {
                                iss: issuer,
                                sub: "oidc-browser-user-001".to_string(),
                                aud: "rustio-console".to_string(),
                                exp: (now + ChronoDuration::minutes(10)).timestamp(),
                                nbf: (now - ChronoDuration::minutes(1)).timestamp(),
                                iat: now.timestamp(),
                                preferred_username: "oidc-browser-admin".to_string(),
                                name: "OIDC Browser Admin".to_string(),
                                groups: vec!["platform-admins".to_string()],
                                nonce: Some(
                                    behavior.token_nonce_override.clone().unwrap_or(grant.nonce),
                                ),
                            };
                            let mut jwt_header = Header::new(signing.algorithm());
                            jwt_header.kid = Some("oidc-key-1".to_string());
                            let id_token = encode(&jwt_header, &claims, &signing.encoding_key())
                                .expect("failed to encode oidc browser id token");
                            let mut payload = json!({
                                "access_token": "mock-access-token",
                                "token_type": "Bearer",
                                "expires_in": 600
                            });
                            if !behavior.omit_id_token {
                                payload["id_token"] = Value::String(id_token);
                            }
                            Json(payload).into_response()
                        }
                    }
                }),
            );
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let server = Self {
            base_url,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        };
        server.wait_until_ready().await;
        server
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }

    async fn wait_until_ready(&self) {
        let ready_url = format!("{}/.well-known/openid-configuration", self.base_url);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build oidc ready client");
        for _ in 0..100 {
            if let Ok(resp) = client.get(&ready_url).send().await {
                if resp.status() == StatusCode::OK {
                    return;
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("oidc server did not become ready: {ready_url}");
    }
}

impl MockLdapServer {
    async fn spawn() -> Self {
        Self::spawn_with_directory(MockLdapDirectory::default()).await
    }

    async fn spawn_with_directory(directory: MockLdapDirectory) -> Self {
        let base_dn = "dc=example,dc=org".to_string();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock ldap listener");
        let addr = listener
            .local_addr()
            .expect("failed to read mock ldap listen addr");
        let url = format!("ldap://{addr}");
        let server_base_dn = base_dn.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else { break; };
                        let base_dn = base_dn.clone();
                        let directory = directory.clone();
                        tokio::spawn(async move {
                            let _ = handle_mock_ldap_connection(stream, &base_dn, &directory).await;
                        });
                    }
                }
            }
        });

        Self {
            url,
            base_dn: server_base_dn,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        }
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

fn ldap_filter_matches(filter: &LdapFilter, attribute: &str, expected: &str) -> bool {
    match filter {
        LdapFilter::Equality(name, value) => {
            name.eq_ignore_ascii_case(attribute) && value == expected
        }
        LdapFilter::And(items) => items
            .iter()
            .all(|item| ldap_filter_matches(item, attribute, expected)),
        LdapFilter::Or(items) => items
            .iter()
            .any(|item| ldap_filter_matches(item, attribute, expected)),
        LdapFilter::Present(name) => name.eq_ignore_ascii_case(attribute),
        _ => false,
    }
}

fn ldap_dn_within_base(entry_dn: &str, base_dn: &str) -> bool {
    entry_dn.eq_ignore_ascii_case(base_dn)
        || entry_dn
            .to_ascii_lowercase()
            .ends_with(&format!(",{}", base_dn.to_ascii_lowercase()))
}

fn ldap_user_entry_with_directory(
    user_dn: &str,
    directory: &MockLdapDirectory,
    base_dn: &str,
) -> LdapSearchResultEntry {
    let mut attributes = vec![
        LdapPartialAttribute {
            atype: "uid".to_string(),
            vals: vec![directory.username.as_bytes().to_vec()],
        },
        LdapPartialAttribute {
            atype: "cn".to_string(),
            vals: vec![directory.cn.as_bytes().to_vec()],
        },
        LdapPartialAttribute {
            atype: "displayName".to_string(),
            vals: vec![directory.display_name.as_bytes().to_vec()],
        },
    ];
    if directory.include_member_of {
        let values = directory
            .groups
            .iter()
            .map(|group_name| {
                if directory.membership_values_are_dns {
                    directory.group_dn(group_name, base_dn).into_bytes()
                } else {
                    group_name.as_bytes().to_vec()
                }
            })
            .collect::<Vec<_>>();
        if !values.is_empty() {
            attributes.push(LdapPartialAttribute {
                atype: directory.membership_attribute_name.clone(),
                vals: values,
            });
        }
    }
    LdapSearchResultEntry {
        dn: user_dn.to_string(),
        attributes,
    }
}

fn ldap_group_entry_with_name(
    group_dn: &str,
    user_dn: &str,
    group_name: &str,
    group_name_attribute: &str,
) -> LdapSearchResultEntry {
    LdapSearchResultEntry {
        dn: group_dn.to_string(),
        attributes: vec![
            LdapPartialAttribute {
                atype: group_name_attribute.to_string(),
                vals: vec![group_name.as_bytes().to_vec()],
            },
            LdapPartialAttribute {
                atype: "member".to_string(),
                vals: vec![user_dn.as_bytes().to_vec()],
            },
        ],
    }
}

async fn handle_mock_ldap_connection(
    stream: tokio::net::TcpStream,
    base_dn: &str,
    directory: &MockLdapDirectory,
) -> Result<(), String> {
    let user_dn = directory.user_dn(base_dn);
    let mut framed = Framed::new(stream, ldap3_proto::LdapCodec::default());
    while let Some(result) = framed.next().await {
        let message = result.map_err(|err| format!("decode ldap frame failed: {err}"))?;
        let op =
            ServerOps::try_from(message).map_err(|_| "unsupported ldap operation".to_string())?;
        match op {
            ServerOps::SimpleBind(request) => {
                let response = if request.dn.is_empty() {
                    request.gen_success()
                } else if directory
                    .bind_dn
                    .as_deref()
                    .is_some_and(|bind_dn| request.dn.eq_ignore_ascii_case(bind_dn))
                    && directory.bind_password.as_deref().unwrap_or_default() == request.pw
                {
                    request.gen_success()
                } else if request.dn.eq_ignore_ascii_case(&user_dn)
                    && request.pw == directory.password
                {
                    request.gen_success()
                } else {
                    request.gen_invalid_cred()
                };
                framed
                    .send(response)
                    .await
                    .map_err(|err| format!("write ldap bind response failed: {err}"))?;
            }
            ServerOps::Search(request) => {
                if ldap_dn_within_base(&user_dn, &request.base)
                    && ldap_filter_matches(&request.filter, "uid", &directory.username)
                {
                    framed
                        .send(request.gen_result_entry(ldap_user_entry_with_directory(
                            &user_dn, directory, base_dn,
                        )))
                        .await
                        .map_err(|err| format!("write ldap user search entry failed: {err}"))?;
                } else if directory.enable_group_search
                    && ldap_filter_matches(&request.filter, "member", &user_dn)
                {
                    for group_name in &directory.groups {
                        let group_dn = directory.group_dn(group_name, base_dn);
                        if !ldap_dn_within_base(&group_dn, &request.base) {
                            continue;
                        }
                        framed
                            .send(request.gen_result_entry(ldap_group_entry_with_name(
                                &group_dn,
                                &user_dn,
                                group_name,
                                &directory.group_name_attribute,
                            )))
                            .await
                            .map_err(|err| {
                                format!("write ldap group search entry failed: {err}")
                            })?;
                    }
                }
                framed
                    .send(request.gen_success())
                    .await
                    .map_err(|err| format!("write ldap search done failed: {err}"))?;
            }
            ServerOps::Unbind(_) => return Ok(()),
            ServerOps::Whoami(request) => {
                framed
                    .send(ldap3_proto::LdapMsg {
                        msgid: request.msgid,
                        op: ldap3_proto::proto::LdapOp::ExtendedResponse(
                            ldap3_proto::proto::LdapExtendedResponse {
                                res: ldap3_proto::proto::LdapResult {
                                    code: ldap3_proto::proto::LdapResultCode::Success,
                                    matcheddn: String::new(),
                                    message: String::new(),
                                    referral: vec![],
                                },
                                name: Some("1.3.6.1.4.1.4203.1.11.3".to_string()),
                                value: Some(format!("dn:{user_dn}").into_bytes()),
                            },
                        ),
                        ctrl: vec![],
                    })
                    .await
                    .map_err(|err| format!("write ldap whoami response failed: {err}"))?;
            }
            ServerOps::Compare(request) => {
                let matches_group = directory.groups.iter().any(|group_name| {
                    request
                        .entry
                        .eq_ignore_ascii_case(&directory.group_dn(group_name, base_dn))
                        && request.atype.eq_ignore_ascii_case("member")
                        && request.val == user_dn
                });
                let response = if matches_group {
                    request.gen_compare_true()
                } else {
                    request.gen_compare_false()
                };
                framed
                    .send(response)
                    .await
                    .map_err(|err| format!("write ldap compare response failed: {err}"))?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct OidcClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    nbf: i64,
    iat: i64,
    preferred_username: String,
    name: String,
    groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

fn encode_mock_oidc_token<T: Serialize>(signing: &MockOidcSigningKey, claims: &T) -> String {
    let mut jwt_header = Header::new(signing.algorithm());
    jwt_header.kid = Some("oidc-key-1".to_string());
    encode(&jwt_header, claims, &signing.encoding_key()).expect("failed to encode mock oidc token")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_via_discovery_and_jwks_succeeds() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-shared-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var(
        "RUSTIO_OIDC_GROUP_ROLE_MAP",
        "platform-admins=admin,security=audit",
    );
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let claims = OidcClaims {
        iss: oidc.base_url.clone(),
        sub: "oidc-user-001".to_string(),
        aud: "rustio-console".to_string(),
        exp: (now + ChronoDuration::minutes(10)).timestamp(),
        nbf: (now - ChronoDuration::minutes(1)).timestamp(),
        iat: now.timestamp(),
        preferred_username: "oidc-admin".to_string(),
        name: "OIDC Admin".to_string(),
        groups: vec!["platform-admins".to_string()],
        nonce: None,
    };
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &claims,
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode oidc token");

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc login request failed");
    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .expect("oidc login response body should be readable");
    assert_eq!(
        response_status,
        StatusCode::OK,
        "unexpected oidc login response body: {response_body}"
    );
    let payload = serde_json::from_str::<serde_json::Value>(&response_body)
        .expect("failed to decode oidc login response");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );
    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-admin")
        .expect("external oidc user should be synced");
    assert_eq!(user.role, "admin");
    assert_eq!(user.display_name, "OIDC Admin");
    drop(users);

    let groups = admin.state.groups.read().await;
    let group = groups
        .iter()
        .find(|group| group.name == "platform-admins")
        .expect("external oidc group should be synced");
    assert!(
        group.members.iter().any(|member| member == "oidc-admin"),
        "external oidc user should be joined into synced group"
    );
    drop(groups);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_supports_email_fallback_and_audience_array() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-email-fallback-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let id_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret),
        &json!({
            "iss": oidc.base_url,
            "sub": "oidc-email-user-001",
            "aud": ["rustio-console", "account"],
            "exp": (now + ChronoDuration::minutes(10)).timestamp(),
            "nbf": (now - ChronoDuration::minutes(1)).timestamp(),
            "iat": now.timestamp(),
            "email": "oidc-email-user@example.internal",
            "name": "OIDC Email User",
            "groups": ["platform-admins"]
        }),
    );

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc email fallback login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc email fallback payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-email-user@example.internal")
        .expect("oidc email fallback user should be synced");
    assert_eq!(user.display_name, "OIDC Email User");
    assert_eq!(user.role, "admin");
    drop(users);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_falls_back_to_subject_when_username_and_email_missing() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-sub-fallback-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let id_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret),
        &json!({
            "iss": oidc.base_url,
            "sub": "oidc-subject-fallback-001",
            "aud": "rustio-console",
            "exp": (now + ChronoDuration::minutes(10)).timestamp(),
            "nbf": (now - ChronoDuration::minutes(1)).timestamp(),
            "iat": now.timestamp(),
            "name": "OIDC Subject Fallback User"
        }),
    );

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc sub fallback login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc sub fallback payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-subject-fallback-001")
        .expect("oidc subject fallback user should be synced");
    assert_eq!(user.display_name, "OIDC Subject Fallback User");
    assert_eq!(user.role, "viewer");
    drop(users);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_supports_nested_claim_paths_and_explicit_role_override() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-nested-claims-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_USERNAME_CLAIM", "custom.username");
    std::env::set_var("RUSTIO_OIDC_GROUPS_CLAIM", "realm_access.roles");
    std::env::set_var("RUSTIO_OIDC_ROLE_CLAIM", "custom.role");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &json!({
            "iss": oidc.base_url,
            "sub": "oidc-nested-user-001",
            "aud": "rustio-console",
            "exp": (now + ChronoDuration::minutes(10)).timestamp(),
            "nbf": (now - ChronoDuration::minutes(1)).timestamp(),
            "iat": now.timestamp(),
            "name": "OIDC Nested Claims User",
            "custom": {
                "username": "oidc-nested-user",
                "role": "auditor"
            },
            "realm_access": {
                "roles": ["platform-admins", "ops"]
            }
        }),
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode oidc nested claims token");

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc nested claims login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc nested claims login payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("auditor")
    );

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-nested-user")
        .expect("oidc nested claims user should be synced");
    assert_eq!(user.display_name, "OIDC Nested Claims User");
    assert_eq!(user.role, "auditor");
    drop(users);

    let groups = admin.state.groups.read().await;
    let platform_admins = groups
        .iter()
        .find(|group| group.name == "platform-admins")
        .expect("oidc nested claims platform-admins group should be synced");
    assert!(
        platform_admins
            .members
            .iter()
            .any(|member| member == "oidc-nested-user"),
        "oidc nested claims user should be joined into mapped group"
    );
    let ops = groups
        .iter()
        .find(|group| group.name == "ops")
        .expect("oidc nested claims ops group should be synced");
    assert!(
        ops.members
            .iter()
            .any(|member| member == "oidc-nested-user"),
        "oidc nested claims user should be joined into all synced groups"
    );
    drop(groups);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_prefers_group_role_mapping_order_when_multiple_groups_match() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-group-order-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var(
        "RUSTIO_OIDC_GROUP_ROLE_MAP",
        "auditors=auditor,ops=operator",
    );
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let id_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret),
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-group-order-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-group-order-user".to_string(),
            name: "OIDC Group Order User".to_string(),
            groups: vec!["ops".to_string(), "auditors".to_string()],
            nonce: None,
        },
    );

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc group order login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc group order payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("auditor")
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_prefers_env_groups_claim_over_runtime_security_config() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-env-groups-claim-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_GROUPS_CLAIM", "realm_access.roles");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    {
        let mut security = admin.state.security.write().await;
        security.oidc_enabled = true;
        security.oidc_discovery_url = format!("{}/.well-known/openid-configuration", oidc.base_url);
        security.oidc_client_id = "rustio-console".to_string();
        security.oidc_groups_claim = "wrong.path".to_string();
        security.oidc_group_role_map = "platform-admins=admin".to_string();
        security.oidc_default_role = "viewer".to_string();
    }

    let now = Utc::now();
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &json!({
            "iss": oidc.base_url,
            "sub": "oidc-env-group-claim-001",
            "aud": "rustio-console",
            "exp": (now + ChronoDuration::minutes(10)).timestamp(),
            "nbf": (now - ChronoDuration::minutes(1)).timestamp(),
            "iat": now.timestamp(),
            "preferred_username": "oidc-env-group-claim-user",
            "name": "OIDC Env Group Claim User",
            "realm_access": {
                "roles": ["platform-admins"]
            }
        }),
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode oidc env groups claim token");

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc env groups claim login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc env groups claim payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );

    let synced_user = admin
        .state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == "oidc-env-group-claim-user")
        .cloned()
        .expect("oidc env groups claim user should be synced");
    assert_eq!(synced_user.role, "admin");

    std::env::remove_var("RUSTIO_OIDC_DISCOVERY_URL");
    std::env::remove_var("RUSTIO_OIDC_CLIENT_ID");
    std::env::remove_var("RUSTIO_OIDC_GROUPS_CLAIM");
    std::env::remove_var("RUSTIO_OIDC_GROUP_ROLE_MAP");
    std::env::remove_var("RUSTIO_OIDC_DEFAULT_ROLE");
    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_prefers_env_username_claim_over_runtime_security_config() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-env-username-claim-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_USERNAME_CLAIM", "custom.username");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    {
        let mut security = admin.state.security.write().await;
        security.oidc_enabled = true;
        security.oidc_discovery_url = format!("{}/.well-known/openid-configuration", oidc.base_url);
        security.oidc_client_id = "rustio-console".to_string();
        security.oidc_username_claim = "wrong.path".to_string();
        security.oidc_default_role = "viewer".to_string();
    }

    let now = Utc::now();
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &json!({
            "iss": oidc.base_url,
            "sub": "oidc-env-username-claim-001",
            "aud": "rustio-console",
            "exp": (now + ChronoDuration::minutes(10)).timestamp(),
            "nbf": (now - ChronoDuration::minutes(1)).timestamp(),
            "iat": now.timestamp(),
            "name": "OIDC Env Username Claim User",
            "custom": {
                "username": "oidc-env-username-user"
            }
        }),
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode oidc env username claim token");

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc env username claim login request failed");
    assert_eq!(response.status(), StatusCode::OK);

    let synced_user = admin
        .state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == "oidc-env-username-user")
        .cloned()
        .expect("oidc env username claim user should be synced");
    assert_eq!(synced_user.display_name, "OIDC Env Username Claim User");
    assert_eq!(synced_user.role, "viewer");

    std::env::remove_var("RUSTIO_OIDC_DISCOVERY_URL");
    std::env::remove_var("RUSTIO_OIDC_CLIENT_ID");
    std::env::remove_var("RUSTIO_OIDC_USERNAME_CLAIM");
    std::env::remove_var("RUSTIO_OIDC_DEFAULT_ROLE");
    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_via_discovery_and_jwks_rs256_succeeds() {
    let admin = AdminServer::spawn().await;
    let signing = MockOidcSigningKey::Rs256;
    let oidc = MockOidcServer::spawn_with_signing(signing.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "RS256");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let id_token = encode_mock_oidc_token(
        &signing,
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-rs256-user-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-rs256-admin".to_string(),
            name: "OIDC RS256 Admin".to_string(),
            groups: vec!["platform-admins".to_string()],
            nonce: None,
        },
    );

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc rs256 login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc rs256 login payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-rs256-admin")
        .expect("oidc rs256 user should be synced");
    assert_eq!(user.role, "admin");
    assert_eq!(user.display_name, "OIDC RS256 Admin");
    drop(users);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_rejects_issuer_mismatch_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-issuer-mismatch-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");

    let now = Utc::now();
    let id_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret),
        &OidcClaims {
            iss: "https://issuer-mismatch.example.internal".to_string(),
            sub: "oidc-issuer-mismatch-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-issuer-mismatch-user".to_string(),
            name: "OIDC Issuer Mismatch User".to_string(),
            groups: vec!["platform-admins".to_string()],
            nonce: None,
        },
    );

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc issuer mismatch login request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response
        .text()
        .await
        .expect("oidc issuer mismatch body should be readable");
    assert!(
        body.contains("OIDC Token 校验失败") && body.contains("oidc token validation failed"),
        "unexpected oidc issuer mismatch body: {body}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_rejects_audience_mismatch_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-audience-mismatch-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");

    let now = Utc::now();
    let id_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret),
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-audience-mismatch-001".to_string(),
            aud: "unexpected-client-id".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-audience-mismatch-user".to_string(),
            name: "OIDC Audience Mismatch User".to_string(),
            groups: vec!["platform-admins".to_string()],
            nonce: None,
        },
    );

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc audience mismatch login request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response
        .text()
        .await
        .expect("oidc audience mismatch body should be readable");
    assert!(
        body.contains("OIDC Token 校验失败") && body.contains("oidc token validation failed"),
        "unexpected oidc audience mismatch body: {body}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_rejects_disallowed_signing_algorithm_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-disallowed-alg-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "RS256");

    let now = Utc::now();
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-bad-alg-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-bad-alg-user".to_string(),
            name: "OIDC Bad Alg User".to_string(),
            groups: vec!["platform-admins".to_string()],
            nonce: None,
        },
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode oidc disallowed alg token");

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": id_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc disallowed alg login request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response
        .text()
        .await
        .expect("oidc disallowed alg body should be readable");
    assert!(
        body.contains("OIDC Token 签名算法不受支持")
            && body.contains("oidc token signing algorithm is unsupported"),
        "unexpected oidc disallowed alg body: {body}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorization_code_rejects_nonce_mismatch_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let oidc = MockOidcServer::spawn_with_signing_and_behavior(
        MockOidcSigningKey::Es256,
        MockOidcBehavior {
            token_nonce_override: Some("unexpected-nonce".to_string()),
            ..MockOidcBehavior::default()
        },
    )
    .await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "ES256");

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client for nonce mismatch");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc nonce mismatch authorize request failed");
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let authorize_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc nonce mismatch authorize location should exist")
        .to_string();

    let provider_response = no_redirect_client
        .get(&authorize_location)
        .send()
        .await
        .expect("oidc nonce mismatch provider authorize request failed");
    assert_eq!(provider_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_location = provider_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc nonce mismatch callback location should exist")
        .to_string();

    let callback_response = no_redirect_client
        .get(&callback_location)
        .send()
        .await
        .expect("oidc nonce mismatch callback request failed");
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let console_location = callback_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc nonce mismatch console redirect should exist")
        .to_string();
    let decoded_location = percent_decode_str(&console_location).decode_utf8_lossy();
    assert!(
        decoded_location.contains("/login/oidc/callback?error=")
            && decoded_location.contains("OIDC Token nonce 不匹配")
            && decoded_location.contains("oidc token nonce does not match"),
        "unexpected oidc nonce mismatch redirect: {decoded_location}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorize_honors_custom_scopes() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-browser-scopes-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var(
        "RUSTIO_OIDC_SCOPES",
        "openid profile email groups offline_access",
    );

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc custom scopes authorize request failed");
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let authorize_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc custom scopes authorize redirect location should exist");
    assert_eq!(
        decode_query_param(authorize_location, "scope").as_deref(),
        Some("openid profile email groups offline_access")
    );

    std::env::remove_var("RUSTIO_OIDC_DISCOVERY_URL");
    std::env::remove_var("RUSTIO_OIDC_CLIENT_ID");
    std::env::remove_var("RUSTIO_OIDC_SCOPES");
    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_callback_rejects_provider_error_with_bilingual_message() {
    let admin = AdminServer::spawn().await;

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client");

    let response = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/callback?error=access_denied&error_description=mock%20access%20denied",
            admin.base_url
        ))
        .send()
        .await
        .expect("oidc callback provider error request failed");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc callback provider error redirect location should exist");
    assert!(
        location.starts_with("/login/oidc/callback?error="),
        "oidc callback provider error should redirect back to console route"
    );
    let decoded_error =
        decode_redirect_error(location).expect("oidc callback provider error should be encoded");
    assert!(
        decoded_error.contains("OIDC 浏览器登录失败")
            && decoded_error.contains("oidc browser login failed")
            && decoded_error.contains("mock access denied"),
        "unexpected oidc callback provider error: {decoded_error}"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_callback_rejects_missing_code_with_bilingual_message() {
    let admin = AdminServer::spawn().await;

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client");

    let response = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/callback?state=mock-state",
            admin.base_url
        ))
        .send()
        .await
        .expect("oidc callback missing code request failed");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc callback missing code redirect location should exist");
    let decoded_error =
        decode_redirect_error(location).expect("oidc callback missing code should be encoded");
    assert!(
        decoded_error.contains("OIDC 回调缺少 code")
            && decoded_error.contains("oidc callback is missing authorization code"),
        "unexpected oidc callback missing code error: {decoded_error}"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_callback_rejects_missing_state_with_bilingual_message() {
    let admin = AdminServer::spawn().await;

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client");

    let response = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/callback?code=mock-code",
            admin.base_url
        ))
        .send()
        .await
        .expect("oidc callback missing state request failed");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc callback missing state redirect location should exist");
    let decoded_error =
        decode_redirect_error(location).expect("oidc callback missing state should be encoded");
    assert!(
        decoded_error.contains("OIDC 回调缺少 state")
            && decoded_error.contains("oidc callback is missing state"),
        "unexpected oidc callback missing state error: {decoded_error}"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_callback_rejects_unknown_state_with_bilingual_message() {
    let admin = AdminServer::spawn().await;

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client");

    let response = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/callback?code=mock-code&state=unknown-state",
            admin.base_url
        ))
        .send()
        .await
        .expect("oidc callback unknown state request failed");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc callback unknown state redirect location should exist");
    let decoded_error =
        decode_redirect_error(location).expect("oidc callback unknown state should be encoded");
    assert!(
        decoded_error.contains("OIDC 登录状态不存在或已过期")
            && decoded_error.contains("oidc login state does not exist or has expired"),
        "unexpected oidc callback unknown state error: {decoded_error}"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorization_code_rejects_token_endpoint_error_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let oidc = MockOidcServer::spawn_with_signing_and_behavior(
        MockOidcSigningKey::Es256,
        MockOidcBehavior {
            token_status_override: Some(StatusCode::BAD_GATEWAY),
            ..MockOidcBehavior::default()
        },
    )
    .await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "ES256");

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client for token endpoint error");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc token endpoint error authorize request failed");
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let authorize_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc token endpoint error authorize location should exist")
        .to_string();

    let provider_response = no_redirect_client
        .get(&authorize_location)
        .send()
        .await
        .expect("oidc token endpoint error provider request failed");
    assert_eq!(provider_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_location = provider_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc token endpoint error callback location should exist")
        .to_string();

    let callback_response = no_redirect_client
        .get(&callback_location)
        .send()
        .await
        .expect("oidc token endpoint error callback request failed");
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let console_location = callback_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc token endpoint error console redirect should exist")
        .to_string();
    let decoded_location = percent_decode_str(&console_location).decode_utf8_lossy();
    assert!(
        decoded_location.contains("/login/oidc/callback?error=")
            && decoded_location.contains("OIDC 授权码换取令牌失败")
            && decoded_location.contains("oidc authorization code exchange failed"),
        "unexpected oidc token endpoint error redirect: {decoded_location}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorization_code_rejects_missing_id_token_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let oidc = MockOidcServer::spawn_with_signing_and_behavior(
        MockOidcSigningKey::Es256,
        MockOidcBehavior {
            omit_id_token: true,
            ..MockOidcBehavior::default()
        },
    )
    .await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "ES256");

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client for missing id token");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc missing id token authorize request failed");
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let authorize_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc missing id token authorize location should exist")
        .to_string();

    let provider_response = no_redirect_client
        .get(&authorize_location)
        .send()
        .await
        .expect("oidc missing id token provider request failed");
    assert_eq!(provider_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_location = provider_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc missing id token callback location should exist")
        .to_string();

    let callback_response = no_redirect_client
        .get(&callback_location)
        .send()
        .await
        .expect("oidc missing id token callback request failed");
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let console_location = callback_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc missing id token console redirect should exist")
        .to_string();
    let decoded_location = percent_decode_str(&console_location).decode_utf8_lossy();
    assert!(
        decoded_location.contains("/login/oidc/callback?error=")
            && decoded_location.contains("OIDC Token 响应缺少 ID Token")
            && decoded_location.contains("oidc token response does not contain id token"),
        "unexpected oidc missing id token redirect: {decoded_location}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorization_code_with_pkce_es256_succeeds() {
    let admin = AdminServer::spawn().await;
    let oidc = MockOidcServer::spawn_with_signing(MockOidcSigningKey::Es256).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "ES256");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client for es256");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc es256 authorize request failed");
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let authorize_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc es256 authorize location should exist")
        .to_string();
    assert!(
        authorize_location.starts_with(&format!("{}/authorize?", oidc.base_url)),
        "oidc es256 authorize redirect should point to provider"
    );

    let provider_response = no_redirect_client
        .get(&authorize_location)
        .send()
        .await
        .expect("oidc es256 provider authorize redirect failed");
    assert_eq!(provider_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_location = provider_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc es256 callback location should exist")
        .to_string();

    let callback_response = no_redirect_client
        .get(&callback_location)
        .send()
        .await
        .expect("oidc es256 callback request failed");
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let console_location = callback_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc es256 console redirect should exist")
        .to_string();
    assert!(
        console_location.starts_with("/login/oidc/callback?request_id="),
        "oidc es256 callback should redirect back to console route"
    );
    let request_id = console_location
        .split("request_id=")
        .nth(1)
        .and_then(|value| value.split('&').next())
        .expect("oidc es256 request_id should exist");

    let redeem_response = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/session/{}",
            admin.base_url, request_id
        ))
        .send()
        .await
        .expect("oidc es256 redeem request failed");
    assert_eq!(redeem_response.status(), StatusCode::OK);
    let payload = redeem_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc es256 redeemed payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-browser-admin")
        .expect("oidc es256 browser user should be synced");
    assert_eq!(user.role, "admin");
    drop(users);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorization_code_forwards_client_secret() {
    let admin = AdminServer::spawn().await;
    let client_secret = "browser-oidc-client-secret".to_string();
    let oidc = MockOidcServer::spawn_with_signing_and_behavior(
        MockOidcSigningKey::Es256,
        MockOidcBehavior {
            expected_client_secret: Some(client_secret.clone()),
            ..MockOidcBehavior::default()
        },
    )
    .await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_CLIENT_SECRET", &client_secret);
    std::env::set_var("RUSTIO_OIDC_ALLOWED_ALGS", "ES256");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client for client secret forwarding");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc client secret authorize request failed");
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let authorize_location = authorize_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc client secret authorize location should exist")
        .to_string();

    let provider_response = no_redirect_client
        .get(&authorize_location)
        .send()
        .await
        .expect("oidc client secret provider request failed");
    assert_eq!(provider_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_location = provider_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc client secret callback location should exist")
        .to_string();

    let callback_response = no_redirect_client
        .get(&callback_location)
        .send()
        .await
        .expect("oidc client secret callback request failed");
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let console_location = callback_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("oidc client secret console redirect should exist")
        .to_string();
    assert!(
        console_location.starts_with("/login/oidc/callback?request_id="),
        "oidc client secret callback should redirect back to console route"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_browser_authorization_code_with_pkce_succeeds() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-browser-shared-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let no_redirect_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .expect("failed to build no redirect client");

    let authorize_response = no_redirect_client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .send()
        .await
        .expect("oidc authorize request failed");
    let authorize_status = authorize_response.status();
    let authorize_headers = authorize_response.headers().clone();
    let authorize_body = authorize_response
        .text()
        .await
        .expect("authorize response body should be readable");
    assert_eq!(
        authorize_status,
        StatusCode::TEMPORARY_REDIRECT,
        "unexpected authorize response body: {authorize_body}"
    );
    let authorize_location = authorize_headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorize redirect location should exist")
        .to_string();
    assert!(
        authorize_location.starts_with(&format!("{}/authorize?", oidc.base_url)),
        "authorize redirect should point to oidc provider"
    );

    let provider_response = no_redirect_client
        .get(&authorize_location)
        .send()
        .await
        .expect("provider authorize redirect failed");
    assert_eq!(provider_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let callback_location = provider_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("provider callback redirect should exist")
        .to_string();
    assert!(
        callback_location.contains("/api/v1/auth/oidc/callback?"),
        "provider redirect should return to admin callback"
    );

    let callback_response = no_redirect_client
        .get(&callback_location)
        .send()
        .await
        .expect("admin oidc callback failed");
    assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let console_location = callback_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("console redirect should exist")
        .to_string();
    assert!(
        console_location.starts_with("/login/oidc/callback?request_id="),
        "callback should redirect back to console route"
    );

    let request_id = console_location
        .split("request_id=")
        .nth(1)
        .and_then(|value| value.split('&').next())
        .expect("request_id should exist in callback redirect");
    let redeem_response = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/session/{}",
            admin.base_url, request_id
        ))
        .send()
        .await
        .expect("redeem oidc session failed");
    assert_eq!(redeem_response.status(), StatusCode::OK);
    let payload = redeem_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode redeemed oidc session");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );

    let second_redeem = no_redirect_client
        .get(format!(
            "{}/api/v1/auth/oidc/session/{}",
            admin.base_url, request_id
        ))
        .send()
        .await
        .expect("second redeem oidc session failed");
    assert_eq!(second_redeem.status(), StatusCode::NOT_FOUND);

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-browser-admin")
        .expect("browser oidc user should be synced");
    assert_eq!(user.role, "admin");
    assert_eq!(user.display_name, "OIDC Browser Admin");
    drop(users);

    let groups = admin.state.groups.read().await;
    let group = groups
        .iter()
        .find(|group| group.name == "platform-admins")
        .expect("browser oidc group should be synced");
    assert!(
        group
            .members
            .iter()
            .any(|member| member == "oidc-browser-admin"),
        "browser oidc user should be joined into synced group"
    );
    drop(groups);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_relogin_reconciles_groups_and_effective_permissions() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-resync-shared-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());

    let initial_token = encode(
        &jwt_header,
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-user-resync-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-resync-user".to_string(),
            name: "OIDC Resync User".to_string(),
            groups: vec!["platform-admins".to_string()],
            nonce: None,
        },
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode initial oidc token");

    let initial_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": initial_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("initial oidc relogin request failed");
    assert_eq!(initial_login.status(), StatusCode::OK);
    let initial_payload = initial_login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode initial oidc relogin payload");
    assert_eq!(
        initial_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );
    let initial_access_token = initial_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("initial oidc relogin access token should exist")
        .to_string();

    let topology_before = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&initial_access_token)
        .send()
        .await
        .expect("topology before oidc relogin drift request failed");
    assert_eq!(topology_before.status(), StatusCode::OK);

    let downgraded_token = encode(
        &jwt_header,
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-user-resync-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-resync-user".to_string(),
            name: "OIDC Resync User".to_string(),
            groups: Vec::new(),
            nonce: None,
        },
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode downgraded oidc token");

    let downgraded_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": downgraded_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("downgraded oidc relogin request failed");
    assert_eq!(downgraded_login.status(), StatusCode::OK);
    let downgraded_payload = downgraded_login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode downgraded oidc relogin payload");
    assert_eq!(
        downgraded_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );
    let downgraded_access_token = downgraded_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("downgraded oidc relogin access token should exist")
        .to_string();

    let topology_with_old_token = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&initial_access_token)
        .send()
        .await
        .expect("topology with old oidc token after drift request failed");
    assert_eq!(topology_with_old_token.status(), StatusCode::FORBIDDEN);

    let topology_with_new_token = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&downgraded_access_token)
        .send()
        .await
        .expect("topology with downgraded oidc token request failed");
    assert_eq!(topology_with_new_token.status(), StatusCode::FORBIDDEN);

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "oidc-resync-user")
        .expect("oidc relogin user should be synced");
    assert_eq!(user.role, "viewer");
    drop(users);

    let groups = admin.state.groups.read().await;
    let platform_admins = groups
        .iter()
        .find(|group| group.name == "platform-admins")
        .expect("oidc relogin group should still exist");
    assert!(
        !platform_admins
            .members
            .iter()
            .any(|member| member == "oidc-resync-user"),
        "oidc relogin should remove stale external group membership"
    );
    drop(groups);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_refresh_uses_latest_role_after_external_relogin() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-refresh-role-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;

    std::env::set_var(
        "RUSTIO_OIDC_DISCOVERY_URL",
        format!("{}/.well-known/openid-configuration", oidc.base_url),
    );
    std::env::set_var("RUSTIO_OIDC_CLIENT_ID", "rustio-console");
    std::env::set_var("RUSTIO_OIDC_GROUP_ROLE_MAP", "platform-admins=admin");
    std::env::set_var("RUSTIO_OIDC_DEFAULT_ROLE", "viewer");

    let now = Utc::now();
    let initial_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret.clone()),
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-refresh-role-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-refresh-role-user".to_string(),
            name: "OIDC Refresh Role User".to_string(),
            groups: vec!["platform-admins".to_string()],
            nonce: None,
        },
    );

    let initial_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": initial_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("initial oidc refresh-role login request failed");
    assert_eq!(initial_login.status(), StatusCode::OK);
    let initial_payload = initial_login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode initial oidc refresh-role payload");
    assert_eq!(
        initial_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("admin")
    );
    let old_refresh_token = initial_payload
        .pointer("/data/refresh_token")
        .and_then(|value| value.as_str())
        .expect("oidc old refresh token should exist")
        .to_string();

    let downgraded_token = encode_mock_oidc_token(
        &MockOidcSigningKey::hs256(oidc_secret),
        &OidcClaims {
            iss: oidc.base_url.clone(),
            sub: "oidc-refresh-role-001".to_string(),
            aud: "rustio-console".to_string(),
            exp: (now + ChronoDuration::minutes(10)).timestamp(),
            nbf: (now - ChronoDuration::minutes(1)).timestamp(),
            iat: now.timestamp(),
            preferred_username: "oidc-refresh-role-user".to_string(),
            name: "OIDC Refresh Role User".to_string(),
            groups: Vec::new(),
            nonce: None,
        },
    );

    let downgraded_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": downgraded_token,
            })
            .to_string(),
        )
        .send()
        .await
        .expect("downgraded oidc refresh-role login request failed");
    assert_eq!(downgraded_login.status(), StatusCode::OK);
    let downgraded_payload = downgraded_login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode downgraded oidc refresh-role payload");
    assert_eq!(
        downgraded_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );

    let refresh_response = admin
        .client
        .post(format!("{}/api/v1/auth/refresh", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": old_refresh_token }).to_string())
        .send()
        .await
        .expect("oidc refresh-role refresh request failed");
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_payload = refresh_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode oidc refresh-role refresh payload");
    assert_eq!(
        refresh_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );
    let refreshed_access_token = refresh_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("oidc refreshed access token should exist")
        .to_string();

    let topology = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(refreshed_access_token)
        .send()
        .await
        .expect("oidc refreshed topology request failed");
    assert_eq!(topology.status(), StatusCode::FORBIDDEN);

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_and_logout_govern_console_sessions() {
    let admin = AdminServer::spawn().await;
    let login_payload = admin.login_response().await;
    let access_token = login_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("access token should exist")
        .to_string();
    let refresh_token = login_payload
        .pointer("/data/refresh_token")
        .and_then(|value| value.as_str())
        .expect("refresh token should exist")
        .to_string();
    let session_id = login_payload
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("session id should exist")
        .to_string();

    {
        let sessions = admin.state.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .expect("console session should be stored");
        assert_eq!(session.status, "active");
        assert_eq!(session.provider, "local");
    }

    let refresh_response = admin
        .client
        .post(format!("{}/api/v1/auth/refresh", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": refresh_token }).to_string())
        .send()
        .await
        .expect("refresh request failed");
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_payload = refresh_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode refresh response");
    assert_eq!(
        refresh_payload
            .pointer("/data/session_id")
            .and_then(|value| value.as_str()),
        Some(session_id.as_str())
    );
    let refreshed_access_token = refresh_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("refreshed access token should exist")
        .to_string();

    let health_response = admin
        .client
        .get(format!("{}/api/v1/cluster/health", admin.base_url))
        .bearer_auth(&refreshed_access_token)
        .send()
        .await
        .expect("cluster health request failed");
    assert_eq!(health_response.status(), StatusCode::OK);

    {
        let sessions = admin.state.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .expect("refreshed console session should exist");
        assert!(session.last_refreshed_at.is_some());
    }

    let logout_response = admin
        .client
        .post(format!("{}/api/v1/auth/logout", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("logout request failed");
    assert_eq!(logout_response.status(), StatusCode::OK);

    let revoked_access = admin
        .client
        .get(format!("{}/api/v1/cluster/health", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("revoked access token request failed");
    assert_eq!(revoked_access.status(), StatusCode::UNAUTHORIZED);

    let revoked_refresh = admin
        .client
        .post(format!("{}/api/v1/auth/refresh", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": refresh_token }).to_string())
        .send()
        .await
        .expect("revoked refresh token request failed");
    assert_eq!(revoked_refresh.status(), StatusCode::UNAUTHORIZED);

    {
        let sessions = admin.state.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .expect("revoked console session should exist");
        assert_eq!(session.status, "revoked");
        assert!(session.revoked_at.is_some());
    }

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_can_list_and_revoke_console_sessions() {
    let admin = AdminServer::spawn().await;
    let admin_login = admin.login_response().await;
    let admin_access_token = admin_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("admin access token should exist")
        .to_string();

    let create_user_response = admin
        .client
        .post(format!("{}/api/v1/iam/users", admin.base_url))
        .bearer_auth(&admin_access_token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "operator-1",
                "password": "operator-password",
                "display_name": "Operator One",
                "role": "operator"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create user request failed");
    assert_eq!(create_user_response.status(), StatusCode::OK);

    let operator_login = admin
        .login_response_as("operator-1", "operator-password")
        .await;
    let operator_access_token = operator_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("operator access token should exist")
        .to_string();
    let operator_refresh_token = operator_login
        .pointer("/data/refresh_token")
        .and_then(|value| value.as_str())
        .expect("operator refresh token should exist")
        .to_string();
    let operator_session_id = operator_login
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("operator session id should exist")
        .to_string();

    let topology_before_revoke = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("operator topology request failed");
    assert_eq!(topology_before_revoke.status(), StatusCode::OK);

    let list_sessions_response = admin
        .client
        .get(format!("{}/api/v1/auth/sessions", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list console sessions request failed");
    assert_eq!(list_sessions_response.status(), StatusCode::OK);
    let list_sessions_payload = list_sessions_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode list console sessions response");
    let sessions = list_sessions_payload
        .pointer("/data")
        .and_then(|value| value.as_array())
        .expect("console session list should be array");
    let operator_session = sessions
        .iter()
        .find(|session| {
            session
                .pointer("/session_id")
                .and_then(|value| value.as_str())
                == Some(operator_session_id.as_str())
        })
        .expect("operator console session should be visible");
    assert_eq!(
        operator_session
            .pointer("/principal")
            .and_then(|value| value.as_str()),
        Some("operator-1")
    );
    assert_eq!(
        operator_session
            .pointer("/provider")
            .and_then(|value| value.as_str()),
        Some("local")
    );

    let revoke_response = admin
        .client
        .delete(format!(
            "{}/api/v1/auth/sessions/{}",
            admin.base_url, operator_session_id
        ))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("revoke console session request failed");
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let topology_after_revoke = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("operator topology after revoke request failed");
    assert_eq!(topology_after_revoke.status(), StatusCode::UNAUTHORIZED);

    let refresh_after_revoke = admin
        .client
        .post(format!("{}/api/v1/auth/refresh", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": operator_refresh_token }).to_string())
        .send()
        .await
        .expect("operator refresh after revoke request failed");
    assert_eq!(refresh_after_revoke.status(), StatusCode::UNAUTHORIZED);

    {
        let sessions = admin.state.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == operator_session_id)
            .expect("revoked operator session should still exist");
        assert_eq!(session.status, "revoked");
        assert!(session.revoked_at.is_some());
    }

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_user_revokes_existing_console_sessions() {
    let admin = AdminServer::spawn().await;
    let admin_login = admin.login_response().await;
    let admin_access_token = admin_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("admin access token should exist")
        .to_string();

    let create_user_response = admin
        .client
        .post(format!("{}/api/v1/iam/users", admin.base_url))
        .bearer_auth(&admin_access_token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "operator-2",
                "password": "operator-password",
                "display_name": "Operator Two",
                "role": "operator"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create operator user request failed");
    assert_eq!(create_user_response.status(), StatusCode::OK);

    let operator_login = admin
        .login_response_as("operator-2", "operator-password")
        .await;
    let operator_access_token = operator_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("operator access token should exist")
        .to_string();
    let operator_refresh_token = operator_login
        .pointer("/data/refresh_token")
        .and_then(|value| value.as_str())
        .expect("operator refresh token should exist")
        .to_string();
    let operator_session_id = operator_login
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("operator session id should exist")
        .to_string();

    let protected_before_disable = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("operator topology before disable request failed");
    assert_eq!(protected_before_disable.status(), StatusCode::OK);

    let disable_response = admin
        .client
        .post(format!(
            "{}/api/v1/iam/users/{}/disable",
            admin.base_url, "operator-2"
        ))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("disable operator request failed");
    assert_eq!(disable_response.status(), StatusCode::OK);

    let disabled_access = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("disabled operator access request failed");
    assert_eq!(disabled_access.status(), StatusCode::UNAUTHORIZED);

    let disabled_refresh = admin
        .client
        .post(format!("{}/api/v1/auth/refresh", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": operator_refresh_token }).to_string())
        .send()
        .await
        .expect("disabled operator refresh request failed");
    assert_eq!(disabled_refresh.status(), StatusCode::UNAUTHORIZED);

    {
        let sessions = admin.state.admin_sessions.read().await;
        let session = sessions
            .iter()
            .find(|session| session.session_id == operator_session_id)
            .expect("disabled operator session should exist");
        assert_eq!(session.status, "revoked");
        assert_eq!(
            session.revoked_reason.as_deref(),
            Some("用户已禁用 / user disabled")
        );
    }

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_change_takes_effect_for_existing_access_token() {
    let admin = AdminServer::spawn().await;
    let admin_login = admin.login_response().await;
    let admin_access_token = admin_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("admin access token should exist")
        .to_string();

    let create_user_response = admin
        .client
        .post(format!("{}/api/v1/iam/users", admin.base_url))
        .bearer_auth(&admin_access_token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "operator-3",
                "password": "operator-password",
                "display_name": "Operator Three",
                "role": "operator"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create operator user request failed");
    assert_eq!(create_user_response.status(), StatusCode::OK);

    let operator_login = admin
        .login_response_as("operator-3", "operator-password")
        .await;
    let operator_access_token = operator_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("operator access token should exist")
        .to_string();

    let topology_before = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("topology before role change request failed");
    assert_eq!(topology_before.status(), StatusCode::OK);

    {
        let mut users = admin.state.users.write().await;
        let user = users
            .iter_mut()
            .find(|user| user.username == "operator-3")
            .expect("operator user should exist");
        user.role = "viewer".to_string();
    }

    let topology_after = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("topology after role change request failed");
    assert_eq!(topology_after.status(), StatusCode::FORBIDDEN);

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_session_projects_latest_permissions_without_refresh() {
    let admin = AdminServer::spawn().await;
    let admin_access_token = admin.login_access_token().await;

    let create_user = admin
        .client
        .post(format!("{}/api/v1/iam/users", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "username": "operator-4",
            "password": "operator-pass",
            "display_name": "Operator Four",
            "role": "operator"
        }))
        .send()
        .await
        .expect("create operator user request failed");
    assert_eq!(create_user.status(), StatusCode::OK);

    let operator_login = admin.login_response_as("operator-4", "operator-pass").await;
    let operator_access_token = operator_login
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("operator access token should exist")
        .to_string();
    let operator_session_id = operator_login
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("operator session id should exist")
        .to_string();

    {
        let mut users = admin.state.users.write().await;
        let user = users
            .iter_mut()
            .find(|user| user.username == "operator-4")
            .expect("operator user should exist");
        user.role = "viewer".to_string();
    }

    let current_session = admin
        .client
        .get(format!("{}/api/v1/auth/session/current", admin.base_url))
        .bearer_auth(&operator_access_token)
        .send()
        .await
        .expect("current session request failed");
    assert_eq!(current_session.status(), StatusCode::OK);
    let current_payload = current_session
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode current session response");
    assert_eq!(
        current_payload
            .pointer("/data/session_id")
            .and_then(|value| value.as_str()),
        Some(operator_session_id.as_str())
    );
    assert_eq!(
        current_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );
    assert_eq!(
        current_payload
            .pointer("/data/permissions")
            .and_then(|value| value.as_array())
            .map(|value| value.len()),
        Some(0)
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn internal_console_session_delete_removes_runtime_session() {
    let admin = AdminServer::spawn().await;
    let login_payload = admin.login_response().await;
    let session_id = login_payload
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("session id should exist")
        .to_string();

    let response = admin
        .client
        .delete(format!(
            "{}/api/v1/internal/auth/sessions/sync/{}",
            admin.base_url, session_id
        ))
        .header("x-rustio-internal-token", "rustio-internal-token")
        .send()
        .await
        .expect("internal console session delete request failed");
    assert_eq!(response.status(), StatusCode::OK);

    let sessions = admin.state.admin_sessions.read().await;
    assert!(
        sessions
            .iter()
            .all(|session| session.session_id != session_id),
        "runtime console session should be removed after internal delete sync"
    );
    drop(sessions);

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_and_policy_mutations_remain_queryable() {
    let admin = AdminServer::spawn().await;
    let admin_access_token = admin.login_access_token().await;

    let create_user = admin
        .client
        .post(format!("{}/api/v1/iam/users", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "username": "policy-user",
            "password": "policy-pass",
            "display_name": "Policy User",
            "role": "operator"
        }))
        .send()
        .await
        .expect("create policy user request failed");
    assert_eq!(create_user.status(), StatusCode::OK);

    let create_group = admin
        .client
        .post(format!("{}/api/v1/iam/groups", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "name": "ops-team" }))
        .send()
        .await
        .expect("create group request failed");
    assert_eq!(create_group.status(), StatusCode::OK);

    let add_member = admin
        .client
        .post(format!(
            "{}/api/v1/iam/groups/ops-team/members",
            admin.base_url
        ))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "username": "policy-user" }))
        .send()
        .await
        .expect("add group member request failed");
    assert_eq!(add_member.status(), StatusCode::OK);

    let groups = admin
        .client
        .get(format!("{}/api/v1/iam/groups", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list groups request failed");
    assert_eq!(groups.status(), StatusCode::OK);
    let groups_payload = groups
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode groups response");
    assert!(
        groups_payload
            .pointer("/data")
            .and_then(|value| value.as_array())
            .expect("groups list should be array")
            .iter()
            .any(|group| {
                group.get("name").and_then(|value| value.as_str()) == Some("ops-team")
                    && group
                        .get("members")
                        .and_then(|value| value.as_array())
                        .is_some_and(|members| {
                            members
                                .iter()
                                .any(|member| member.as_str() == Some("policy-user"))
                        })
            }),
        "group mutation should remain queryable"
    );

    let remove_member = admin
        .client
        .delete(format!(
            "{}/api/v1/iam/groups/ops-team/members/policy-user",
            admin.base_url
        ))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("remove group member request failed");
    assert_eq!(remove_member.status(), StatusCode::OK);

    let create_policy = admin
        .client
        .post(format!("{}/api/v1/iam/policies", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "name": "bucket-list-policy",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::reports-bucket"]
                    }
                ]
            }
        }))
        .send()
        .await
        .expect("create policy request failed");
    assert_eq!(create_policy.status(), StatusCode::OK);

    let attach_policy = admin
        .client
        .post(format!(
            "{}/api/v1/iam/policies/bucket-list-policy/attach",
            admin.base_url
        ))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "principal": "policy-user" }))
        .send()
        .await
        .expect("attach policy request failed");
    assert_eq!(attach_policy.status(), StatusCode::OK);

    let policies = admin
        .client
        .get(format!("{}/api/v1/iam/policies", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list policies request failed");
    assert_eq!(policies.status(), StatusCode::OK);
    let policies_payload = policies
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode policies response");
    assert!(
        policies_payload
            .pointer("/data")
            .and_then(|value| value.as_array())
            .expect("policies list should be array")
            .iter()
            .any(|policy| {
                policy.get("name").and_then(|value| value.as_str()) == Some("bucket-list-policy")
                    && policy
                        .get("attached_to")
                        .and_then(|value| value.as_array())
                        .is_some_and(|attached_to| {
                            attached_to
                                .iter()
                                .any(|item| item.as_str() == Some("policy-user"))
                        })
            }),
        "policy mutation should remain queryable"
    );

    let detach_policy = admin
        .client
        .post(format!(
            "{}/api/v1/iam/policies/bucket-list-policy/detach",
            admin.base_url
        ))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "principal": "policy-user" }))
        .send()
        .await
        .expect("detach policy request failed");
    assert_eq!(detach_policy.status(), StatusCode::OK);

    let policies_after_detach = admin
        .client
        .get(format!("{}/api/v1/iam/policies", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list policies after detach request failed");
    assert_eq!(policies_after_detach.status(), StatusCode::OK);
    let policies_after_detach_payload = policies_after_detach
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode policies after detach response");
    assert!(
        policies_after_detach_payload
            .pointer("/data")
            .and_then(|value| value.as_array())
            .expect("policies list after detach should be array")
            .iter()
            .any(|policy| {
                policy.get("name").and_then(|value| value.as_str()) == Some("bucket-list-policy")
                    && policy
                        .get("attached_to")
                        .and_then(|value| value.as_array())
                        .is_some_and(|attached_to| attached_to.is_empty())
            }),
        "policy detach should remain queryable"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_account_and_sts_mutations_remain_queryable() {
    let admin = AdminServer::spawn().await;
    let admin_access_token = admin.login_access_token().await;

    let create_user = admin
        .client
        .post(format!("{}/api/v1/iam/users", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "username": "cred-user",
            "password": "cred-pass",
            "display_name": "Credential User",
            "role": "operator"
        }))
        .send()
        .await
        .expect("create credential user request failed");
    assert_eq!(create_user.status(), StatusCode::OK);

    let create_service_account = admin
        .client
        .post(format!("{}/api/v1/iam/service-accounts", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "owner": "cred-user" }))
        .send()
        .await
        .expect("create service account request failed");
    assert_eq!(create_service_account.status(), StatusCode::OK);
    let service_account_payload = create_service_account
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode create service account response");
    let service_access_key = service_account_payload
        .pointer("/data/access_key")
        .and_then(|value| value.as_str())
        .expect("service account access key should exist")
        .to_string();

    let create_sts = admin
        .client
        .post(format!("{}/api/v1/iam/sts/sessions", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "principal": "cred-user", "ttl_minutes": 30 }))
        .send()
        .await
        .expect("create sts request failed");
    assert_eq!(create_sts.status(), StatusCode::OK);
    let sts_payload = create_sts
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode create sts response");
    let sts_session_id = sts_payload
        .pointer("/data/session_id")
        .and_then(|value| value.as_str())
        .expect("sts session id should exist")
        .to_string();

    let delete_sts = admin
        .client
        .delete(format!(
            "{}/api/v1/iam/sts/sessions/{}",
            admin.base_url, sts_session_id
        ))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("delete sts request failed");
    assert_eq!(delete_sts.status(), StatusCode::OK);

    let sts_sessions = admin
        .client
        .get(format!("{}/api/v1/iam/sts/sessions", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list sts sessions request failed");
    assert_eq!(sts_sessions.status(), StatusCode::OK);
    let sts_sessions_payload = sts_sessions
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode sts sessions response");
    assert!(
        sts_sessions_payload
            .pointer("/data")
            .and_then(|value| value.as_array())
            .expect("sts session list should be array")
            .iter()
            .all(
                |item| item.get("session_id").and_then(|value| value.as_str())
                    != Some(sts_session_id.as_str())
            ),
        "deleted sts session should no longer be queryable"
    );

    let delete_service_account = admin
        .client
        .delete(format!(
            "{}/api/v1/iam/service-accounts/{}",
            admin.base_url, service_access_key
        ))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("delete service account request failed");
    assert_eq!(delete_service_account.status(), StatusCode::OK);

    let service_accounts = admin
        .client
        .get(format!("{}/api/v1/iam/service-accounts", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list service accounts request failed");
    assert_eq!(service_accounts.status(), StatusCode::OK);
    let service_accounts_payload = service_accounts
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode service accounts response");
    assert!(
        service_accounts_payload
            .pointer("/data")
            .and_then(|value| value.as_array())
            .expect("service account list should be array")
            .iter()
            .all(
                |item| item.get("access_key").and_then(|value| value.as_str())
                    != Some(service_access_key.as_str())
            ),
        "deleted service account should no longer be queryable"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federated_sts_web_identity_issues_session_and_enforces_inline_policy() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-sts-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;
    configure_mock_oidc_env(&oidc, "rustio-console");
    let admin_access_token = admin.login_access_token().await;
    let bucket = "federated-sts-web";
    let allowed_key = "reports/allowed.txt";
    let denied_key = "reports/denied.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, body) in [(allowed_key, "allowed"), (denied_key, "denied")] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(body.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let create_policy = admin
        .client
        .post(format!("{}/api/v1/iam/policies", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "name": "reports-reader",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [format!("arn:aws:s3:::{bucket}/reports/*")]
                }]
            }
        }))
        .send()
        .await
        .expect("create role policy request failed");
    assert_eq!(create_policy.status(), StatusCode::OK);

    let now = Utc::now();
    let claims = OidcClaims {
        iss: oidc.base_url.clone(),
        sub: "oidc-web-user-001".to_string(),
        aud: "rustio-console".to_string(),
        exp: (now + ChronoDuration::minutes(10)).timestamp(),
        nbf: (now - ChronoDuration::minutes(1)).timestamp(),
        iat: now.timestamp(),
        preferred_username: "oidc-sts-user".to_string(),
        name: "OIDC STS User".to_string(),
        groups: vec!["platform-admins".to_string()],
        nonce: None,
    };
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &claims,
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode oidc sts token");

    let inline_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{allowed_key}")]
        }]
    })
    .to_string();
    let assume_response = admin
        .client
        .post(format!("{}/", admin.base_url))
        .form(&vec![
            (
                "Action".to_string(),
                "AssumeRoleWithWebIdentity".to_string(),
            ),
            ("Version".to_string(), "2011-06-15".to_string()),
            ("WebIdentityToken".to_string(), id_token),
            (
                "RoleArn".to_string(),
                "arn:aws:iam::rustio:role/reports-reader".to_string(),
            ),
            (
                "RoleSessionName".to_string(),
                "oidc-web-session".to_string(),
            ),
            ("DurationSeconds".to_string(), "1800".to_string()),
            ("Policy".to_string(), inline_policy),
        ])
        .send()
        .await
        .expect("assume role with web identity request failed");
    let assume_status = assume_response.status();
    let assume_body = assume_response
        .text()
        .await
        .expect("assume role with web identity response should be readable");
    assert_eq!(
        assume_status,
        StatusCode::OK,
        "unexpected assume role with web identity body: {assume_body}"
    );
    let access_key = xml_tag_text(&assume_body, "AccessKeyId").expect("access key should exist");
    let secret_key =
        xml_tag_text(&assume_body, "SecretAccessKey").expect("secret key should exist");
    let session_token =
        xml_tag_text(&assume_body, "SessionToken").expect("session token should exist");
    assert_eq!(
        xml_tag_text(&assume_body, "SubjectFromWebIdentityToken").as_deref(),
        Some("oidc-web-user-001")
    );
    assert_eq!(
        xml_tag_text(&assume_body, "Audience").as_deref(),
        Some("rustio-console")
    );

    let sts_sessions = admin
        .client
        .get(format!("{}/api/v1/iam/sts/sessions", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list sts sessions request failed");
    assert_eq!(sts_sessions.status(), StatusCode::OK);
    let sts_sessions_payload = sts_sessions
        .json::<Value>()
        .await
        .expect("failed to decode sts sessions response");
    assert!(
        sts_sessions_payload
            .pointer("/data")
            .and_then(Value::as_array)
            .expect("sts sessions should be array")
            .iter()
            .any(|item| {
                item.pointer("/provider") == Some(&json!("oidc"))
                    && item.pointer("/role_arn")
                        == Some(&json!("arn:aws:iam::rustio:role/reports-reader"))
                    && item.pointer("/session_name") == Some(&json!("oidc-web-session"))
                    && item.pointer("/principal") == Some(&json!("oidc-sts-user"))
            }),
        "federated oidc sts session should be queryable with provider metadata"
    );

    let allowed = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, allowed_key))
        .basic_auth(&access_key, Some(&secret_key))
        .header("x-amz-security-token", &session_token)
        .send()
        .await
        .expect("allowed federated sts request failed");
    assert_eq!(allowed.status(), StatusCode::OK);

    let denied = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, denied_key))
        .basic_auth(&access_key, Some(&secret_key))
        .header("x-amz-security-token", &session_token)
        .send()
        .await
        .expect("denied federated sts request failed");
    let denied_status = denied.status();
    let denied_body = denied
        .text()
        .await
        .expect("denied federated sts response should be readable");
    assert_eq!(denied_status, StatusCode::FORBIDDEN);
    assert!(
        denied_body.contains("<Code>AccessDenied</Code>"),
        "unexpected denied federated sts body: {denied_body}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federated_sts_custom_token_bridge_issues_session_with_custom_claim_mapping() {
    let admin = AdminServer::spawn().await;
    let oidc_secret = "oidc-custom-sts-secret".to_string();
    let oidc = MockOidcServer::spawn(oidc_secret.clone()).await;
    configure_mock_oidc_env(&oidc, "rustio-console");
    let admin_access_token = admin.login_access_token().await;
    let bucket = "federated-sts-custom";
    let allowed_key = "reports/custom-allowed.txt";
    let denied_key = "reports/custom-denied.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, body) in [(allowed_key, "allowed"), (denied_key, "denied")] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(body.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let create_policy = admin
        .client
        .post(format!("{}/api/v1/iam/policies", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "name": "reports-custom-reader",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [format!("arn:aws:s3:::{bucket}/reports/*")]
                }]
            }
        }))
        .send()
        .await
        .expect("create custom role policy request failed");
    assert_eq!(create_policy.status(), StatusCode::OK);

    let now = Utc::now();
    let claims = json!({
        "iss": oidc.base_url,
        "sub": "custom-token-user-001",
        "aud": "rustio-console",
        "exp": (now + ChronoDuration::minutes(10)).timestamp(),
        "nbf": (now - ChronoDuration::minutes(1)).timestamp(),
        "iat": now.timestamp(),
        "actor": "custom-sts-user",
        "display": "Custom STS User",
        "entitlements": {
            "teams": ["ops", "observability"],
            "assumed_role": "operator"
        }
    });
    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("oidc-key-1".to_string());
    let id_token = encode(
        &jwt_header,
        &claims,
        &EncodingKey::from_secret(oidc_secret.as_bytes()),
    )
    .expect("failed to encode custom sts token");

    let inline_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{allowed_key}")]
        }]
    })
    .to_string();
    let assume_response = admin
        .client
        .post(format!("{}/", admin.base_url))
        .form(&vec![
            (
                "Action".to_string(),
                "AssumeRoleWithCustomToken".to_string(),
            ),
            ("Version".to_string(), "2011-06-15".to_string()),
            ("Token".to_string(), id_token),
            ("ProviderName".to_string(), "custom-jwt-bridge".to_string()),
            ("UsernameClaim".to_string(), "actor".to_string()),
            ("DisplayNameClaim".to_string(), "display".to_string()),
            ("GroupsClaim".to_string(), "entitlements.teams".to_string()),
            (
                "RoleClaim".to_string(),
                "entitlements.assumed_role".to_string(),
            ),
            (
                "GroupRoleMap".to_string(),
                "ops=operator;observability=auditor".to_string(),
            ),
            ("DefaultRole".to_string(), "viewer".to_string()),
            (
                "RoleArn".to_string(),
                "arn:aws:iam::rustio:role/reports-custom-reader".to_string(),
            ),
            (
                "RoleSessionName".to_string(),
                "custom-token-session".to_string(),
            ),
            ("DurationSeconds".to_string(), "1800".to_string()),
            ("Policy".to_string(), inline_policy),
        ])
        .send()
        .await
        .expect("assume role with custom token request failed");
    let assume_status = assume_response.status();
    let assume_body = assume_response
        .text()
        .await
        .expect("assume role with custom token response should be readable");
    assert_eq!(
        assume_status,
        StatusCode::OK,
        "unexpected assume role with custom token body: {assume_body}"
    );
    assert_eq!(
        xml_tag_text(&assume_body, "Provider").as_deref(),
        Some("custom-jwt-bridge")
    );
    assert_eq!(
        xml_tag_text(&assume_body, "SubjectFromCustomToken").as_deref(),
        Some("custom-token-user-001")
    );
    let access_key = xml_tag_text(&assume_body, "AccessKeyId").expect("access key should exist");
    let secret_key =
        xml_tag_text(&assume_body, "SecretAccessKey").expect("secret key should exist");
    let session_token =
        xml_tag_text(&assume_body, "SessionToken").expect("session token should exist");

    {
        let users = admin.state.users.read().await;
        let custom_user = users
            .iter()
            .find(|user| user.username == "custom-sts-user")
            .expect("custom token user should be synchronized into iam");
        assert_eq!(custom_user.role, "operator");
    }

    let sts_sessions = admin
        .client
        .get(format!("{}/api/v1/iam/sts/sessions", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list sts sessions request failed");
    assert_eq!(sts_sessions.status(), StatusCode::OK);
    let sts_sessions_payload = sts_sessions
        .json::<Value>()
        .await
        .expect("failed to decode custom sts sessions response");
    assert!(
        sts_sessions_payload
            .pointer("/data")
            .and_then(Value::as_array)
            .expect("sts sessions should be array")
            .iter()
            .any(|item| {
                item.pointer("/provider") == Some(&json!("custom-jwt-bridge"))
                    && item.pointer("/role_arn")
                        == Some(&json!("arn:aws:iam::rustio:role/reports-custom-reader"))
                    && item.pointer("/session_name") == Some(&json!("custom-token-session"))
                    && item.pointer("/principal") == Some(&json!("custom-sts-user"))
            }),
        "custom token sts session should be queryable with provider metadata"
    );

    let allowed = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, allowed_key))
        .basic_auth(&access_key, Some(&secret_key))
        .header("x-amz-security-token", &session_token)
        .send()
        .await
        .expect("allowed custom sts request failed");
    assert_eq!(allowed.status(), StatusCode::OK);

    let denied = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, denied_key))
        .basic_auth(&access_key, Some(&secret_key))
        .header("x-amz-security-token", &session_token)
        .send()
        .await
        .expect("denied custom sts request failed");
    let denied_status = denied.status();
    let denied_body = denied
        .text()
        .await
        .expect("denied custom sts response should be readable");
    assert_eq!(denied_status, StatusCode::FORBIDDEN);
    assert!(
        denied_body.contains("<Code>AccessDenied</Code>"),
        "unexpected denied custom sts body: {denied_body}"
    );

    oidc.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federated_sts_ldap_identity_issues_session_and_enforces_inline_policy() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn().await;
    configure_mock_ldap_env(&ldap);
    let admin_access_token = admin.login_access_token().await;
    let bucket = "federated-sts-ldap";
    let allowed_key = "ops/allowed.txt";
    let denied_key = "ops/denied.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, body) in [(allowed_key, "allowed"), (denied_key, "denied")] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(body.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let create_policy = admin
        .client
        .post(format!("{}/api/v1/iam/policies", admin.base_url))
        .bearer_auth(&admin_access_token)
        .json(&json!({
            "name": "ops-read",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [format!("arn:aws:s3:::{bucket}/ops/*")]
                }]
            }
        }))
        .send()
        .await
        .expect("create ldap policy request failed");
    assert_eq!(create_policy.status(), StatusCode::OK);

    let attach_policy = admin
        .client
        .post(format!(
            "{}/api/v1/iam/policies/{}/attach",
            admin.base_url, "ops-read"
        ))
        .bearer_auth(&admin_access_token)
        .json(&json!({ "principal": "ops" }))
        .send()
        .await
        .expect("attach ldap group policy request failed");
    assert_eq!(attach_policy.status(), StatusCode::OK);

    let inline_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{allowed_key}")]
        }]
    })
    .to_string();
    let assume_response = admin
        .client
        .post(format!("{}/", admin.base_url))
        .form(&vec![
            (
                "Action".to_string(),
                "AssumeRoleWithLDAPIdentity".to_string(),
            ),
            ("Version".to_string(), "2011-06-15".to_string()),
            ("LDAPUsername".to_string(), "alice".to_string()),
            ("LDAPPassword".to_string(), "alice-pass".to_string()),
            ("RoleSessionName".to_string(), "alice-ldap".to_string()),
            ("DurationSeconds".to_string(), "1800".to_string()),
            ("Policy".to_string(), inline_policy),
        ])
        .send()
        .await
        .expect("assume role with ldap identity request failed");
    let assume_status = assume_response.status();
    let assume_body = assume_response
        .text()
        .await
        .expect("assume role with ldap response should be readable");
    assert_eq!(
        assume_status,
        StatusCode::OK,
        "unexpected assume role with ldap body: {assume_body}"
    );
    let access_key = xml_tag_text(&assume_body, "AccessKeyId").expect("access key should exist");
    let secret_key =
        xml_tag_text(&assume_body, "SecretAccessKey").expect("secret key should exist");
    let session_token =
        xml_tag_text(&assume_body, "SessionToken").expect("session token should exist");
    assert_eq!(
        xml_tag_text(&assume_body, "LDAPUsername").as_deref(),
        Some("alice")
    );

    let sts_sessions = admin
        .client
        .get(format!("{}/api/v1/iam/sts/sessions", admin.base_url))
        .bearer_auth(&admin_access_token)
        .send()
        .await
        .expect("list sts sessions request failed");
    assert_eq!(sts_sessions.status(), StatusCode::OK);
    let sts_sessions_payload = sts_sessions
        .json::<Value>()
        .await
        .expect("failed to decode sts sessions response");
    assert!(
        sts_sessions_payload
            .pointer("/data")
            .and_then(Value::as_array)
            .expect("sts sessions should be array")
            .iter()
            .any(|item| {
                item.pointer("/provider") == Some(&json!("ldap"))
                    && item.pointer("/session_name") == Some(&json!("alice-ldap"))
                    && item.pointer("/principal") == Some(&json!("alice"))
            }),
        "federated ldap sts session should be queryable with provider metadata"
    );

    let allowed = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, allowed_key))
        .basic_auth(&access_key, Some(&secret_key))
        .header("x-amz-security-token", &session_token)
        .send()
        .await
        .expect("allowed ldap sts request failed");
    assert_eq!(allowed.status(), StatusCode::OK);

    let denied = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, denied_key))
        .basic_auth(&access_key, Some(&secret_key))
        .header("x-amz-security-token", &session_token)
        .send()
        .await
        .expect("denied ldap sts request failed");
    let denied_status = denied.status();
    let denied_body = denied
        .text()
        .await
        .expect("denied ldap sts response should be readable");
    assert_eq!(denied_status, StatusCode::FORBIDDEN);
    assert!(
        denied_body.contains("<Code>AccessDenied</Code>"),
        "unexpected denied ldap sts body: {denied_body}"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_config_update_supports_external_identity_fields() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;

    let response = admin
        .client
        .patch(format!("{}/api/v1/security/config", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "oidc_enabled": true,
            "ldap_enabled": true,
            "oidc_discovery_url": "https://id.example.internal/.well-known/openid-configuration",
            "oidc_issuer": "https://id.example.internal",
            "oidc_client_id": "rustio-console",
            "oidc_jwks_url": "https://id.example.internal/jwks.json",
            "oidc_allowed_algs": "RS256,ES256",
            "oidc_username_claim": "preferred_username",
            "oidc_groups_claim": "groups",
            "oidc_role_claim": "role",
            "oidc_default_role": "viewer",
            "oidc_group_role_map": "platform-admins=admin",
            "ldap_url": "ldap://127.0.0.1:1389",
            "ldap_bind_dn": "cn=admin,dc=example,dc=org",
            "ldap_user_base_dn": "ou=users,dc=example,dc=org",
            "ldap_user_filter": "(uid={username})",
            "ldap_group_base_dn": "ou=groups,dc=example,dc=org",
            "ldap_group_filter": "(member={user_dn})",
            "ldap_group_attribute": "memberOf",
            "ldap_group_name_attribute": "cn",
            "ldap_default_role": "operator",
            "ldap_group_role_map": "ops=operator,audit=auditor",
            "kms_endpoint": "https://vault.example.internal",
            "sse_mode": "SSE-KMS"
        }))
        .send()
        .await
        .expect("security config patch failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode security config patch response");
    assert_eq!(
        payload
            .pointer("/data/oidc_discovery_url")
            .and_then(|value| value.as_str()),
        Some("https://id.example.internal/.well-known/openid-configuration")
    );
    assert_eq!(
        payload
            .pointer("/data/ldap_group_role_map")
            .and_then(|value| value.as_str()),
        Some("ops=operator,audit=auditor")
    );

    let current = admin
        .client
        .get(format!("{}/api/v1/security/config", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("security config get failed");
    assert_eq!(current.status(), StatusCode::OK);
    let current_payload = current
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode security config get response");
    assert_eq!(
        current_payload
            .pointer("/data/oidc_client_id")
            .and_then(|value| value.as_str()),
        Some("rustio-console")
    );
    assert_eq!(
        current_payload
            .pointer("/data/ldap_default_role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let cluster_current = admin
        .client
        .get(format!("{}/api/v1/cluster/config/current", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("cluster config current get failed");
    assert_eq!(cluster_current.status(), StatusCode::OK);
    let cluster_payload = cluster_current
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode cluster config current response");
    assert_eq!(
        cluster_payload
            .pointer("/data/source")
            .and_then(|value| value.as_str()),
        Some("security-api")
    );
    assert_eq!(
        cluster_payload
            .pointer("/data/payload/security/oidc_client_id")
            .and_then(|value| value.as_str()),
        Some("rustio-console")
    );
    assert_eq!(
        cluster_payload
            .pointer("/data/payload/security/ldap_group_role_map")
            .and_then(|value| value.as_str()),
        Some("ops=operator,audit=auditor")
    );

    let persisted_path = admin
        .data_dir
        .join(".rustio_meta")
        .join("security-config.json");
    let persisted = std::fs::read_to_string(&persisted_path)
        .expect("persisted security config should be written");
    let persisted_json = serde_json::from_str::<serde_json::Value>(&persisted)
        .expect("persisted config must be json");
    assert_eq!(
        persisted_json
            .pointer("/oidc_jwks_url")
            .and_then(|value| value.as_str()),
        Some("https://id.example.internal/jwks.json")
    );
    let cluster_history_path = admin
        .data_dir
        .join(".rustio_meta")
        .join("cluster-config-history.json");
    let cluster_history = std::fs::read_to_string(&cluster_history_path)
        .expect("persisted cluster config history should be written");
    assert!(
        cluster_history.contains("\"source\": \"security-api\""),
        "cluster config history should record security-api snapshot"
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_config_apply_and_rollback_updates_security_runtime() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;

    let current = admin
        .client
        .get(format!("{}/api/v1/cluster/config/current", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("initial cluster config current get failed");
    assert_eq!(current.status(), StatusCode::OK);
    let current_payload = current
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode initial cluster config current");
    let initial_version = current_payload
        .pointer("/data/version")
        .and_then(|value| value.as_str())
        .expect("initial cluster config version should exist")
        .to_string();
    let mut next_payload = current_payload
        .pointer("/data/payload")
        .cloned()
        .expect("initial cluster config payload should exist");
    next_payload["security"] = json!({
        "oidc_enabled": true,
        "ldap_enabled": true,
        "oidc_discovery_url": "https://id.example.internal/.well-known/openid-configuration",
        "oidc_issuer": "https://id.example.internal",
        "oidc_client_id": "rustio-console-browser",
        "oidc_jwks_url": "https://id.example.internal/jwks.json",
        "oidc_allowed_algs": "RS256",
        "oidc_username_claim": "preferred_username",
        "oidc_groups_claim": "groups",
        "oidc_role_claim": "role",
        "oidc_default_role": "viewer",
        "oidc_group_role_map": "platform-admins=admin",
        "ldap_url": "ldap://ldap.example.internal:389",
        "ldap_bind_dn": "cn=admin,dc=example,dc=org",
        "ldap_user_base_dn": "ou=users,dc=example,dc=org",
        "ldap_user_filter": "(uid={username})",
        "ldap_group_base_dn": "ou=groups,dc=example,dc=org",
        "ldap_group_filter": "(member={user_dn})",
        "ldap_group_attribute": "memberOf",
        "ldap_group_name_attribute": "cn",
        "ldap_default_role": "operator",
        "ldap_group_role_map": "ops=operator",
        "kms_endpoint": "https://vault.cluster.internal",
        "sse_mode": "SSE-KMS"
    });

    let apply = admin
        .client
        .post(format!("{}/api/v1/cluster/config/apply", admin.base_url))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "payload": next_payload,
            "reason": "test cluster config apply security runtime"
        }))
        .send()
        .await
        .expect("cluster config apply failed");
    assert_eq!(apply.status(), StatusCode::OK);
    let apply_payload = apply
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode cluster config apply response");
    let applied_version = apply_payload
        .pointer("/data/version")
        .and_then(|value| value.as_str())
        .expect("applied cluster config version should exist")
        .to_string();
    assert_ne!(applied_version, initial_version);
    assert_eq!(
        apply_payload
            .pointer("/data/payload/security/oidc_client_id")
            .and_then(|value| value.as_str()),
        Some("rustio-console-browser")
    );

    let security = admin
        .client
        .get(format!("{}/api/v1/security/config", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("security config get after apply failed");
    assert_eq!(security.status(), StatusCode::OK);
    let security_payload = security
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode security config after apply");
    assert_eq!(
        security_payload
            .pointer("/data/oidc_client_id")
            .and_then(|value| value.as_str()),
        Some("rustio-console-browser")
    );
    assert_eq!(
        security_payload
            .pointer("/data/ldap_url")
            .and_then(|value| value.as_str()),
        Some("ldap://ldap.example.internal:389")
    );

    let rollback = admin
        .client
        .post(format!("{}/api/v1/cluster/config/rollback", admin.base_url))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "version": initial_version,
            "reason": "test cluster config rollback security runtime"
        }))
        .send()
        .await
        .expect("cluster config rollback failed");
    assert_eq!(rollback.status(), StatusCode::OK);

    let rolled_security = admin
        .client
        .get(format!("{}/api/v1/security/config", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("security config get after rollback failed");
    assert_eq!(rolled_security.status(), StatusCode::OK);
    let rolled_security_payload = rolled_security
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode security config after rollback");
    assert_eq!(
        rolled_security_payload
            .pointer("/data/oidc_client_id")
            .and_then(|value| value.as_str()),
        Some("")
    );
    assert_eq!(
        rolled_security_payload
            .pointer("/data/ldap_url")
            .and_then(|value| value.as_str()),
        Some("")
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_provider_listing_defaults_to_local_only_when_external_auth_is_unconfigured() {
    let admin = AdminServer::spawn().await;

    let response = admin
        .client
        .get(format!("{}/api/v1/auth/providers", admin.base_url))
        .send()
        .await
        .expect("list auth providers request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode auth providers response");

    let providers = payload["data"]
        .as_array()
        .expect("auth providers should be an array");
    assert_eq!(providers.len(), 3);
    assert_eq!(providers[0]["id"].as_str(), Some("local"));
    assert_eq!(providers[0]["enabled"].as_bool(), Some(true));
    assert_eq!(providers[0]["configured"].as_bool(), Some(true));
    assert_eq!(
        providers[0]["supports_username_password"].as_bool(),
        Some(true)
    );
    assert_eq!(providers[1]["id"].as_str(), Some("oidc"));
    assert_eq!(providers[1]["enabled"].as_bool(), Some(false));
    assert_eq!(providers[1]["configured"].as_bool(), Some(false));
    assert_eq!(
        providers[1]["supports_browser_redirect"].as_bool(),
        Some(true)
    );
    assert_eq!(
        providers[1]["authorize_url"].as_str(),
        Some("/api/v1/auth/oidc/authorize")
    );
    assert_eq!(
        providers[1]["missing_requirements"]
            .as_array()
            .map(|items| items.len()),
        Some(2)
    );
    assert_eq!(providers[2]["id"].as_str(), Some("ldap"));
    assert_eq!(providers[2]["enabled"].as_bool(), Some(false));
    assert_eq!(providers[2]["configured"].as_bool(), Some(false));
    assert_eq!(
        providers[2]["supports_username_password"].as_bool(),
        Some(true)
    );
    assert_eq!(
        providers[2]["missing_requirements"]
            .as_array()
            .map(|items| items.len()),
        Some(2)
    );

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_provider_listing_reflects_runtime_external_auth_switches() {
    let admin = AdminServer::spawn().await;

    {
        let mut security = admin.state.security.write().await;
        security.oidc_enabled = true;
        security.oidc_discovery_url =
            "https://id.example.internal/.well-known/openid-configuration".to_string();
        security.oidc_client_id = "rustio-console".to_string();
        security.ldap_enabled = true;
        security.ldap_url = "ldap://ldap.example.internal:389".to_string();
        security.ldap_user_base_dn = "ou=users,dc=example,dc=org".to_string();
    }

    let response = admin
        .client
        .get(format!("{}/api/v1/auth/providers", admin.base_url))
        .send()
        .await
        .expect("list auth providers request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode auth providers response");

    let providers = payload["data"]
        .as_array()
        .expect("auth providers should be an array");
    assert_eq!(providers.len(), 3);
    assert_eq!(providers[1]["id"].as_str(), Some("oidc"));
    assert_eq!(providers[1]["enabled"].as_bool(), Some(true));
    assert_eq!(providers[1]["configured"].as_bool(), Some(true));
    assert_eq!(providers[2]["id"].as_str(), Some("ldap"));
    assert_eq!(providers[2]["enabled"].as_bool(), Some(true));
    assert_eq!(providers[2]["configured"].as_bool(), Some(true));

    {
        let mut security = admin.state.security.write().await;
        security.oidc_enabled = false;
        security.ldap_enabled = false;
    }

    let disabled_response = admin
        .client
        .get(format!("{}/api/v1/auth/providers", admin.base_url))
        .send()
        .await
        .expect("list auth providers request after disabling failed");
    assert_eq!(disabled_response.status(), StatusCode::OK);
    let disabled_payload = disabled_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode disabled auth providers response");
    let disabled_providers = disabled_payload["data"]
        .as_array()
        .expect("disabled auth providers should be an array");
    assert_eq!(disabled_providers[1]["enabled"].as_bool(), Some(false));
    assert_eq!(disabled_providers[1]["configured"].as_bool(), Some(true));
    assert_eq!(disabled_providers[2]["enabled"].as_bool(), Some(false));
    assert_eq!(disabled_providers[2]["configured"].as_bool(), Some(true));

    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_via_real_directory_bind_and_group_search_succeeds() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn().await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let providers = admin
        .client
        .get(format!("{}/api/v1/auth/providers", admin.base_url))
        .send()
        .await
        .expect("list auth providers request failed");
    assert_eq!(providers.status(), StatusCode::OK);
    let providers_payload = providers
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode auth providers payload");
    let ldap_provider = providers_payload["data"]
        .as_array()
        .expect("auth providers should be an array")
        .iter()
        .find(|item| item.get("id").and_then(|value| value.as_str()) == Some("ldap"))
        .expect("ldap provider should exist");
    assert_eq!(ldap_provider["enabled"].as_bool(), Some(true));
    assert_eq!(ldap_provider["configured"].as_bool(), Some(true));

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let login_payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap login payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );
    let access_token = login_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("ldap access token should exist")
        .to_string();

    let current_session = admin
        .client
        .get(format!("{}/api/v1/auth/session/current", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("ldap current session request failed");
    assert_eq!(current_session.status(), StatusCode::OK);
    let current_session_payload = current_session
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap current session payload");
    assert_eq!(
        current_session_payload
            .pointer("/data/principal")
            .and_then(|value| value.as_str()),
        Some("alice")
    );
    assert_eq!(
        current_session_payload
            .pointer("/data/provider")
            .and_then(|value| value.as_str()),
        Some("ldap")
    );
    assert_eq!(
        current_session_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_user = admin
        .state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == "alice")
        .cloned()
        .expect("ldap user should be synced into iam users");
    assert_eq!(synced_user.display_name, "Alice Ops Team");
    assert_eq!(synced_user.role, "operator");
    assert!(synced_user.enabled);

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "ops")
        .cloned()
        .expect("ldap group should be synced into iam groups");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "ldap user should be added into synced group"
    );

    let admin_access_token = admin.login_access_token().await;
    let sessions = admin
        .client
        .get(format!("{}/api/v1/auth/sessions", admin.base_url))
        .bearer_auth(admin_access_token)
        .send()
        .await
        .expect("list auth sessions request failed");
    assert_eq!(sessions.status(), StatusCode::OK);
    let sessions_payload = sessions
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode sessions payload");
    assert!(
        sessions_payload["data"]
            .as_array()
            .expect("sessions should be array")
            .iter()
            .any(|session| {
                session.get("principal").and_then(|value| value.as_str()) == Some("alice")
                    && session.get("provider").and_then(|value| value.as_str()) == Some("ldap")
                    && session.get("role").and_then(|value| value.as_str()) == Some("operator")
            }),
        "ldap session should be persisted with provider metadata"
    );

    let audit_events = admin.state.audits.read().await.clone();
    assert!(
        audit_events.iter().any(|event| {
            event.action == "auth.login.ldap"
                && event.actor == "alice"
                && event
                    .details
                    .get("provider")
                    .and_then(|value| value.as_str())
                    == Some("ldap")
        }),
        "ldap login should emit audit event with provider metadata"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_escapes_username_and_user_dn_in_search_filters() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        username: "alice*(ops)".to_string(),
        password: "alice-pass".to_string(),
        cn: "Alice Escaped".to_string(),
        display_name: "Alice Escaped User".to_string(),
        groups: vec!["ops".to_string()],
        include_member_of: false,
        enable_group_search: true,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice*(ops)",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap escaped filter login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap escaped filter payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_user = admin
        .state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == "alice*(ops)")
        .cloned()
        .expect("ldap escaped filter user should be synced");
    assert_eq!(synced_user.display_name, "Alice Escaped User");
    assert_eq!(synced_user.role, "operator");

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_via_member_of_attribute_role_mapping_succeeds() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        include_member_of: true,
        enable_group_search: false,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap memberOf login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap memberOf login payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let access_token = login_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("ldap memberOf access token should exist")
        .to_string();

    let current_session = admin
        .client
        .get(format!("{}/api/v1/auth/session/current", admin.base_url))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("ldap memberOf current session request failed");
    assert_eq!(current_session.status(), StatusCode::OK);
    let current_session_payload = current_session
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap memberOf current session payload");
    assert_eq!(
        current_session_payload
            .pointer("/data/provider")
            .and_then(|value| value.as_str()),
        Some("ldap")
    );
    assert_eq!(
        current_session_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "ops")
        .cloned()
        .expect("memberOf ldap group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "memberOf ldap user should be added into synced group"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_supports_custom_group_attribute_with_direct_group_names() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["ops".to_string()],
        include_member_of: true,
        enable_group_search: false,
        membership_attribute_name: "groups".to_string(),
        membership_values_are_dns: false,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "groups".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap custom group attribute login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap custom group attribute login payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "ops")
        .cloned()
        .expect("custom group attribute ldap group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "custom group attribute ldap user should be added into synced group"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_prefers_env_group_attribute_over_runtime_security_config() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["ops".to_string()],
        include_member_of: true,
        enable_group_search: false,
        membership_attribute_name: "groups".to_string(),
        membership_values_are_dns: false,
        ..MockLdapDirectory::default()
    })
    .await;
    std::env::set_var("RUSTIO_LDAP_GROUP_ATTRIBUTE", "groups");

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap env group attribute login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap env group attribute payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "ops")
        .cloned()
        .expect("ldap env group attribute group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "ldap env group attribute user should be added into synced group"
    );

    std::env::remove_var("RUSTIO_LDAP_GROUP_ATTRIBUTE");
    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_prefers_env_group_name_attribute_over_runtime_security_config() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["engineering".to_string()],
        include_member_of: true,
        enable_group_search: false,
        membership_attribute_name: "memberOf".to_string(),
        membership_values_are_dns: true,
        group_name_attribute: "ou".to_string(),
        group_ou_path: "ou=groups".to_string(),
        ..MockLdapDirectory::default()
    })
    .await;
    std::env::set_var("RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE", "ou");

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "engineering=operator".to_string();
    }

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap env group name attribute login request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap env group name attribute payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "engineering")
        .cloned()
        .expect("ldap env group name attribute group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "ldap env group name attribute user should be added into synced group"
    );

    std::env::remove_var("RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE");
    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_via_administrative_bind_and_group_search_succeeds() {
    let admin = AdminServer::spawn().await;
    let bind_dn = format!("cn=admin,{}", "dc=example,dc=org");
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        bind_dn: Some(bind_dn.clone()),
        bind_password: Some("directory-secret".to_string()),
        include_member_of: false,
        enable_group_search: true,
        ..MockLdapDirectory::default()
    })
    .await;
    std::env::set_var("RUSTIO_LDAP_BIND_PASSWORD", "directory-secret");

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = bind_dn.clone();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap administrative bind login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap administrative bind login payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );
    let access_token = login_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("ldap administrative bind access token should exist")
        .to_string();
    let current_session = admin
        .client
        .get(format!("{}/api/v1/auth/session/current", admin.base_url))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("ldap administrative bind current session request failed");
    assert_eq!(current_session.status(), StatusCode::OK);
    let current_session_payload = current_session
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap administrative bind current session payload");
    assert_eq!(
        current_session_payload
            .pointer("/data/provider")
            .and_then(|value| value.as_str()),
        Some("ldap")
    );
    assert_eq!(
        current_session_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_user = admin
        .state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == "alice")
        .cloned()
        .expect("administrative bind ldap user should be synced");
    assert_eq!(synced_user.display_name, "Alice Ops Team");
    assert_eq!(synced_user.role, "operator");

    std::env::remove_var("RUSTIO_LDAP_BIND_PASSWORD");
    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_extracts_group_name_from_member_dn_with_configured_attribute() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["engineering".to_string()],
        include_member_of: true,
        enable_group_search: false,
        membership_attribute_name: "memberOf".to_string(),
        membership_values_are_dns: true,
        group_name_attribute: "ou".to_string(),
        group_ou_path: "ou=groups".to_string(),
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "ou".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "engineering=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap custom group dn login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap custom group dn login payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "engineering")
        .cloned()
        .expect("custom group dn ldap group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "custom group dn ldap user should be added into synced group"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_rejects_invalid_administrative_bind_password_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let bind_dn = format!("cn=admin,{}", "dc=example,dc=org");
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        bind_dn: Some(bind_dn.clone()),
        bind_password: Some("directory-secret".to_string()),
        include_member_of: false,
        enable_group_search: true,
        ..MockLdapDirectory::default()
    })
    .await;
    std::env::set_var("RUSTIO_LDAP_BIND_PASSWORD", "wrong-secret");

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = bind_dn.clone();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap invalid administrative bind password request failed");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response
        .text()
        .await
        .expect("ldap invalid administrative bind password body should be readable");
    assert!(
        body.contains("LDAP 管理绑定被拒绝")
            && body.contains("ldap administrative bind was rejected"),
        "unexpected ldap invalid administrative bind body: {body}"
    );

    std::env::remove_var("RUSTIO_LDAP_BIND_PASSWORD");
    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_supports_group_search_with_custom_group_name_attribute() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["engineering".to_string()],
        include_member_of: false,
        enable_group_search: true,
        group_name_attribute: "ou".to_string(),
        group_ou_path: "ou=groups".to_string(),
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "ou".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "engineering=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap custom group search login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap custom group search login payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "engineering")
        .cloned()
        .expect("custom group search ldap group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "custom group search ldap user should be added into synced group"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_supports_nested_ou_and_multiple_group_sync() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        cn: "Alice Platform".to_string(),
        display_name: "Alice Platform Team".to_string(),
        groups: vec!["ops".to_string(), "engineering".to_string()],
        user_ou_path: "ou=engineering,ou=users".to_string(),
        group_ou_path: "ou=platform,ou=groups".to_string(),
        include_member_of: false,
        enable_group_search: true,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = ldap.base_dn.clone();
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = ldap.base_dn.clone();
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap nested ou login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap nested ou login payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );

    let users = admin.state.users.read().await;
    let user = users
        .iter()
        .find(|user| user.username == "alice")
        .expect("ldap nested ou user should be synced");
    assert_eq!(user.display_name, "Alice Platform Team");
    assert_eq!(user.role, "operator");
    drop(users);

    let groups = admin.state.groups.read().await;
    let ops = groups
        .iter()
        .find(|group| group.name == "ops")
        .expect("ldap nested ou ops group should be synced");
    assert!(ops.members.iter().any(|member| member == "alice"));
    let engineering = groups
        .iter()
        .find(|group| group.name == "engineering")
        .expect("ldap nested ou engineering group should be synced");
    assert!(engineering.members.iter().any(|member| member == "alice"));
    drop(groups);

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_prefers_group_role_mapping_order_when_multiple_groups_match() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        cn: "Alice Multi Role".to_string(),
        display_name: "Alice Multi Role".to_string(),
        groups: vec!["ops".to_string(), "auditors".to_string()],
        include_member_of: true,
        enable_group_search: false,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "auditors=auditor,ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap group order login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap group order payload");
    assert_eq!(
        payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("auditor")
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_refresh_uses_latest_role_after_external_relogin() {
    let admin = AdminServer::spawn().await;
    let ldap_first = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["ops".to_string()],
        include_member_of: true,
        enable_group_search: false,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap_first.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap_first.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap_first.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let first_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("first ldap refresh-role login request failed");
    assert_eq!(first_login.status(), StatusCode::OK);
    let first_payload = first_login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode first ldap refresh-role payload");
    assert_eq!(
        first_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("operator")
    );
    let old_refresh_token = first_payload
        .pointer("/data/refresh_token")
        .and_then(|value| value.as_str())
        .expect("ldap old refresh token should exist")
        .to_string();

    let ldap_second = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        groups: vec!["engineering".to_string()],
        include_member_of: true,
        enable_group_search: false,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_url = ldap_second.url.clone();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap_second.base_dn);
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap_second.base_dn);
    }

    let second_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("second ldap refresh-role login request failed");
    assert_eq!(second_login.status(), StatusCode::OK);
    let second_payload = second_login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode second ldap refresh-role payload");
    assert_eq!(
        second_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );

    let refresh_response = admin
        .client
        .post(format!("{}/api/v1/auth/refresh", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": old_refresh_token }).to_string())
        .send()
        .await
        .expect("ldap refresh-role refresh request failed");
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_payload = refresh_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap refresh-role refresh payload");
    assert_eq!(
        refresh_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );
    let refreshed_access_token = refresh_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("ldap refreshed access token should exist")
        .to_string();

    let topology = admin
        .client
        .get(format!("{}/api/v1/system/topology", admin.base_url))
        .bearer_auth(refreshed_access_token)
        .send()
        .await
        .expect("ldap refreshed topology request failed");
    assert_eq!(topology.status(), StatusCode::FORBIDDEN);

    ldap_second.stop().await;
    ldap_first.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_falls_back_to_default_role_when_groups_are_unmapped() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn_with_directory(MockLdapDirectory {
        cn: "Alice Engineering".to_string(),
        display_name: "Alice Engineering".to_string(),
        groups: vec!["engineering".to_string()],
        include_member_of: true,
        enable_group_search: false,
        ..MockLdapDirectory::default()
    })
    .await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "alice-pass",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap default role fallback login request failed");
    assert_eq!(login.status(), StatusCode::OK);
    let login_payload = login
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap default role fallback payload");
    assert_eq!(
        login_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );

    let access_token = login_payload
        .pointer("/data/access_token")
        .and_then(|value| value.as_str())
        .expect("ldap default role fallback access token should exist")
        .to_string();

    let current_session = admin
        .client
        .get(format!("{}/api/v1/auth/session/current", admin.base_url))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("ldap default role fallback current session request failed");
    assert_eq!(current_session.status(), StatusCode::OK);
    let current_session_payload = current_session
        .json::<serde_json::Value>()
        .await
        .expect("failed to decode ldap default role fallback current session payload");
    assert_eq!(
        current_session_payload
            .pointer("/data/role")
            .and_then(|value| value.as_str()),
        Some("viewer")
    );

    let synced_user = admin
        .state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == "alice")
        .cloned()
        .expect("ldap default role fallback user should be synced");
    assert_eq!(synced_user.display_name, "Alice Engineering");
    assert_eq!(synced_user.role, "viewer");

    let synced_group = admin
        .state
        .groups
        .read()
        .await
        .iter()
        .find(|group| group.name == "engineering")
        .cloned()
        .expect("ldap default role fallback group should be synced");
    assert!(
        synced_group.members.iter().any(|member| member == "alice"),
        "ldap default role fallback group should include user"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ldap_login_rejects_invalid_directory_password_with_bilingual_message() {
    let admin = AdminServer::spawn().await;
    let ldap = MockLdapServer::spawn().await;

    {
        let mut security = admin.state.security.write().await;
        security.ldap_enabled = true;
        security.ldap_url = ldap.url.clone();
        security.ldap_bind_dn = String::new();
        security.ldap_user_base_dn = format!("ou=users,{}", ldap.base_dn);
        security.ldap_user_filter = "(uid={username})".to_string();
        security.ldap_group_base_dn = format!("ou=groups,{}", ldap.base_dn);
        security.ldap_group_filter = "(member={user_dn})".to_string();
        security.ldap_group_attribute = "memberOf".to_string();
        security.ldap_group_name_attribute = "cn".to_string();
        security.ldap_default_role = "viewer".to_string();
        security.ldap_group_role_map = "ops=operator".to_string();
    }

    let response = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "wrong-password",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap login with invalid password request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response
        .text()
        .await
        .expect("ldap invalid password body should be readable");
    assert!(
        body.contains("LDAP 用户名或密码无效")
            && body.contains("ldap username or password is invalid"),
        "unexpected ldap invalid password body: {body}"
    );

    ldap.stop().await;
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_login_rejects_incomplete_provider_configuration_with_clear_errors() {
    let admin = AdminServer::spawn().await;

    let oidc_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "",
                "password": "",
                "provider": "oidc",
                "id_token": "dummy-token"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("oidc login request should complete");
    assert_eq!(oidc_login.status(), StatusCode::FORBIDDEN);
    let oidc_body = oidc_login
        .text()
        .await
        .expect("oidc login error body should be readable");
    assert!(
        oidc_body.contains("OIDC 登录未完成配置")
            && oidc_body.contains("oidc login is not fully configured"),
        "unexpected oidc error body: {oidc_body}"
    );

    let oidc_browser = admin
        .client
        .get(format!("{}/api/v1/auth/oidc/authorize", admin.base_url))
        .header("host", "127.0.0.1")
        .send()
        .await
        .expect("oidc browser authorize request should complete");
    assert_eq!(oidc_browser.status(), StatusCode::FORBIDDEN);
    let oidc_browser_body = oidc_browser
        .text()
        .await
        .expect("oidc browser authorize error body should be readable");
    assert!(
        oidc_browser_body.contains("OIDC 登录未完成配置")
            && oidc_browser_body.contains("oidc login is not fully configured"),
        "unexpected oidc browser error body: {oidc_browser_body}"
    );

    let ldap_login = admin
        .client
        .post(format!("{}/api/v1/auth/login", admin.base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "secret",
                "provider": "ldap"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("ldap login request should complete");
    assert_eq!(ldap_login.status(), StatusCode::FORBIDDEN);
    let ldap_body = ldap_login
        .text()
        .await
        .expect("ldap login error body should be readable");
    assert!(
        ldap_body.contains("LDAP 登录未完成配置")
            && ldap_body.contains("ldap login is not fully configured"),
        "unexpected ldap error body: {ldap_body}"
    );

    admin.stop().await;
}

#[tokio::test]
async fn system_metrics_summary_reports_cluster_and_replication_state() {
    let admin = AdminServer::spawn().await;
    let now = Utc::now();

    {
        let mut nodes = admin.state.nodes.write().await;
        let node = nodes.get_mut(1).expect("node-b should exist");
        node.online = false;
        node.last_heartbeat = now;
    }
    {
        let mut replications = admin.state.replications.write().await;
        replications.clear();
        replications.extend([
            ReplicationStatus {
                rule_id: "rule-dr-a".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                rule_name: None,
                endpoint: None,
                prefix: None,
                suffix: None,
                tags: Vec::new(),
                priority: 100,
                replicate_existing: true,
                sync_deletes: true,
                lag_seconds: 8,
                status: "active".to_string(),
            },
            ReplicationStatus {
                rule_id: "rule-dr-b".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-b".to_string(),
                rule_name: None,
                endpoint: None,
                prefix: None,
                suffix: None,
                tags: Vec::new(),
                priority: 100,
                replicate_existing: true,
                sync_deletes: true,
                lag_seconds: 33,
                status: "active".to_string(),
            },
        ]);
    }
    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.clear();
        backlog.extend([
            ReplicationBacklogItem {
                id: "repl-in-progress".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/a.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 11,
                idempotency_key: "idem-a".to_string(),
                version_id: Some("v1".to_string()),
                attempts: 1,
                status: "in_progress".to_string(),
                last_error: String::new(),
                lease_owner: Some("replication-worker-test".to_string()),
                lease_until: Some(now + ChronoDuration::seconds(30)),
                queued_at: now - ChronoDuration::minutes(5),
                last_attempt_at: now - ChronoDuration::seconds(10),
            },
            ReplicationBacklogItem {
                id: "repl-failed".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-b".to_string(),
                object_key: "2026/03/b.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 12,
                idempotency_key: "idem-b".to_string(),
                version_id: Some("v2".to_string()),
                attempts: 1,
                status: "failed".to_string(),
                last_error: "网络抖动 / network jitter".to_string(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(4),
                last_attempt_at: now,
            },
            ReplicationBacklogItem {
                id: "repl-dead-letter".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-b".to_string(),
                object_key: "2026/03/c.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "delete".to_string(),
                checkpoint: 13,
                idempotency_key: "idem-c".to_string(),
                version_id: None,
                attempts: 5,
                status: "dead_letter".to_string(),
                last_error: "对象不存在 / object not found".to_string(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(3),
                last_attempt_at: now - ChronoDuration::minutes(2),
            },
            ReplicationBacklogItem {
                id: "repl-done".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/d.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 14,
                idempotency_key: "idem-d".to_string(),
                version_id: Some("v3".to_string()),
                attempts: 1,
                status: "done".to_string(),
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(2),
                last_attempt_at: now - ChronoDuration::minutes(2),
            },
        ]);
    }
    {
        let mut checkpoints = admin.state.replication_checkpoints.write().await;
        checkpoints.clear();
        checkpoints.insert("dr-site-a".to_string(), 14);
        checkpoints.insert("dr-site-b".to_string(), 12);
    }
    {
        let mut alert_channels = admin.state.alert_channels.write().await;
        alert_channels.clear();
        alert_channels.extend([
            AlertChannel {
                id: "channel-webhook-main".to_string(),
                name: "主 webhook".to_string(),
                kind: "webhook".to_string(),
                endpoint: "https://hooks.example.internal/rustio".to_string(),
                headers: HashMap::new(),
                payload_template: None,
                header_template: HashMap::new(),
                enabled: true,
                status: "healthy".to_string(),
                last_checked_at: now,
                error: None,
            },
            AlertChannel {
                id: "channel-email-ops".to_string(),
                name: "运维邮件".to_string(),
                kind: "email".to_string(),
                endpoint: "ops@example.internal".to_string(),
                headers: HashMap::new(),
                payload_template: None,
                header_template: HashMap::new(),
                enabled: true,
                status: "degraded".to_string(),
                last_checked_at: now,
                error: Some("smtp timeout".to_string()),
            },
        ]);
    }
    {
        admin.state.alert_delivery_queue.write().await.clear();
    }
    {
        let mut alert_history = admin.state.alert_history.write().await;
        alert_history.clear();
        alert_history.extend([
            AlertHistoryEntry {
                id: "history-repl-dr-b".to_string(),
                rule_id: None,
                rule_name: Some("复制 backlog SLA".to_string()),
                severity: "warning".to_string(),
                status: "firing".to_string(),
                message: "复制 backlog 持续告警".to_string(),
                triggered_at: now - ChronoDuration::minutes(1),
                source: "replication-backlog-sla-watchdog:dr-site-b".to_string(),
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: None,
                resolved_at: None,
                details: json!({
                    "breaches": ["failed", "dead_letter"],
                    "failed": 1,
                    "dead_letter": 1
                }),
            },
            AlertHistoryEntry {
                id: "history-capacity".to_string(),
                rule_id: Some("rule-capacity".to_string()),
                rule_name: Some("容量使用率过高".to_string()),
                severity: "critical".to_string(),
                status: "resolved".to_string(),
                message: "容量已恢复".to_string(),
                triggered_at: now - ChronoDuration::minutes(10),
                source: "rule-engine".to_string(),
                assignee: Some("admin".to_string()),
                claimed_at: Some(now - ChronoDuration::minutes(9)),
                acknowledged_by: Some("admin".to_string()),
                acknowledged_at: Some(now - ChronoDuration::minutes(8)),
                resolved_by: Some("admin".to_string()),
                resolved_at: Some(now - ChronoDuration::minutes(7)),
                details: json!({ "value": 0.72 }),
            },
        ]);
    }
    {
        let mut security = admin.state.security.write().await;
        security.oidc_enabled = true;
        security.ldap_enabled = false;
        security.kms_healthy = true;
        security.kms_last_checked_at = Some(now);
        security.kms_last_success_at = Some(now - ChronoDuration::minutes(2));
        security.kms_rotation_status = "partial_failed".to_string();
        security.kms_rotation_last_started_at = Some(now - ChronoDuration::minutes(5));
        security.kms_rotation_last_completed_at = Some(now - ChronoDuration::minutes(4));
        security.kms_rotation_last_failure_reason =
            Some("轮换失败，需重试失败对象 / rotation failed, retry failed objects".to_string());
        security.kms_rotation_scanned = 9;
        security.kms_rotation_rotated = 7;
        security.kms_rotation_skipped = 1;
        security.kms_rotation_failed = 1;
        security.kms_rotation_failed_objects = vec![kms_failed_object(
            "photos",
            "2026/03/b.jpg",
            None,
            true,
            Some("qa-kms-preview"),
            "rewrap",
            "KMS 数据密钥重新包裹失败 / failed to rewrap KMS data key",
        )];
        security.sse_mode = "SSE-KMS".to_string();
    }
    {
        let mut jobs = admin.state.jobs.write().await;
        jobs.clear();
        let mut job_running = test_job_status("job-running", "heal", "running", 3, 0.4, now);
        job_running.attempt = 1;
        job_running.lease_owner = Some("worker-plane-test".to_string());
        job_running.lease_until = Some(now + ChronoDuration::seconds(15));

        let mut job_pending = test_job_status("job-pending", "replication", "pending", 1, 0.0, now);
        job_pending.bucket = Some("photos".to_string());
        job_pending.object_key = Some("2026/03/pending.jpg".to_string());
        job_pending.site_id = Some("dr-site-a".to_string());
        job_pending.checkpoint = Some(15);

        let mut job_completed = test_job_status("job-completed", "heal", "completed", 3, 1.0, now);
        job_completed.attempt = 1;

        let mut job_failed = test_job_status("job-failed", "replication", "failed", 1, 0.6, now);
        job_failed.bucket = Some("photos".to_string());
        job_failed.object_key = Some("2026/03/failed.jpg".to_string());
        job_failed.site_id = Some("dr-site-b".to_string());
        job_failed.attempt = 2;
        job_failed.checkpoint = Some(16);
        job_failed.last_error = Some("同步失败 / replication failed".to_string());

        let mut job_cancelled = test_job_status("job-cancelled", "heal", "cancelled", 3, 0.1, now);
        job_cancelled.attempt = 1;
        job_cancelled.last_error = Some("operator cancelled".to_string());

        let job_idle = test_job_status("job-idle", "heal", "idle", 3, 0.0, now);

        let mut job_other = test_job_status("job-other", "scan", "blocked", 2, 0.2, now);
        job_other.attempt = 1;
        job_other.last_error = Some("awaiting approval".to_string());

        jobs.extend([
            job_running,
            job_pending,
            job_completed,
            job_failed,
            job_cancelled,
            job_idle,
            job_other,
        ]);
    }
    {
        let mut governance = admin.state.storage_governance.write().await;
        governance.last_scan_at = Some(now);
        governance.last_heal_at = Some(now);
        governance.last_scan_result = "degraded".to_string();
        governance.last_heal_duration_seconds = 12.5;
        governance.scan_runs_total = 2;
        governance.scan_failures_total = 1;
        governance.heal_objects_total = 3;
        governance.heal_failures_total = 1;
    }

    let access_token = admin.login_access_token().await;
    let current_admin_session = admin
        .state
        .admin_sessions
        .read()
        .await
        .first()
        .cloned()
        .expect("login should create admin console session");
    {
        let mut users = admin.state.users.write().await;
        let admin_user = users
            .iter()
            .find(|user| user.username == "admin")
            .cloned()
            .expect("admin user should exist");
        users.clear();
        users.extend([
            admin_user,
            IamUser {
                username: "ops".to_string(),
                display_name: "运维".to_string(),
                role: "operator".to_string(),
                enabled: true,
                created_at: now,
            },
            IamUser {
                username: "auditor".to_string(),
                display_name: "审计".to_string(),
                role: "viewer".to_string(),
                enabled: false,
                created_at: now,
            },
        ]);
    }
    {
        let mut groups = admin.state.groups.write().await;
        groups.clear();
        groups.extend([
            IamGroup {
                name: "ops".to_string(),
                members: vec!["ops".to_string()],
            },
            IamGroup {
                name: "audit".to_string(),
                members: vec!["auditor".to_string()],
            },
        ]);
    }
    {
        let mut policies = admin.state.policies.write().await;
        policies.clear();
        policies.extend([
            IamPolicy {
                name: "ops-read".to_string(),
                document: json!({ "Statement": ["cluster:read"] }),
                attached_to: vec!["ops".to_string()],
            },
            IamPolicy {
                name: "audit-read".to_string(),
                document: json!({ "Statement": ["audit:read"] }),
                attached_to: vec!["auditor".to_string()],
            },
        ]);
    }
    {
        let mut service_accounts = admin.state.service_accounts.write().await;
        service_accounts.clear();
        service_accounts.extend([
            ServiceAccount {
                access_key: "svc-active".to_string(),
                secret_key: "secret-active".to_string(),
                owner: "ops".to_string(),
                created_at: now,
                status: "enabled".to_string(),
            },
            ServiceAccount {
                access_key: "svc-disabled".to_string(),
                secret_key: "secret-disabled".to_string(),
                owner: "auditor".to_string(),
                created_at: now,
                status: "disabled".to_string(),
            },
        ]);
    }
    {
        let mut admin_sessions = admin.state.admin_sessions.write().await;
        admin_sessions.clear();
        admin_sessions.extend([
            current_admin_session,
            ConsoleSession {
                session_id: "console-expiring".to_string(),
                principal: "ops".to_string(),
                role: "operator".to_string(),
                permissions: vec!["cluster:read".to_string()],
                provider: "local".to_string(),
                status: "active".to_string(),
                issued_at: now - ChronoDuration::minutes(15),
                access_expires_at: now + ChronoDuration::hours(2),
                refresh_expires_at: now + ChronoDuration::days(1),
                last_refreshed_at: Some(now - ChronoDuration::minutes(5)),
                revoked_at: None,
                revoked_reason: None,
            },
        ]);
    }
    {
        let mut sts_sessions = admin.state.sts_sessions.write().await;
        sts_sessions.clear();
        sts_sessions.push(StsSession {
            session_id: "sts-expiring".to_string(),
            principal: "ops".to_string(),
            access_key: "sts-ak".to_string(),
            secret_key: "sts-sk".to_string(),
            session_token: "sts-token".to_string(),
            provider: "manual".to_string(),
            role_arn: None,
            session_name: Some("ops-session".to_string()),
            session_policy: None,
            subject: None,
            audience: None,
            status: "active".to_string(),
            issued_at: now - ChronoDuration::minutes(10),
            expires_at: now + ChronoDuration::hours(1),
        });
    }
    {
        let mut queue = admin.state.alert_delivery_queue.write().await;
        queue.clear();
        queue.extend([
            AlertDeliveryItem {
                id: "delivery-pending".to_string(),
                history_id: "history-repl-dr-b".to_string(),
                rule_id: Some("rule-repl".to_string()),
                channel_id: "channel-webhook-main".to_string(),
                channel_kind: "webhook".to_string(),
                endpoint: "https://hooks.example.internal/rustio".to_string(),
                status: "pending".to_string(),
                attempts: 0,
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now,
                last_attempt_at: None,
                next_attempt_at: now,
                payload: json!({}),
                idempotency_key: "pending".to_string(),
            },
            AlertDeliveryItem {
                id: "delivery-failed".to_string(),
                history_id: "history-repl-dr-b".to_string(),
                rule_id: Some("rule-repl".to_string()),
                channel_id: "channel-email-ops".to_string(),
                channel_kind: "email".to_string(),
                endpoint: "ops@example.internal".to_string(),
                status: "failed".to_string(),
                attempts: 2,
                last_error: "SMTP 认证失败 / smtp authentication failed".to_string(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(3),
                last_attempt_at: Some(now - ChronoDuration::minutes(1)),
                next_attempt_at: now + ChronoDuration::minutes(1),
                payload: json!({}),
                idempotency_key: "failed".to_string(),
            },
            AlertDeliveryItem {
                id: "delivery-done".to_string(),
                history_id: "history-capacity".to_string(),
                rule_id: Some("rule-capacity".to_string()),
                channel_id: "channel-webhook-main".to_string(),
                channel_kind: "webhook".to_string(),
                endpoint: "https://hooks.example.internal/rustio".to_string(),
                status: "done".to_string(),
                attempts: 1,
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(4),
                last_attempt_at: Some(now - ChronoDuration::minutes(3)),
                next_attempt_at: now - ChronoDuration::minutes(3),
                payload: json!({}),
                idempotency_key: "done".to_string(),
            },
        ]);
    }
    {
        let mut audits = admin.state.audits.write().await;
        audits.clear();
        audits.extend([
            AuditEvent {
                id: "audit-auth".to_string(),
                actor: "admin".to_string(),
                action: "auth.login".to_string(),
                resource: "auth/session/admin".to_string(),
                outcome: "success".to_string(),
                reason: None,
                timestamp: now - ChronoDuration::minutes(6),
                details: json!({ "provider": "local", "session_id": "session-1" }),
            },
            AuditEvent {
                id: "audit-kms".to_string(),
                actor: "admin".to_string(),
                action: "security.kms.rotate".to_string(),
                resource: "security/kms".to_string(),
                outcome: "partial_failed".to_string(),
                reason: Some("夜间轮换".to_string()),
                timestamp: now - ChronoDuration::minutes(4),
                details: json!({
                    "status": "partial_failed",
                    "retry_only_failed": false,
                    "failed": 1
                }),
            },
            AuditEvent {
                id: "audit-alert".to_string(),
                actor: "alert-delivery-worker".to_string(),
                action: "alerts.channel.test".to_string(),
                resource: "alerts/channel/channel-email-ops".to_string(),
                outcome: "failed".to_string(),
                reason: Some("smtp auth".to_string()),
                timestamp: now - ChronoDuration::minutes(2),
                details: json!({ "channel_id": "channel-email-ops", "kind": "email" }),
            },
        ]);
    }
    let response = admin
        .client
        .get(format!("{}/api/v1/system/metrics/summary", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("metrics summary request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .json::<Value>()
        .await
        .expect("metrics summary response should be json");

    assert_eq!(
        body.pointer("/data/cluster_status"),
        Some(&json!("degraded"))
    );
    assert_eq!(body.pointer("/data/nodes/online"), Some(&json!(2)));
    assert_eq!(body.pointer("/data/nodes/offline"), Some(&json!(1)));
    assert_eq!(
        body.pointer("/data/replication/rules_total"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/replication/backlog_total"),
        Some(&json!(4))
    );
    assert_eq!(
        body.pointer("/data/replication/backlog_in_progress"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/replication/backlog_failed"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/replication/backlog_dead_letter"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/replication/checkpoints_total"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/replication/backlog_sla_firing_sites"),
        Some(&json!(1))
    );
    assert_eq!(body.pointer("/data/alerts/channels_total"), Some(&json!(2)));
    assert_eq!(
        body.pointer("/data/alerts/channels_healthy"),
        Some(&json!(1))
    );
    assert_eq!(body.pointer("/data/alerts/firing_alerts"), Some(&json!(1)));
    assert_eq!(
        body.pointer("/data/alerts/delivery_queued"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/alerts/delivery_failed"),
        Some(&json!(1))
    );
    assert_eq!(body.pointer("/data/alerts/delivery_done"), Some(&json!(1)));
    assert_eq!(
        body.pointer("/data/alerts/last_delivery_error"),
        Some(&json!("SMTP 认证失败 / smtp authentication failed"))
    );
    assert_eq!(body.pointer("/data/iam/users_total"), Some(&json!(3)));
    assert_eq!(body.pointer("/data/iam/users_enabled"), Some(&json!(2)));
    assert_eq!(body.pointer("/data/iam/groups_total"), Some(&json!(2)));
    assert_eq!(body.pointer("/data/iam/policies_total"), Some(&json!(2)));
    assert_eq!(
        body.pointer("/data/iam/service_accounts_total"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/iam/service_accounts_enabled"),
        Some(&json!(1))
    );
    assert_eq!(body.pointer("/data/audit/events_total"), Some(&json!(3)));
    assert_eq!(
        body.pointer("/data/audit/auth_events_total"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/audit/kms_events_total"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/audit/alert_events_total"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/audit/failed_outcomes_total"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/security/ldap_enabled"),
        Some(&json!(false))
    );
    assert_eq!(
        body.pointer("/data/security/kms_healthy"),
        Some(&json!(true))
    );
    assert_eq!(body.pointer("/data/kms/healthy"), Some(&json!(true)));
    assert_eq!(
        body.pointer("/data/kms/rotation_status"),
        Some(&json!("partial_failed"))
    );
    assert_eq!(body.pointer("/data/kms/rotation_failed"), Some(&json!(1)));
    assert_eq!(
        body.pointer("/data/kms/retry_recommended"),
        Some(&json!(true))
    );
    assert_eq!(
        body.pointer("/data/kms/rotation_failed_objects_preview/0/bucket"),
        Some(&json!("photos"))
    );
    assert_eq!(
        body.pointer("/data/kms/rotation_failed_objects_preview/0/object_key"),
        Some(&json!("2026/03/b.jpg"))
    );
    assert_eq!(
        body.pointer("/data/kms/rotation_failed_objects_preview/0/stage"),
        Some(&json!("rewrap"))
    );
    assert_eq!(
        body.pointer("/data/kms/rotation_failed_objects_preview/0/retry_id"),
        Some(&json!("photos/2026/03/b.jpg"))
    );
    assert_eq!(body.pointer("/data/jobs/running"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/pending"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/completed"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/failed"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/cancelled"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/idle"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/other"), Some(&json!(1)));
    assert_eq!(body.pointer("/data/jobs/async_total"), Some(&json!(13)));
    assert_eq!(body.pointer("/data/jobs/async_pending"), Some(&json!(2)));
    assert_eq!(
        body.pointer("/data/jobs/async_in_progress"),
        Some(&json!(2))
    );
    assert_eq!(body.pointer("/data/jobs/async_completed"), Some(&json!(3)));
    assert_eq!(body.pointer("/data/jobs/async_failed"), Some(&json!(3)));
    assert_eq!(
        body.pointer("/data/jobs/async_dead_letter"),
        Some(&json!(1))
    );
    assert_eq!(body.pointer("/data/jobs/async_retryable"), Some(&json!(4)));
    assert_eq!(
        body.pointer("/data/storage/governance/scan_runs_total"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/storage/governance/scan_failures_total"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/storage/governance/heal_objects_total"),
        Some(&json!(3))
    );
    assert_eq!(
        body.pointer("/data/storage/governance/heal_failures_total"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/storage/governance/last_scan_result"),
        Some(&json!("degraded"))
    );
    assert_eq!(
        body.pointer("/data/sessions/admin_sessions_total"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/sessions/admin_sessions_expiring_24h"),
        Some(&json!(2))
    );
    assert_eq!(
        body.pointer("/data/sessions/sts_sessions_total"),
        Some(&json!(1))
    );
    assert_eq!(
        body.pointer("/data/sessions/sts_sessions_expiring_24h"),
        Some(&json!(1))
    );

    let replication_sites = body
        .pointer("/data/replication/sites")
        .and_then(Value::as_array)
        .expect("replication sites array should exist");
    let dr_site_b = replication_sites
        .iter()
        .find(|item| item.pointer("/site_id") == Some(&json!("dr-site-b")))
        .expect("dr-site-b metrics should exist");
    assert_eq!(dr_site_b.pointer("/backlog_failed"), Some(&json!(1)));
    assert_eq!(dr_site_b.pointer("/backlog_dead_letter"), Some(&json!(1)));
    assert_eq!(
        dr_site_b.pointer("/backlog_sla_status"),
        Some(&json!("firing"))
    );
    assert_eq!(dr_site_b.pointer("/firing_alerts"), Some(&json!(1)));

    let kms_status = admin
        .client
        .get(format!("{}/api/v1/security/kms/status", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("kms status request should complete");
    assert_eq!(kms_status.status(), StatusCode::OK);
    let kms_status = kms_status
        .json::<Value>()
        .await
        .expect("kms status response should be json");
    assert_eq!(
        kms_status.pointer("/data/rotation_status"),
        Some(&json!("partial_failed"))
    );
    assert_eq!(
        kms_status.pointer("/data/rotation_last_failure_reason"),
        Some(&json!(
            "轮换失败，需重试失败对象 / rotation failed, retry failed objects"
        ))
    );
    assert_eq!(
        kms_status.pointer("/data/retry_recommended"),
        Some(&json!(true))
    );
    assert_eq!(
        kms_status.pointer("/data/rotation_failed_objects_preview/0/message"),
        Some(&json!(
            "KMS 数据密钥重新包裹失败 / failed to rewrap KMS data key"
        ))
    );

    admin.stop().await;
}

#[tokio::test]
async fn system_storage_disks_reports_missing_and_corrupted_shards() {
    let admin = AdminServer::spawn().await;
    let bucket = "disk-metrics";
    let key = "objects/a.bin";
    let payload = b"disk-metrics-payload".to_vec();

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let put_object = admin
        .client
        .put(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .body(payload)
        .send()
        .await
        .expect("put object request should complete");
    assert_eq!(put_object.status(), StatusCode::OK);

    let manifest_path = admin
        .data_dir
        .join(bucket)
        .join(".rustio_ec_meta")
        .join(format!("{}.json", sha256_hex_test(key.as_bytes())));
    let manifest = serde_json::from_slice::<EcManifestFile>(
        &std::fs::read(&manifest_path).expect("manifest should exist after object write"),
    )
    .expect("manifest should decode");
    assert!(
        manifest.shards.len() >= 2,
        "manifest should include at least two shards"
    );

    let missing_disk_index = manifest.shards[0].disk_index;
    let corrupted_disk_index = manifest.shards[1].disk_index;
    std::fs::remove_file(&manifest.shards[0].path).expect("missing shard should be removable");
    std::fs::write(&manifest.shards[1].path, b"corrupted-shard")
        .expect("corrupted shard should be writable");

    let access_token = admin.login_access_token().await;

    let disks_response = admin
        .client
        .get(format!("{}/api/v1/system/storage/disks", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("storage disks request should complete");
    assert_eq!(disks_response.status(), StatusCode::OK);
    let disks_body = disks_response
        .json::<Value>()
        .await
        .expect("storage disks response should be json");
    let disks = disks_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("storage disks array should exist");
    let missing_disk = disks
        .iter()
        .find(|item| item.pointer("/disk_id") == Some(&json!(format!("disk-{missing_disk_index}"))))
        .expect("missing disk entry should exist");
    let corrupted_disk = disks
        .iter()
        .find(|item| {
            item.pointer("/disk_id") == Some(&json!(format!("disk-{corrupted_disk_index}")))
        })
        .expect("corrupted disk entry should exist");
    assert_eq!(missing_disk.pointer("/shard_missing"), Some(&json!(1)));
    assert_eq!(missing_disk.pointer("/status"), Some(&json!("degraded")));
    assert_eq!(corrupted_disk.pointer("/shard_corrupted"), Some(&json!(1)));
    assert_eq!(corrupted_disk.pointer("/status"), Some(&json!("degraded")));

    let summary_response = admin
        .client
        .get(format!("{}/api/v1/system/metrics/summary", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("metrics summary request should complete");
    assert_eq!(summary_response.status(), StatusCode::OK);
    let summary_body = summary_response
        .json::<Value>()
        .await
        .expect("metrics summary should decode");
    assert_eq!(
        summary_body.pointer("/data/storage/disks_total"),
        Some(&json!(5))
    );
    assert_eq!(
        summary_body.pointer("/data/storage/disks_degraded"),
        Some(&json!(2))
    );
    assert_eq!(
        summary_body.pointer("/data/storage/shard_missing_total"),
        Some(&json!(1))
    );
    assert_eq!(
        summary_body.pointer("/data/storage/shard_corrupted_total"),
        Some(&json!(1))
    );

    let prometheus_response = admin
        .client
        .get(format!("{}/metrics", admin.base_url))
        .send()
        .await
        .expect("prometheus metrics request should complete");
    assert_eq!(prometheus_response.status(), StatusCode::OK);
    let prometheus_body = prometheus_response
        .text()
        .await
        .expect("prometheus body should be readable");
    assert!(
        prometheus_body.contains(&format!(
            "rustio_storage_disk_shards_total{{disk_id=\"disk-{missing_disk_index}\",status=\"missing\",disk_status=\"degraded\"}} 1"
        )),
        "prometheus output should expose missing shard metric: {prometheus_body}"
    );
    assert!(
        prometheus_body.contains(&format!(
            "rustio_storage_disk_shards_total{{disk_id=\"disk-{corrupted_disk_index}\",status=\"corrupted\",disk_status=\"degraded\"}} 1"
        )),
        "prometheus output should expose corrupted shard metric: {prometheus_body}"
    );

    admin.stop().await;
}

#[tokio::test]
async fn storage_governance_decommission_rebalances_object_off_target_disk() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let disk_root = std::env::temp_dir().join(format!(
        "rustio-storage-decommission-disks-{}-{nonce}",
        std::process::id()
    ));
    for index in 0..6 {
        std::fs::create_dir_all(disk_root.join(format!("disk-{index}")))
            .expect("test disk directory should be creatable");
    }
    let disks_csv = (0..6)
        .map(|index| {
            disk_root
                .join(format!("disk-{index}"))
                .display()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(",");
    let admin = AdminServer::spawn_with_env(&[
        ("RUSTIO_DATA_DISKS", disks_csv.as_str()),
        ("RUSTIO_STORAGE_HEAL_INTERVAL_MS", "100"),
        ("RUSTIO_STORAGE_SCAN_INTERVAL_MS", "10000"),
    ])
    .await;
    let bucket = "governance-decommission";
    let key = "objects/decommission.bin";
    let payload = b"storage-governance-decommission".to_vec();

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let put_object = admin
        .client
        .put(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .body(payload.clone())
        .send()
        .await
        .expect("put object request should complete");
    assert_eq!(put_object.status(), StatusCode::OK);

    let manifest_before = read_manifest_file(&admin.data_dir, bucket, key);
    let decommission_disk_id = format!("disk-{}", manifest_before.shards[0].disk_index);
    let access_token = admin.login_access_token().await;

    let decommission_response = admin
        .client
        .post(format!(
            "{}/api/v1/storage/governance/decommission",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "disk_ids": [decommission_disk_id.clone()],
            "reason": "P0 退役闭环回归"
        }))
        .send()
        .await
        .expect("decommission request should complete");
    assert_eq!(decommission_response.status(), StatusCode::OK);

    let completed_job =
        wait_for_storage_job_status(&admin, "decommission", Some(bucket), Some(key), "completed")
            .await;
    assert_eq!(completed_job.pointer("/bucket"), Some(&json!(bucket)));
    wait_for_governance_disk_state(&admin, &decommission_disk_id, "decommissioned").await;

    let manifest_after = read_manifest_file(&admin.data_dir, bucket, key);
    let disk_ids_after = disk_ids_from_manifest(&manifest_after);
    assert!(
        !disk_ids_after.contains(&decommission_disk_id),
        "decommissioned disk should disappear from manifest: {disk_ids_after:?}"
    );

    let get_object = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("get object request should complete");
    assert_eq!(get_object.status(), StatusCode::OK);
    assert_eq!(
        get_object
            .bytes()
            .await
            .expect("get object body should be readable")
            .to_vec(),
        payload
    );

    let next_key = "objects/post-decommission.bin";
    let next_payload = b"storage-governance-post-decommission".to_vec();
    let put_next = admin
        .client
        .put(format!("{}/{}/{}", admin.base_url, bucket, next_key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .body(next_payload.clone())
        .send()
        .await
        .expect("put next object request should complete");
    assert_eq!(put_next.status(), StatusCode::OK);

    let next_manifest = read_manifest_file(&admin.data_dir, bucket, next_key);
    let next_disk_ids = disk_ids_from_manifest(&next_manifest);
    assert!(
        !next_disk_ids.contains(&decommission_disk_id),
        "new writes should avoid decommissioned disks: {next_disk_ids:?}"
    );

    let governance_response = admin
        .client
        .get(format!("{}/api/v1/storage/governance", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("governance status request should complete");
    assert_eq!(governance_response.status(), StatusCode::OK);
    let governance_body = governance_response
        .json::<Value>()
        .await
        .expect("governance response should decode");
    assert_eq!(
        governance_body.pointer("/data/summary/decommissioned_disks"),
        Some(&json!(1))
    );
    assert_eq!(
        governance_body.pointer("/data/summary/decommission_objects_total"),
        Some(&json!(1))
    );

    admin.stop().await;
    let _ = std::fs::remove_dir_all(&disk_root);
}

#[tokio::test]
async fn storage_governance_rebalance_moves_legacy_layout_to_balanced_layout() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let disk_root = std::env::temp_dir().join(format!(
        "rustio-storage-rebalance-disks-{}-{nonce}",
        std::process::id()
    ));
    for index in 0..6 {
        std::fs::create_dir_all(disk_root.join(format!("disk-{index}")))
            .expect("test disk directory should be creatable");
    }
    let disks_csv = (0..6)
        .map(|index| {
            disk_root
                .join(format!("disk-{index}"))
                .display()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(",");
    let admin = AdminServer::spawn_with_env(&[
        ("RUSTIO_DATA_DISKS", disks_csv.as_str()),
        ("RUSTIO_STORAGE_HEAL_INTERVAL_MS", "100"),
        ("RUSTIO_STORAGE_SCAN_INTERVAL_MS", "10000"),
    ])
    .await;
    let bucket = "governance-rebalance";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let legacy_disk_ids = vec![
        "disk-0".to_string(),
        "disk-1".to_string(),
        "disk-2".to_string(),
        "disk-3".to_string(),
        "disk-4".to_string(),
    ];
    let mut selected_key = None::<String>;
    let mut desired_manifest = None::<EcManifestFile>;
    let payload = b"storage-governance-rebalance".to_vec();
    for attempt in 0..24 {
        let key = format!("objects/rebalance-{attempt}.bin");
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(payload.clone())
            .send()
            .await
            .expect("put object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
        let manifest = read_manifest_file(&admin.data_dir, bucket, &key);
        if disk_ids_from_manifest(&manifest) != legacy_disk_ids {
            selected_key = Some(key);
            desired_manifest = Some(manifest);
            break;
        }
    }

    let key = selected_key.expect("at least one object should hash to a non-legacy layout");
    let desired_manifest = desired_manifest.expect("desired manifest should exist");
    let desired_disk_ids = disk_ids_from_manifest(&desired_manifest);
    let object_hash = sha256_hex_test(key.as_bytes());
    let mut legacy_manifest = desired_manifest.clone();
    let original_shards = desired_manifest.shards.clone();
    let mut legacy_shards = Vec::with_capacity(original_shards.len());
    for shard in &original_shards {
        let bytes = std::fs::read(&shard.path).expect("original shard should be readable");
        let legacy_path = disk_root
            .join(format!("disk-{}", shard.shard_index))
            .join(bucket)
            .join(".rustio_ec")
            .join(&object_hash)
            .join(format!("{}.bin", shard.shard_index));
        if let Some(parent) = legacy_path.parent() {
            std::fs::create_dir_all(parent).expect("legacy shard parent should be creatable");
        }
        std::fs::write(&legacy_path, &bytes).expect("legacy shard should be writable");
        legacy_shards.push(EcManifestShardFile {
            shard_index: shard.shard_index,
            disk_index: shard.shard_index,
            path: legacy_path,
            checksum: shard.checksum.clone(),
        });
    }
    legacy_manifest.shards = legacy_shards.clone();
    legacy_manifest.updated_at = Utc::now();
    std::fs::write(
        manifest_path_for(&admin.data_dir, bucket, &key),
        serde_json::to_vec_pretty(&legacy_manifest).expect("legacy manifest should encode"),
    )
    .expect("legacy manifest should be writable");
    for shard in original_shards {
        let legacy_path = disk_root
            .join(format!("disk-{}", shard.shard_index))
            .join(bucket)
            .join(".rustio_ec")
            .join(&object_hash)
            .join(format!("{}.bin", shard.shard_index));
        if shard.path != legacy_path {
            let _ = std::fs::remove_file(&shard.path);
        }
    }

    let access_token = admin.login_access_token().await;
    let rebalance_response = admin
        .client
        .post(format!(
            "{}/api/v1/storage/governance/rebalance",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "reason": "P0 重平衡闭环回归"
        }))
        .send()
        .await
        .expect("rebalance request should complete");
    assert_eq!(rebalance_response.status(), StatusCode::OK);

    wait_for_storage_job_status(&admin, "rebalance", Some(bucket), Some(&key), "completed").await;

    let manifest_after = read_manifest_file(&admin.data_dir, bucket, &key);
    assert_eq!(disk_ids_from_manifest(&manifest_after), desired_disk_ids);

    let get_object = admin
        .client
        .get(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("get object request should complete");
    assert_eq!(get_object.status(), StatusCode::OK);
    assert_eq!(
        get_object
            .bytes()
            .await
            .expect("get object body should be readable")
            .to_vec(),
        payload
    );

    let governance_response = admin
        .client
        .get(format!("{}/api/v1/storage/governance", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("governance status request should complete");
    assert_eq!(governance_response.status(), StatusCode::OK);
    let governance_body = governance_response
        .json::<Value>()
        .await
        .expect("governance response should decode");
    assert_eq!(
        governance_body.pointer("/data/summary/rebalance_objects_total"),
        Some(&json!(1))
    );

    admin.stop().await;
    let _ = std::fs::remove_dir_all(&disk_root);
}

#[tokio::test]
async fn async_job_endpoints_support_summary_page_filter_and_bulk_actions() {
    let admin = AdminServer::spawn().await;
    let now = Utc::now();
    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.clear();
        backlog.extend([
            ReplicationBacklogItem {
                id: "repl-pending-a".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/a.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 21,
                idempotency_key: "repl-pending-a".to_string(),
                version_id: Some("v1".to_string()),
                attempts: 0,
                status: "pending".to_string(),
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(5),
                last_attempt_at: now - ChronoDuration::minutes(5),
            },
            ReplicationBacklogItem {
                id: "repl-failed-b".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-b".to_string(),
                object_key: "2026/03/b.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 22,
                idempotency_key: "repl-failed-b".to_string(),
                version_id: Some("v2".to_string()),
                attempts: 2,
                status: "failed".to_string(),
                last_error: "network jitter".to_string(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(4),
                last_attempt_at: now - ChronoDuration::minutes(4),
            },
            ReplicationBacklogItem {
                id: "repl-done-c".to_string(),
                source_bucket: "photos".to_string(),
                target_site: "dr-site-b".to_string(),
                object_key: "2026/03/c.jpg".to_string(),
                rule_id: None,
                priority: 100,
                operation: "delete".to_string(),
                checkpoint: 23,
                idempotency_key: "repl-done-c".to_string(),
                version_id: None,
                attempts: 1,
                status: "done".to_string(),
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(3),
                last_attempt_at: now - ChronoDuration::minutes(3),
            },
        ]);
    }
    {
        let mut queue = admin.state.alert_delivery_queue.write().await;
        queue.clear();
        queue.push(AlertDeliveryItem {
            id: "notification-failed-1".to_string(),
            history_id: "history-1".to_string(),
            rule_id: Some("rule-1".to_string()),
            channel_id: "channel-webhook-main".to_string(),
            channel_kind: "webhook".to_string(),
            endpoint: "https://hooks.example.internal/rustio".to_string(),
            status: "failed".to_string(),
            attempts: 2,
            last_error: "delivery timeout".to_string(),
            lease_owner: None,
            lease_until: None,
            queued_at: now - ChronoDuration::minutes(2),
            last_attempt_at: Some(now - ChronoDuration::minutes(2)),
            next_attempt_at: now - ChronoDuration::minutes(1),
            payload: json!({
                "kind": "bucket-notification",
                "bucket": "photos",
                "key": "2026/03/notify.jpg",
            }),
            idempotency_key: "notification-failed-1".to_string(),
        });
    }
    {
        let mut jobs = admin.state.jobs.write().await;
        jobs.clear();
        let mut job_failover = test_job_status(
            "job-failover-1",
            "failover",
            "completed",
            0,
            1.0,
            now - ChronoDuration::minutes(1),
        );
        job_failover.site_id = Some("dr-site-b".to_string());
        job_failover.attempt = 1;
        job_failover.checkpoint = Some(30);

        let mut job_failback = test_job_status(
            "job-failback-1",
            "failback",
            "completed",
            0,
            1.0,
            now - ChronoDuration::seconds(50),
        );
        job_failback.site_id = Some("dr-site-a".to_string());
        job_failback.attempt = 1;
        job_failback.checkpoint = Some(31);

        let mut job_lifecycle = test_job_status(
            "job-lifecycle-1",
            "lifecycle",
            "pending",
            1,
            0.0,
            now - ChronoDuration::seconds(40),
        );
        job_lifecycle.bucket = Some("photos".to_string());
        job_lifecycle.object_key = Some("2026/03/ttl.jpg".to_string());
        job_lifecycle.checkpoint = Some(32);

        jobs.extend([job_failover, job_failback, job_lifecycle]);
    }

    let access_token = admin.login_access_token().await;

    let summary = admin
        .client
        .get(format!("{}/api/v1/jobs/async/summary", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("async summary request should complete");
    assert_eq!(summary.status(), StatusCode::OK);
    let summary_body = summary
        .json::<Value>()
        .await
        .expect("async summary response should be json");
    assert_eq!(summary_body.pointer("/data/total"), Some(&json!(7)));
    assert_eq!(summary_body.pointer("/data/pending"), Some(&json!(2)));
    assert_eq!(summary_body.pointer("/data/completed"), Some(&json!(3)));
    assert_eq!(summary_body.pointer("/data/failed"), Some(&json!(2)));
    assert_eq!(summary_body.pointer("/data/retryable"), Some(&json!(2)));

    let page = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async/page?kind=replication&limit=2",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("async page request should complete");
    assert_eq!(page.status(), StatusCode::OK);
    let page_body = page
        .json::<Value>()
        .await
        .expect("async page response should be json");
    let page_items = page_body
        .pointer("/data/items")
        .and_then(Value::as_array)
        .expect("async page items should exist");
    assert_eq!(page_items.len(), 2);
    assert!(page_body.pointer("/data/next_cursor").is_some());

    let next_cursor = page_body
        .pointer("/data/next_cursor")
        .and_then(Value::as_str)
        .expect("next cursor should exist")
        .to_string();
    let second_page = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async/page?kind=replication&limit=2&cursor={}",
            admin.base_url, next_cursor
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("second async page request should complete");
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page_body = second_page
        .json::<Value>()
        .await
        .expect("second async page response should be json");
    let second_page_items = second_page_body
        .pointer("/data/items")
        .and_then(Value::as_array)
        .expect("second async page items should exist");
    assert_eq!(second_page_items.len(), 1);

    let notification_filtered = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async?kind=notification&status=failed",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("async filter request should complete");
    assert_eq!(notification_filtered.status(), StatusCode::OK);
    let filtered_body = notification_filtered
        .json::<Value>()
        .await
        .expect("async filter response should be json");
    let filtered_items = filtered_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("filtered items should exist");
    assert_eq!(filtered_items.len(), 1);
    assert_eq!(
        filtered_items[0].pointer("/kind"),
        Some(&json!("notification"))
    );

    let retry_response = admin
        .client
        .post(format!(
            "{}/api/v1/jobs/async/bulk/retry?kind=replication&status=failed",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .json(&json!({}))
        .send()
        .await
        .expect("async retry request should complete");
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_body = retry_response
        .json::<Value>()
        .await
        .expect("async retry response should be json");
    assert_eq!(retry_body.pointer("/data/updated"), Some(&json!(1)));
    assert_eq!(retry_body.pointer("/data/matched"), Some(&json!(1)));

    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.push(ReplicationBacklogItem {
            id: "repl-in-progress-c".to_string(),
            source_bucket: "photos".to_string(),
            target_site: "dr-site-b".to_string(),
            object_key: "2026/03/in-progress.jpg".to_string(),
            rule_id: None,
            priority: 100,
            operation: "put".to_string(),
            checkpoint: 24,
            idempotency_key: "repl-in-progress-c".to_string(),
            version_id: Some("v3".to_string()),
            attempts: 1,
            status: "in_progress".to_string(),
            last_error: "lease active".to_string(),
            lease_owner: Some("worker-1".to_string()),
            lease_until: Some(now + ChronoDuration::minutes(2)),
            queued_at: now - ChronoDuration::minutes(1),
            last_attempt_at: now - ChronoDuration::seconds(30),
        });
    }

    let retry_in_progress_response = admin
        .client
        .post(format!("{}/api/v1/jobs/async/bulk/retry", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({ "job_ids": ["repl-in-progress-c"] }))
        .send()
        .await
        .expect("async retry in-progress request should complete");
    assert_eq!(retry_in_progress_response.status(), StatusCode::OK);
    let retry_in_progress_body = retry_in_progress_response
        .json::<Value>()
        .await
        .expect("async retry in-progress response should be json");
    assert_eq!(
        retry_in_progress_body.pointer("/data/matched"),
        Some(&json!(1))
    );
    assert_eq!(
        retry_in_progress_body.pointer("/data/updated"),
        Some(&json!(0))
    );
    assert_eq!(
        retry_in_progress_body.pointer("/data/skipped"),
        Some(&json!(1))
    );
    {
        let backlog = admin.state.replication_backlog.read().await;
        let in_progress = backlog
            .iter()
            .find(|entry| entry.id == "repl-in-progress-c")
            .expect("in-progress backlog item should remain");
        assert_eq!(in_progress.status, "in_progress");
        assert_eq!(in_progress.lease_owner.as_deref(), Some("worker-1"));
    }

    let cleanup_response = admin
        .client
        .post(format!(
            "{}/api/v1/jobs/async/bulk/cleanup?kind=failover",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .json(&json!({}))
        .send()
        .await
        .expect("async cleanup request should complete");
    assert_eq!(cleanup_response.status(), StatusCode::OK);
    let cleanup_body = cleanup_response
        .json::<Value>()
        .await
        .expect("async cleanup response should be json");
    assert_eq!(cleanup_body.pointer("/data/removed"), Some(&json!(1)));

    let skip_response = admin
        .client
        .post(format!(
            "{}/api/v1/jobs/async/bulk/skip?kind=lifecycle&status=pending",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .json(&json!({}))
        .send()
        .await
        .expect("async skip request should complete");
    assert_eq!(skip_response.status(), StatusCode::OK);
    let skip_body = skip_response
        .json::<Value>()
        .await
        .expect("async skip response should be json");
    assert_eq!(skip_body.pointer("/data/updated"), Some(&json!(1)));

    let system_summary = admin
        .client
        .get(format!("{}/api/v1/system/metrics/summary", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("system summary should complete");
    assert_eq!(system_summary.status(), StatusCode::OK);
    let system_summary_body = system_summary
        .json::<Value>()
        .await
        .expect("system summary response should be json");
    assert_eq!(
        system_summary_body.pointer("/data/jobs/async_total"),
        Some(&json!(7))
    );

    admin.stop().await;
}

#[tokio::test]
async fn batch_replication_requeue_creates_batch_runs_and_surfaces_in_async_jobs() {
    let admin = AdminServer::spawn().await;
    let bucket = "batch-requeue";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, payload) in [
        ("logs/a.txt", "log-a"),
        ("logs/b.txt", "log-b"),
        ("images/c.txt", "image-c"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(payload.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let access_token = admin.login_access_token().await;
    let create_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "logs-dr-batch",
            "target_site": "dr-site-batch",
            "prefix": "logs/",
            "priority": 7,
            "replicate_existing": false,
            "sync_deletes": true,
            "enabled": true
        }))
        .send()
        .await
        .expect("create replication rule request should complete");
    assert_eq!(create_rule.status(), StatusCode::OK);
    assert!(
        admin.state.replication_backlog.read().await.is_empty(),
        "replicate_existing=false should not enqueue initial backlog"
    );

    let first_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "replication-requeue",
            "source_bucket": bucket,
            "target_site": "dr-site-batch",
            "object_prefix": "logs/",
            "limit": 1
        }))
        .send()
        .await
        .expect("create batch run request should complete");
    assert_eq!(first_batch.status(), StatusCode::OK);
    let first_batch_body = first_batch
        .json::<Value>()
        .await
        .expect("create batch run response should be json");
    assert_eq!(
        first_batch_body.pointer("/data/kind"),
        Some(&json!("replication-requeue"))
    );
    assert_eq!(
        first_batch_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(first_batch_body.pointer("/data/matched"), Some(&json!(2)));
    assert_eq!(first_batch_body.pointer("/data/enqueued"), Some(&json!(1)));
    assert_eq!(first_batch_body.pointer("/data/skipped"), Some(&json!(1)));
    assert_eq!(
        first_batch_body.pointer("/data/scope/source_bucket"),
        Some(&json!(bucket))
    );
    assert_eq!(
        first_batch_body.pointer("/data/scope/target_site"),
        Some(&json!("dr-site-batch"))
    );
    assert_eq!(
        first_batch_body.pointer("/data/scope/object_prefix"),
        Some(&json!("logs/"))
    );
    let first_batch_id = first_batch_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("batch run id should exist")
        .to_string();

    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].source_bucket, bucket);
        assert_eq!(backlog[0].target_site, "dr-site-batch");
        assert!(backlog[0].object_key.starts_with("logs/"));
    }

    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.clear();
        backlog.push(test_replication_backlog_item(
            "batch-failed-a",
            bucket,
            "dr-site-batch",
            "logs/a.txt",
            Some("rule-batch"),
            7,
            "put",
            10,
            "failed",
        ));
        backlog.push(test_replication_backlog_item(
            "batch-done-b",
            bucket,
            "dr-site-batch",
            "logs/b.txt",
            Some("rule-batch"),
            7,
            "put",
            11,
            "done",
        ));
    }

    let retry_failed_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "replication-requeue",
            "source_bucket": bucket,
            "target_site": "dr-site-batch",
            "retry_only_failed": true
        }))
        .send()
        .await
        .expect("retry failed batch run request should complete");
    assert_eq!(retry_failed_batch.status(), StatusCode::OK);
    let retry_failed_body = retry_failed_batch
        .json::<Value>()
        .await
        .expect("retry failed batch run response should be json");
    assert_eq!(
        retry_failed_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(retry_failed_body.pointer("/data/matched"), Some(&json!(1)));
    assert_eq!(retry_failed_body.pointer("/data/enqueued"), Some(&json!(1)));
    assert_eq!(retry_failed_body.pointer("/data/skipped"), Some(&json!(0)));
    assert_eq!(
        retry_failed_body.pointer("/data/scope/retry_only_failed"),
        Some(&json!(true))
    );

    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 2);
        assert!(backlog
            .iter()
            .any(|entry| entry.object_key == "logs/a.txt" && entry.status == "pending"));
        assert!(backlog
            .iter()
            .all(|entry| entry.object_key != "logs/b.txt" || entry.status != "pending"));
    }

    let list_batch_runs = admin
        .client
        .get(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list batch runs request should complete");
    assert_eq!(list_batch_runs.status(), StatusCode::OK);
    let list_batch_runs_body = list_batch_runs
        .json::<Value>()
        .await
        .expect("list batch runs response should be json");
    let listed_runs = list_batch_runs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("listed batch runs should be array");
    assert!(listed_runs
        .iter()
        .any(|item| item.pointer("/id") == Some(&json!(first_batch_id))));

    let get_batch_run = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/batch/{}",
            admin.base_url, first_batch_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("get batch run request should complete");
    assert_eq!(get_batch_run.status(), StatusCode::OK);
    let get_batch_run_body = get_batch_run
        .json::<Value>()
        .await
        .expect("get batch run response should be json");
    assert_eq!(get_batch_run_body.pointer("/data/matched"), Some(&json!(2)));

    let async_jobs = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async?kind=batch:replication-requeue",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list async jobs request should complete");
    assert_eq!(async_jobs.status(), StatusCode::OK);
    let async_jobs_body = async_jobs
        .json::<Value>()
        .await
        .expect("list async jobs response should be json");
    let async_items = async_jobs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("async batch jobs should be array");
    assert_eq!(async_items.len(), 2);
    assert!(async_items
        .iter()
        .all(|item| item.pointer("/status") == Some(&json!("completed"))));

    admin.stop().await;
}

#[tokio::test]
async fn batch_lifecycle_requeue_supports_current_noncurrent_and_failed_only() {
    let admin = AdminServer::spawn().await;
    let bucket = "batch-lifecycle";
    let key = "reports/daily.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (object_key, payload) in [
        (key, "version-a"),
        (key, "version-b"),
        ("images/skip.txt", "skip-me"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, object_key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(payload.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    {
        admin.state.bucket_lifecycle_rules.write().await.insert(
            bucket.to_string(),
            vec![BucketLifecycleRule {
                id: "rule-lifecycle-batch".to_string(),
                prefix: Some("reports/".to_string()),
                status: "Enabled".to_string(),
                expiration_days: Some(0),
                noncurrent_expiration_days: Some(0),
                transition_days: None,
                transition_tier: None,
                noncurrent_transition_days: None,
                noncurrent_transition_tier: None,
            }],
        );
    }

    let access_token = admin.login_access_token().await;
    let current_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "lifecycle-requeue",
            "source_bucket": bucket,
            "object_prefix": "reports/",
            "current_only": true
        }))
        .send()
        .await
        .expect("current lifecycle batch request should complete");
    assert_eq!(current_batch.status(), StatusCode::OK);
    let current_batch_body = current_batch
        .json::<Value>()
        .await
        .expect("current lifecycle batch response should be json");
    assert_eq!(
        current_batch_body.pointer("/data/kind"),
        Some(&json!("lifecycle-requeue"))
    );
    assert_eq!(
        current_batch_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(current_batch_body.pointer("/data/matched"), Some(&json!(1)));
    assert_eq!(
        current_batch_body.pointer("/data/enqueued"),
        Some(&json!(1))
    );
    assert_eq!(
        current_batch_body.pointer("/data/scope/current_only"),
        Some(&json!(true))
    );
    let first_batch_id = current_batch_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("current lifecycle batch id should exist")
        .to_string();

    let first_current_job_id = {
        let jobs = admin.state.jobs.read().await;
        let current_jobs = jobs
            .iter()
            .filter(|job| job.kind == "lifecycle:current")
            .collect::<Vec<_>>();
        assert_eq!(current_jobs.len(), 1);
        assert_eq!(current_jobs[0].bucket.as_deref(), Some(bucket));
        assert_eq!(current_jobs[0].object_key.as_deref(), Some(key));
        assert_eq!(
            current_jobs[0].payload.pointer("/mode"),
            Some(&json!("current"))
        );
        current_jobs[0].id.clone()
    };

    {
        let mut jobs = admin.state.jobs.write().await;
        let current_job = jobs
            .iter_mut()
            .find(|job| job.id == first_current_job_id)
            .expect("current lifecycle job should exist");
        current_job.status = "failed".to_string();
        current_job.last_error = Some("模拟失败 / simulated failure".to_string());
        current_job.updated_at = Utc::now();
    }

    let retry_failed_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "lifecycle-requeue",
            "source_bucket": bucket,
            "object_prefix": "reports/",
            "current_only": true,
            "retry_only_failed": true,
            "statuses": ["failed"]
        }))
        .send()
        .await
        .expect("failed-only lifecycle batch request should complete");
    assert_eq!(retry_failed_batch.status(), StatusCode::OK);
    let retry_failed_body = retry_failed_batch
        .json::<Value>()
        .await
        .expect("failed-only lifecycle batch response should be json");
    assert_eq!(retry_failed_body.pointer("/data/matched"), Some(&json!(1)));
    assert_eq!(retry_failed_body.pointer("/data/enqueued"), Some(&json!(1)));
    assert_eq!(
        retry_failed_body.pointer("/data/scope/retry_only_failed"),
        Some(&json!(true))
    );

    {
        let jobs = admin.state.jobs.read().await;
        let current_jobs = jobs
            .iter()
            .filter(|job| job.kind == "lifecycle:current")
            .collect::<Vec<_>>();
        assert_eq!(current_jobs.len(), 1);
        assert_ne!(current_jobs[0].id, first_current_job_id);
        assert_eq!(current_jobs[0].status, "pending");
    }

    let noncurrent_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "lifecycle-requeue",
            "source_bucket": bucket,
            "object_prefix": "reports/",
            "noncurrent_only": true
        }))
        .send()
        .await
        .expect("noncurrent lifecycle batch request should complete");
    assert_eq!(noncurrent_batch.status(), StatusCode::OK);
    let noncurrent_batch_body = noncurrent_batch
        .json::<Value>()
        .await
        .expect("noncurrent lifecycle batch response should be json");
    assert_eq!(
        noncurrent_batch_body.pointer("/data/matched"),
        Some(&json!(1))
    );
    assert_eq!(
        noncurrent_batch_body.pointer("/data/enqueued"),
        Some(&json!(1))
    );
    assert_eq!(
        noncurrent_batch_body.pointer("/data/scope/noncurrent_only"),
        Some(&json!(true))
    );

    {
        let jobs = admin.state.jobs.read().await;
        let noncurrent_jobs = jobs
            .iter()
            .filter(|job| job.kind == "lifecycle:noncurrent")
            .collect::<Vec<_>>();
        assert_eq!(noncurrent_jobs.len(), 1);
        assert_eq!(noncurrent_jobs[0].bucket.as_deref(), Some(bucket));
        assert_eq!(noncurrent_jobs[0].object_key.as_deref(), Some(key));
        assert_eq!(
            noncurrent_jobs[0].payload.pointer("/mode"),
            Some(&json!("noncurrent"))
        );
    }

    let batch_runs = admin
        .client
        .get(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list lifecycle batch runs request should complete");
    assert_eq!(batch_runs.status(), StatusCode::OK);
    let batch_runs_body = batch_runs
        .json::<Value>()
        .await
        .expect("list lifecycle batch runs response should be json");
    let batch_items = batch_runs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("batch run list should be array");
    assert_eq!(batch_items.len(), 3);
    assert!(batch_items
        .iter()
        .any(|item| item.pointer("/id") == Some(&json!(first_batch_id))));

    let async_jobs = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async?kind=batch:lifecycle-requeue",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list lifecycle batch async jobs request should complete");
    assert_eq!(async_jobs.status(), StatusCode::OK);
    let async_jobs_body = async_jobs
        .json::<Value>()
        .await
        .expect("list lifecycle batch async jobs response should be json");
    let async_items = async_jobs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("lifecycle batch async jobs should be array");
    assert_eq!(async_items.len(), 3);
    assert!(async_items
        .iter()
        .all(|item| item.pointer("/kind") == Some(&json!("batch:lifecycle-requeue"))));

    admin.stop().await;
}

#[tokio::test]
async fn batch_kms_rotate_supports_scope_limit_and_failed_only_retry() {
    let admin = AdminServer::spawn().await;
    let bucket = "batch-kms-rotate";
    let log_key_a = "logs/a.txt";
    let log_key_b = "logs/b.txt";
    let image_key = "images/c.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, payload, kms_key_id) in [
        (log_key_a, "kms-a", "qa-kms-batch"),
        (log_key_b, "kms-b", "qa-kms-alt"),
        (image_key, "kms-c", "qa-kms-batch"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .header("x-amz-server-side-encryption", "aws:kms")
            .header("x-amz-server-side-encryption-aws-kms-key-id", kms_key_id)
            .body(payload.to_string())
            .send()
            .await
            .expect("seed kms object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let old_meta_a = read_object_meta_file(&admin.data_dir, bucket, log_key_a);
    let old_meta_b = read_object_meta_file(&admin.data_dir, bucket, log_key_b);
    let old_meta_c = read_object_meta_file(&admin.data_dir, bucket, image_key);
    let old_wrapped_a = old_meta_a
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object a should have wrapped key");
    let old_wrapped_b = old_meta_b
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object b should have wrapped key");
    let old_wrapped_c = old_meta_c
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object c should have wrapped key");
    let old_version_a = old_meta_a.version_id.clone();
    let old_version_b = old_meta_b.version_id.clone();
    assert_eq!(
        old_meta_a.encryption.kms_key_id.as_deref(),
        Some("qa-kms-batch")
    );
    assert_eq!(
        old_meta_b.encryption.kms_key_id.as_deref(),
        Some("qa-kms-alt")
    );
    assert_eq!(
        old_meta_c.encryption.kms_key_id.as_deref(),
        Some("qa-kms-batch")
    );

    let access_token = admin.login_access_token().await;
    let first_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "kms-rotate",
            "source_bucket": bucket,
            "object_prefix": "logs/",
            "object_key": log_key_a,
            "version_id": old_version_a.clone(),
            "kms_key_id": "qa-kms-batch",
            "limit": 1
        }))
        .send()
        .await
        .expect("create kms batch request should complete");
    assert_eq!(first_batch.status(), StatusCode::OK);
    let first_batch_body = first_batch
        .json::<Value>()
        .await
        .expect("create kms batch response should be json");
    assert_eq!(
        first_batch_body.pointer("/data/kind"),
        Some(&json!("kms-rotate"))
    );
    assert_eq!(
        first_batch_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(first_batch_body.pointer("/data/matched"), Some(&json!(1)));
    assert_eq!(first_batch_body.pointer("/data/enqueued"), Some(&json!(1)));
    assert_eq!(first_batch_body.pointer("/data/failed"), Some(&json!(0)));
    assert_eq!(
        first_batch_body.pointer("/data/scope/object_prefix"),
        Some(&json!("logs/"))
    );
    assert_eq!(
        first_batch_body.pointer("/data/scope/object_key"),
        Some(&json!(log_key_a))
    );
    assert_eq!(
        first_batch_body.pointer("/data/scope/version_id"),
        Some(&json!(old_version_a))
    );
    assert_eq!(
        first_batch_body.pointer("/data/scope/kms_key_id"),
        Some(&json!("qa-kms-batch"))
    );
    let first_batch_id = first_batch_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("kms batch id should exist")
        .to_string();

    let new_meta_a = read_object_meta_file(&admin.data_dir, bucket, log_key_a);
    let new_meta_b = read_object_meta_file(&admin.data_dir, bucket, log_key_b);
    let new_meta_c = read_object_meta_file(&admin.data_dir, bucket, image_key);
    let new_wrapped_a = new_meta_a
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object a should keep wrapped key");
    let new_wrapped_b = new_meta_b
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object b should keep wrapped key");
    let new_wrapped_c = new_meta_c
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object c should keep wrapped key");
    assert_ne!(old_wrapped_a, new_wrapped_a);
    assert_eq!(old_wrapped_b, new_wrapped_b);
    assert_eq!(old_wrapped_c, new_wrapped_c);

    {
        let mut security = admin.state.security.write().await;
        security.kms_rotation_failed_objects = vec![kms_failed_object(
            bucket,
            log_key_b,
            Some(&old_version_b),
            true,
            Some("qa-kms-alt"),
            "rewrap",
            "KMS 数据密钥重新包裹失败 / failed to rewrap KMS data key",
        )];
    }

    let retry_failed_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "kms-rotate",
            "source_bucket": bucket,
            "object_prefix": "logs/",
            "object_key": log_key_b,
            "version_id": old_version_b.clone(),
            "kms_key_id": "qa-kms-alt",
            "retry_only_failed": true
        }))
        .send()
        .await
        .expect("retry failed kms batch request should complete");
    assert_eq!(retry_failed_batch.status(), StatusCode::OK);
    let retry_failed_body = retry_failed_batch
        .json::<Value>()
        .await
        .expect("retry failed kms batch response should be json");
    assert_eq!(
        retry_failed_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(retry_failed_body.pointer("/data/matched"), Some(&json!(1)));
    assert_eq!(retry_failed_body.pointer("/data/enqueued"), Some(&json!(1)));
    assert_eq!(retry_failed_body.pointer("/data/failed"), Some(&json!(0)));
    assert_eq!(
        retry_failed_body.pointer("/data/scope/retry_only_failed"),
        Some(&json!(true))
    );
    assert_eq!(
        retry_failed_body.pointer("/data/scope/object_key"),
        Some(&json!(log_key_b))
    );
    assert_eq!(
        retry_failed_body.pointer("/data/scope/version_id"),
        Some(&json!(old_version_b))
    );
    assert_eq!(
        retry_failed_body.pointer("/data/scope/kms_key_id"),
        Some(&json!("qa-kms-alt"))
    );

    let retried_meta_a = read_object_meta_file(&admin.data_dir, bucket, log_key_a);
    let retried_wrapped_a = retried_meta_a
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object a should keep wrapped key after retry");
    let retried_meta_b = read_object_meta_file(&admin.data_dir, bucket, log_key_b);
    let retried_wrapped_b = retried_meta_b
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object b should keep wrapped key after retry");
    let retried_meta_c = read_object_meta_file(&admin.data_dir, bucket, image_key);
    let retried_wrapped_c = retried_meta_c
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("kms object c should keep wrapped key after retry");
    assert_eq!(new_wrapped_a, retried_wrapped_a);
    assert_ne!(old_wrapped_b, retried_wrapped_b);
    assert_eq!(old_wrapped_c, retried_wrapped_c);

    let get_batch_run = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/batch/{}",
            admin.base_url, first_batch_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("get kms batch run request should complete");
    assert_eq!(get_batch_run.status(), StatusCode::OK);
    let get_batch_run_body = get_batch_run
        .json::<Value>()
        .await
        .expect("get kms batch run response should be json");
    assert_eq!(get_batch_run_body.pointer("/data/matched"), Some(&json!(1)));

    let list_batch_runs = admin
        .client
        .get(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list kms batch runs request should complete");
    assert_eq!(list_batch_runs.status(), StatusCode::OK);
    let list_batch_runs_body = list_batch_runs
        .json::<Value>()
        .await
        .expect("list kms batch runs response should be json");
    let batch_items = list_batch_runs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("kms batch run list should be array");
    assert_eq!(batch_items.len(), 2);
    assert!(batch_items
        .iter()
        .all(|item| item.pointer("/kind") == Some(&json!("kms-rotate"))));

    let async_jobs = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async?kind=batch:kms-rotate",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list kms batch async jobs request should complete");
    assert_eq!(async_jobs.status(), StatusCode::OK);
    let async_jobs_body = async_jobs
        .json::<Value>()
        .await
        .expect("list kms batch async jobs response should be json");
    let async_items = async_jobs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("kms batch async jobs should be array");
    assert_eq!(async_items.len(), 2);
    assert!(async_items
        .iter()
        .all(|item| item.pointer("/status") == Some(&json!("completed"))));

    admin.stop().await;
}

#[tokio::test]
async fn batch_kms_rotate_rejects_object_key_outside_prefix() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;

    let response = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "kms-rotate",
            "object_prefix": "logs/",
            "object_key": "images/c.txt"
        }))
        .send()
        .await
        .expect("invalid kms batch request should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response
        .json::<Value>()
        .await
        .expect("invalid kms batch response should be json");
    let message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .expect("invalid kms batch error should include message");
    assert!(
        message.contains("object_key 必须落在 object_prefix 范围内"),
        "unexpected error message: {message}"
    );

    admin.stop().await;
}

#[tokio::test]
async fn kms_rotate_and_batch_expose_structured_failed_objects() {
    let admin = AdminServer::spawn().await;
    let bucket = "kms-rotate-structured-failure";
    let key = "logs/failure.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let put_object = admin
        .client
        .put(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .header("x-amz-server-side-encryption", "aws:kms")
        .header(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "qa-kms-structured",
        )
        .body("kms-structured-failure".to_string())
        .send()
        .await
        .expect("seed kms object request should complete");
    assert_eq!(put_object.status(), StatusCode::OK);

    let current_meta = read_object_meta_file(&admin.data_dir, bucket, key);
    let current_version_id = current_meta.version_id.clone();
    let access_token = admin.login_access_token().await;

    std::env::set_var("RUSTIO_KMS_EXTERNAL_ENABLED", "true");
    {
        let mut security = admin.state.security.write().await;
        security.kms_endpoint = "http://127.0.0.1:9".to_string();
    }

    let rotate_response = admin
        .client
        .post(format!("{}/api/v1/security/kms/rotate", admin.base_url))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "reason": "验证结构化失败对象 / validate structured failed objects"
        }))
        .send()
        .await
        .expect("kms rotate request should complete");
    assert_eq!(rotate_response.status(), StatusCode::OK);
    let rotate_body = rotate_response
        .json::<Value>()
        .await
        .expect("kms rotate response should be json");
    assert_eq!(rotate_body.pointer("/data/status"), Some(&json!("failed")));
    assert_eq!(rotate_body.pointer("/data/failed"), Some(&json!(1)));
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/bucket"),
        Some(&json!(bucket))
    );
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/object_key"),
        Some(&json!(key))
    );
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/version_id"),
        Some(&json!(current_version_id.clone()))
    );
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/is_current"),
        Some(&json!(true))
    );
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/kms_key_id"),
        Some(&json!("qa-kms-structured"))
    );
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/stage"),
        Some(&json!("unwrap"))
    );
    assert_eq!(
        rotate_body.pointer("/data/failed_objects/0/retry_id"),
        Some(&json!(format!(
            "{bucket}/{key}?versionId={current_version_id}"
        )))
    );

    let kms_status = admin
        .client
        .get(format!("{}/api/v1/security/kms/status", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("kms status request should complete");
    assert_eq!(kms_status.status(), StatusCode::OK);
    let kms_status_body = kms_status
        .json::<Value>()
        .await
        .expect("kms status response should be json");
    assert_eq!(
        kms_status_body.pointer("/data/rotation_failed_objects_preview/0/stage"),
        Some(&json!("unwrap"))
    );
    assert_eq!(
        kms_status_body.pointer("/data/rotation_failed_objects_preview/0/retry_id"),
        Some(&json!(format!(
            "{bucket}/{key}?versionId={current_version_id}"
        )))
    );

    let batch_response = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "kms-rotate",
            "source_bucket": bucket,
            "object_key": key,
            "version_id": current_version_id,
            "current_only": true,
            "retry_only_failed": true
        }))
        .send()
        .await
        .expect("kms batch retry request should complete");
    assert_eq!(batch_response.status(), StatusCode::OK);
    let batch_body = batch_response
        .json::<Value>()
        .await
        .expect("kms batch retry response should be json");
    assert_eq!(batch_body.pointer("/data/status"), Some(&json!("failed")));
    assert_eq!(batch_body.pointer("/data/failed"), Some(&json!(1)));
    assert_eq!(
        batch_body.pointer("/data/failed_objects_preview/0/stage"),
        Some(&json!("unwrap"))
    );
    assert_eq!(
        batch_body.pointer("/data/failed_objects_preview/0/kms_key_id"),
        Some(&json!("qa-kms-structured"))
    );
    let batch_id = batch_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("kms batch id should exist");

    let get_batch = admin
        .client
        .get(format!("{}/api/v1/jobs/batch/{}", admin.base_url, batch_id))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("get kms batch request should complete");
    assert_eq!(get_batch.status(), StatusCode::OK);
    let get_batch_body = get_batch
        .json::<Value>()
        .await
        .expect("get kms batch response should be json");
    assert_eq!(
        get_batch_body.pointer("/data/failed_objects_preview/0/retry_id"),
        Some(&json!(format!(
            "{bucket}/{key}?versionId={}",
            current_meta.version_id
        )))
    );

    std::env::remove_var("RUSTIO_KMS_EXTERNAL_ENABLED");
    admin.stop().await;
}

#[tokio::test]
async fn batch_kms_rotate_supports_current_and_noncurrent_version_scope() {
    let admin = AdminServer::spawn().await;
    let bucket = "batch-kms-versioned";
    let key = "archive/history.txt";
    let access_token = admin.login_access_token().await;

    let create_bucket = admin
        .client
        .post(format!("{}/api/v1/buckets", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "name": bucket,
            "tenant_id": "default",
            "versioning": true,
            "object_lock": false,
            "ilm_policy": null,
            "replication_policy": null
        }))
        .send()
        .await
        .expect("create versioned bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (payload, kms_key_id) in [
        ("history-version-one", "qa-kms-history-old"),
        ("history-version-two", "qa-kms-history-new"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .header("x-amz-server-side-encryption", "aws:kms")
            .header("x-amz-server-side-encryption-aws-kms-key-id", kms_key_id)
            .body(payload.to_string())
            .send()
            .await
            .expect("seed versioned kms object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let current_meta_before = read_object_meta_file(&admin.data_dir, bucket, key);
    let current_version_id = current_meta_before.version_id.clone();
    let current_wrapped_before = current_meta_before
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("current kms object should have wrapped key");
    assert_eq!(
        current_meta_before.encryption.kms_key_id.as_deref(),
        Some("qa-kms-history-new")
    );

    let versions_response = admin
        .client
        .get(format!(
            "{}/api/v1/buckets/{}/objects/versions",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .query(&[("key", key)])
        .send()
        .await
        .expect("list versioned object versions request should complete");
    assert_eq!(versions_response.status(), StatusCode::OK);
    let versions_body = versions_response
        .json::<Value>()
        .await
        .expect("list versioned object versions response should be json");
    let archived_version_id = versions_body["data"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| !item["is_latest"].as_bool().unwrap_or(false))
        })
        .and_then(|item| item["version_id"].as_str())
        .expect("archived version id should exist")
        .to_string();

    let archived_meta_before =
        read_archived_object_meta_file(&admin.data_dir, bucket, key, &archived_version_id);
    let archived_wrapped_before = archived_meta_before
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("archived kms object should have wrapped key");
    assert_eq!(
        archived_meta_before.encryption.kms_key_id.as_deref(),
        Some("qa-kms-history-old")
    );

    let noncurrent_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "kms-rotate",
            "source_bucket": bucket,
            "object_key": key,
            "version_id": archived_version_id.clone(),
            "kms_key_id": "qa-kms-history-old",
            "noncurrent_only": true
        }))
        .send()
        .await
        .expect("create noncurrent kms batch request should complete");
    assert_eq!(noncurrent_batch.status(), StatusCode::OK);
    let noncurrent_batch_body = noncurrent_batch
        .json::<Value>()
        .await
        .expect("create noncurrent kms batch response should be json");
    assert_eq!(
        noncurrent_batch_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(
        noncurrent_batch_body.pointer("/data/matched"),
        Some(&json!(1))
    );
    assert_eq!(
        noncurrent_batch_body.pointer("/data/enqueued"),
        Some(&json!(1))
    );
    assert_eq!(
        noncurrent_batch_body.pointer("/data/scope/noncurrent_only"),
        Some(&json!(true))
    );
    assert_eq!(
        noncurrent_batch_body.pointer("/data/scope/version_id"),
        Some(&json!(archived_version_id.clone()))
    );

    let archived_meta_after_first =
        read_archived_object_meta_file(&admin.data_dir, bucket, key, &archived_version_id);
    let archived_wrapped_after_first = archived_meta_after_first
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("archived kms object should keep wrapped key after rotation");
    let current_meta_after_first = read_object_meta_file(&admin.data_dir, bucket, key);
    let current_wrapped_after_first = current_meta_after_first
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("current kms object should keep wrapped key after archived rotation");
    assert_ne!(archived_wrapped_before, archived_wrapped_after_first);
    assert_eq!(current_wrapped_before, current_wrapped_after_first);

    {
        let mut security = admin.state.security.write().await;
        security.kms_rotation_failed_objects = vec![kms_failed_object(
            bucket,
            key,
            Some(&current_version_id),
            true,
            Some("qa-kms-history-new"),
            "unwrap",
            "KMS 数据密钥解包失败 / failed to unwrap KMS data key",
        )];
    }

    let current_retry_batch = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "kms-rotate",
            "source_bucket": bucket,
            "object_key": key,
            "version_id": current_version_id.clone(),
            "kms_key_id": "qa-kms-history-new",
            "current_only": true,
            "retry_only_failed": true
        }))
        .send()
        .await
        .expect("create current retry kms batch request should complete");
    assert_eq!(current_retry_batch.status(), StatusCode::OK);
    let current_retry_body = current_retry_batch
        .json::<Value>()
        .await
        .expect("create current retry kms batch response should be json");
    assert_eq!(
        current_retry_body.pointer("/data/status"),
        Some(&json!("completed"))
    );
    assert_eq!(current_retry_body.pointer("/data/matched"), Some(&json!(1)));
    assert_eq!(
        current_retry_body.pointer("/data/enqueued"),
        Some(&json!(1))
    );
    assert_eq!(
        current_retry_body.pointer("/data/scope/current_only"),
        Some(&json!(true))
    );
    assert_eq!(
        current_retry_body.pointer("/data/scope/retry_only_failed"),
        Some(&json!(true))
    );

    let current_meta_after_retry = read_object_meta_file(&admin.data_dir, bucket, key);
    let current_wrapped_after_retry = current_meta_after_retry
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("current kms object should keep wrapped key after retry");
    let archived_meta_after_retry =
        read_archived_object_meta_file(&admin.data_dir, bucket, key, &archived_version_id);
    let archived_wrapped_after_retry = archived_meta_after_retry
        .encryption
        .wrapped_key_base64
        .clone()
        .expect("archived kms object should keep wrapped key after current retry");
    assert_ne!(current_wrapped_before, current_wrapped_after_retry);
    assert_eq!(archived_wrapped_after_first, archived_wrapped_after_retry);

    let async_jobs = admin
        .client
        .get(format!(
            "{}/api/v1/jobs/async?kind=batch:kms-rotate",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("list versioned kms batch async jobs request should complete");
    assert_eq!(async_jobs.status(), StatusCode::OK);
    let async_jobs_body = async_jobs
        .json::<Value>()
        .await
        .expect("list versioned kms batch async jobs response should be json");
    let async_items = async_jobs_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("versioned kms batch async jobs should be array");
    assert_eq!(async_items.len(), 2);
    assert!(async_items
        .iter()
        .all(|item| item.pointer("/status") == Some(&json!("completed"))));

    admin.stop().await;
}

#[tokio::test]
async fn batch_replication_requeue_rejects_object_key_filter() {
    let admin = AdminServer::spawn().await;
    let bucket = "batch-requeue-invalid-scope";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let access_token = admin.login_access_token().await;
    let response = admin
        .client
        .post(format!("{}/api/v1/jobs/batch", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!({
            "kind": "replication-requeue",
            "source_bucket": bucket,
            "object_key": "logs/a.txt"
        }))
        .send()
        .await
        .expect("invalid replication batch request should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response
        .json::<Value>()
        .await
        .expect("invalid replication batch response should be json");
    let message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .expect("invalid replication batch error should include message");
    assert!(
        message.contains("复制批处理不支持 object_key 过滤"),
        "unexpected error message: {message}"
    );

    admin.stop().await;
}

#[tokio::test]
async fn failover_and_failback_routes_enqueue_and_complete_unified_switch_jobs() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;

    let failover = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/dr-site-b/failover",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({ "reason": "integration failover task" }))
        .send()
        .await
        .expect("failover enqueue request should complete");
    assert_eq!(failover.status(), StatusCode::OK);
    let failover_body = failover
        .json::<Value>()
        .await
        .expect("failover enqueue response should be json");
    let failover_job_id = failover_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("failover job id should exist")
        .to_string();
    assert_eq!(
        failover_body.pointer("/data/kind"),
        Some(&json!("failover"))
    );
    assert_eq!(
        failover_body.pointer("/data/status"),
        Some(&json!("pending"))
    );

    let mut failover_completed = false;
    for _ in 0..40 {
        {
            let jobs = admin.state.jobs.read().await;
            if jobs
                .iter()
                .any(|job| job.id == failover_job_id && job.status == "completed")
            {
                failover_completed = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        failover_completed,
        "failover job should complete via unified worker"
    );
    {
        let sites = admin.state.site_replications.read().await;
        let primary = sites
            .iter()
            .find(|site| site.role == "primary")
            .expect("primary site should exist after failover");
        assert_eq!(primary.site_id, "dr-site-b");
    }

    let failback = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/dr-site-a/failback",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({ "reason": "integration failback task" }))
        .send()
        .await
        .expect("failback enqueue request should complete");
    assert_eq!(failback.status(), StatusCode::OK);
    let failback_body = failback
        .json::<Value>()
        .await
        .expect("failback enqueue response should be json");
    let failback_job_id = failback_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("failback job id should exist")
        .to_string();
    assert_eq!(
        failback_body.pointer("/data/kind"),
        Some(&json!("failback"))
    );
    assert_eq!(
        failback_body.pointer("/data/status"),
        Some(&json!("pending"))
    );

    let mut failback_completed = false;
    for _ in 0..40 {
        {
            let jobs = admin.state.jobs.read().await;
            if jobs
                .iter()
                .any(|job| job.id == failback_job_id && job.status == "completed")
            {
                failback_completed = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        failback_completed,
        "failback job should complete via unified worker"
    );
    {
        let sites = admin.state.site_replications.read().await;
        let primary = sites
            .iter()
            .find(|site| site.role == "primary")
            .expect("primary site should exist after failback");
        assert_eq!(primary.site_id, "dr-site-a");
    }

    admin.stop().await;
}

#[tokio::test]
async fn site_governance_routes_bootstrap_join_resync_and_reconcile_complete_unified_jobs() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;

    let bootstrap = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/bootstrap",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "site_id": "dr-site-z",
            "endpoint": "https://dr-site-z.example.com",
            "preferred_primary": false,
            "reason": "integration bootstrap site"
        }))
        .send()
        .await
        .expect("bootstrap site request should complete");
    assert_eq!(bootstrap.status(), StatusCode::OK);
    let bootstrap_body = bootstrap
        .json::<Value>()
        .await
        .expect("bootstrap site response should be json");
    let bootstrap_job_id = bootstrap_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("bootstrap job id should exist")
        .to_string();
    assert_eq!(
        bootstrap_body.pointer("/data/kind"),
        Some(&json!("site-bootstrap"))
    );

    let mut bootstrap_completed = false;
    for _ in 0..40 {
        {
            let jobs = admin.state.jobs.read().await;
            if jobs
                .iter()
                .any(|job| job.id == bootstrap_job_id && job.status == "completed")
            {
                bootstrap_completed = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        bootstrap_completed,
        "site bootstrap job should complete via unified worker"
    );
    {
        let sites = admin.state.site_replications.read().await;
        let site = sites
            .iter()
            .find(|site| site.site_id == "dr-site-z")
            .expect("bootstrapped site should exist");
        assert_eq!(site.endpoint, "https://dr-site-z.example.com");
        assert_eq!(site.bootstrap_state, "bootstrapped");
        assert!(site.joined_at.is_some());
    }

    let join = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/dr-site-z/join",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "reason": "integration join site",
            "endpoint": "https://dr-site-z-v2.example.com"
        }))
        .send()
        .await
        .expect("join site request should complete");
    assert_eq!(join.status(), StatusCode::OK);
    let join_body = join
        .json::<Value>()
        .await
        .expect("join site response should be json");
    let join_job_id = join_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("join job id should exist")
        .to_string();
    assert_eq!(join_body.pointer("/data/kind"), Some(&json!("site-join")));

    let mut join_completed = false;
    for _ in 0..40 {
        {
            let jobs = admin.state.jobs.read().await;
            if jobs
                .iter()
                .any(|job| job.id == join_job_id && job.status == "completed")
            {
                join_completed = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        join_completed,
        "site join job should complete via unified worker"
    );
    {
        let sites = admin.state.site_replications.read().await;
        let site = sites
            .iter()
            .find(|site| site.site_id == "dr-site-z")
            .expect("joined site should exist");
        assert_eq!(site.endpoint, "https://dr-site-z-v2.example.com");
        assert_eq!(site.bootstrap_state, "joined");
        assert!(site.topology_version >= 2);
    }

    let bucket = "site-governance-bucket";
    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, payload) in [
        ("logs/a.txt", "log-a"),
        ("logs/b.txt", "log-b"),
        ("images/c.txt", "image-c"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(payload.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let create_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "logs-dr",
            "target_site": "dr-site-c",
            "endpoint": "https://dr-site-c.example.com",
            "prefix": "logs/",
            "priority": 5,
            "replicate_existing": true,
            "sync_deletes": false,
            "enabled": true
        }))
        .send()
        .await
        .expect("create replication rule request should complete");
    assert_eq!(create_rule.status(), StatusCode::OK);

    let sites_response = admin
        .client
        .get(format!("{}/api/v1/replication/sites", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("site replication request should complete");
    assert_eq!(sites_response.status(), StatusCode::OK);
    let sites_body = sites_response
        .json::<Value>()
        .await
        .expect("site replication response should be json");
    let dr_site_c = sites_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("site replication response should contain array")
        .iter()
        .find(|item| item.pointer("/site_id") == Some(&json!("dr-site-c")))
        .expect("dr-site-c should exist");
    assert_eq!(
        dr_site_c.pointer("/bootstrap_state"),
        Some(&json!("discovered"))
    );
    assert!(
        dr_site_c
            .pointer("/pending_resync_items")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 2
    );

    {
        let now = Utc::now();
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.push(ReplicationBacklogItem {
            id: "site-governance-backlog-1".to_string(),
            source_bucket: bucket.to_string(),
            target_site: "dr-site-c".to_string(),
            object_key: "logs/a.txt".to_string(),
            rule_id: Some("logs-dr".to_string()),
            priority: 5,
            operation: "put".to_string(),
            checkpoint: 1,
            idempotency_key: "site-governance-backlog-1".to_string(),
            version_id: None,
            attempts: 0,
            status: "pending".to_string(),
            last_error: String::new(),
            lease_owner: None,
            lease_until: None,
            queued_at: now,
            last_attempt_at: now,
        });
        backlog.push(ReplicationBacklogItem {
            id: "site-governance-backlog-2".to_string(),
            source_bucket: bucket.to_string(),
            target_site: "dr-site-c".to_string(),
            object_key: "logs/b.txt".to_string(),
            rule_id: Some("logs-dr".to_string()),
            priority: 5,
            operation: "put".to_string(),
            checkpoint: 2,
            idempotency_key: "site-governance-backlog-2".to_string(),
            version_id: None,
            attempts: 0,
            status: "pending".to_string(),
            last_error: String::new(),
            lease_owner: None,
            lease_until: None,
            queued_at: now,
            last_attempt_at: now,
        });
    }

    let resync = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/dr-site-c/resync",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({ "reason": "integration resync site" }))
        .send()
        .await
        .expect("resync site request should complete");
    assert_eq!(resync.status(), StatusCode::OK);
    let resync_body = resync
        .json::<Value>()
        .await
        .expect("resync site response should be json");
    let resync_job_id = resync_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("resync job id should exist")
        .to_string();
    assert_eq!(
        resync_body.pointer("/data/kind"),
        Some(&json!("site-resync"))
    );

    let mut resync_completed = false;
    for _ in 0..40 {
        {
            let jobs = admin.state.jobs.read().await;
            if jobs
                .iter()
                .any(|job| job.id == resync_job_id && job.status == "completed")
            {
                resync_completed = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        resync_completed,
        "site resync job should complete via unified worker"
    );
    {
        let sites = admin.state.site_replications.read().await;
        let site = sites
            .iter()
            .find(|site| site.site_id == "dr-site-c")
            .expect("resynced site should exist");
        assert!(site.last_resync_at.is_some());
        assert!(site.pending_resync_items >= 2);
        assert_eq!(site.state, "resyncing");
    }

    let drift_root = admin
        .data_dir
        .join(".rustio_sites")
        .join("dr-site-c")
        .join("data")
        .join(bucket);
    let _ = std::fs::remove_dir_all(&drift_root);
    assert!(
        !drift_root.exists(),
        "drift root should be removed before reconcile"
    );

    let reconcile = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/dr-site-c/reconcile",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({ "reason": "integration reconcile site" }))
        .send()
        .await
        .expect("reconcile site request should complete");
    assert_eq!(reconcile.status(), StatusCode::OK);
    let reconcile_body = reconcile
        .json::<Value>()
        .await
        .expect("reconcile site response should be json");
    let reconcile_job_id = reconcile_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("reconcile job id should exist")
        .to_string();
    assert_eq!(
        reconcile_body.pointer("/data/kind"),
        Some(&json!("site-reconcile"))
    );

    let mut reconcile_completed = false;
    for _ in 0..40 {
        {
            let jobs = admin.state.jobs.read().await;
            if jobs
                .iter()
                .any(|job| job.id == reconcile_job_id && job.status == "completed")
            {
                reconcile_completed = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        reconcile_completed,
        "site reconcile job should complete via unified worker"
    );
    assert!(
        drift_root.exists(),
        "reconcile should recreate missing site bucket root"
    );
    {
        let sites = admin.state.site_replications.read().await;
        let site = sites
            .iter()
            .find(|site| site.site_id == "dr-site-c")
            .expect("reconciled site should exist");
        assert!(site.last_reconcile_at.is_some());
        assert_eq!(site.drifted_buckets, 0);
        assert!(site.topology_version >= 2);
    }

    admin.stop().await;
}

#[tokio::test]
async fn cluster_diagnostic_support_bundle_is_redacted_and_downloadable() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;

    admin.state.audits.write().await.push(AuditEvent {
        id: "audit-diagnostic-secret".to_string(),
        actor: "admin".to_string(),
        action: "cluster.diagnostic.seed".to_string(),
        resource: "cluster/diagnostics".to_string(),
        outcome: "success".to_string(),
        reason: Some("seed support bundle".to_string()),
        timestamp: Utc::now(),
        details: json!({
            "api_key": "super-secret-token",
            "nested": {
                "authorization": "Bearer test-secret"
            }
        }),
    });

    let create = admin
        .client
        .post(format!(
            "{}/api/v1/cluster/diagnostics?audit_limit=10&job_limit=10&backlog_limit=10",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("create diagnostic support bundle request should complete");
    assert_eq!(create.status(), StatusCode::OK);
    let create_body = create
        .json::<Value>()
        .await
        .expect("create diagnostic support bundle response should be json");
    let report_id = create_body
        .pointer("/data/id")
        .and_then(Value::as_str)
        .expect("support bundle report id should exist")
        .to_string();
    assert_eq!(
        create_body.pointer("/data/kind"),
        Some(&json!("support-bundle"))
    );
    assert_eq!(
        create_body.pointer("/data/format"),
        Some(&json!("support-bundle.v1"))
    );
    assert_eq!(create_body.pointer("/data/redacted"), Some(&json!(true)));

    let support_bundle_path = admin
        .data_dir
        .join(".rustio_support_bundles")
        .join(format!("{report_id}.json"));
    assert!(
        support_bundle_path.exists(),
        "support bundle json should be persisted for offline inspection"
    );

    let detail = admin
        .client
        .get(format!(
            "{}/api/v1/cluster/diagnostics/{}",
            admin.base_url, report_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("get support bundle detail request should complete");
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = detail
        .json::<Value>()
        .await
        .expect("support bundle detail response should be json");
    assert_eq!(
        detail_body.pointer("/data/format_version"),
        Some(&json!("support-bundle.v1"))
    );
    assert_eq!(
        detail_body.pointer("/data/offline_ready"),
        Some(&json!(true))
    );
    assert!(
        detail_body
            .pointer("/data/sections/system_metrics")
            .is_some(),
        "system metrics section should exist in support bundle"
    );
    assert_eq!(
        detail_body.pointer("/data/sections/audits/recent/0/details/api_key"),
        Some(&json!("***REDACTED***"))
    );
    assert_eq!(
        detail_body.pointer("/data/sections/audits/recent/0/details/nested/authorization"),
        Some(&json!("***REDACTED***"))
    );

    let download = admin
        .client
        .get(format!(
            "{}/api/v1/cluster/diagnostics/{}/download",
            admin.base_url, report_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("download support bundle request should complete");
    assert_eq!(download.status(), StatusCode::OK);
    let content_disposition = download
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .expect("support bundle download should expose content-disposition");
    assert!(
        content_disposition.contains(&format!("rustio-support-bundle-{report_id}.json")),
        "download file name should include report id"
    );
    let download_body = download
        .text()
        .await
        .expect("support bundle download body should be readable");
    assert!(
        download_body.contains(&report_id),
        "download payload should include report id"
    );

    admin.stop().await;
}

#[tokio::test]
async fn site_replication_drift_preview_explains_conflicts_and_blocks_reconcile() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;
    let now = Utc::now();
    let site_id = "dr-preview-conflict";
    let bucket = "preview-bucket";

    admin.state.buckets.write().await.insert(
        bucket.to_string(),
        BucketSpec {
            name: bucket.to_string(),
            tenant_id: "default".to_string(),
            versioning: true,
            object_lock: false,
            ilm_policy: None,
            replication_policy: None,
        },
    );
    admin.state.replications.write().await.extend([
        ReplicationStatus {
            rule_id: "preview-rule-a".to_string(),
            source_bucket: bucket.to_string(),
            target_site: site_id.to_string(),
            rule_name: Some("preview-a".to_string()),
            endpoint: Some("https://dr-a.example.internal".to_string()),
            prefix: Some("logs/".to_string()),
            suffix: None,
            tags: vec![],
            priority: 10,
            replicate_existing: true,
            sync_deletes: true,
            lag_seconds: 0,
            status: "healthy".to_string(),
        },
        ReplicationStatus {
            rule_id: "preview-rule-b".to_string(),
            source_bucket: bucket.to_string(),
            target_site: site_id.to_string(),
            rule_name: Some("preview-b".to_string()),
            endpoint: Some("https://dr-b.example.internal".to_string()),
            prefix: Some("images/".to_string()),
            suffix: None,
            tags: vec![],
            priority: 20,
            replicate_existing: true,
            sync_deletes: true,
            lag_seconds: 0,
            status: "healthy".to_string(),
        },
    ]);
    admin
        .state
        .replication_backlog
        .write()
        .await
        .push(ReplicationBacklogItem {
            id: "preview-backlog-1".to_string(),
            source_bucket: bucket.to_string(),
            target_site: site_id.to_string(),
            object_key: "logs/a.txt".to_string(),
            rule_id: Some("preview-rule-a".to_string()),
            priority: 10,
            operation: "put".to_string(),
            checkpoint: 1,
            idempotency_key: "preview-backlog-1".to_string(),
            version_id: None,
            attempts: 0,
            status: "pending".to_string(),
            last_error: String::new(),
            lease_owner: None,
            lease_until: None,
            queued_at: now,
            last_attempt_at: now,
        });

    let inspect = admin
        .client
        .get(format!(
            "{}/api/v1/replication/sites/{}/drift",
            admin.base_url, site_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("site drift inspect request should complete");
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_body = inspect
        .json::<Value>()
        .await
        .expect("site drift inspect response should be json");
    assert_eq!(
        inspect_body.pointer("/data/topology/endpoint_alignment"),
        Some(&json!("conflicting_rules"))
    );
    assert_eq!(
        inspect_body.pointer("/data/buckets/0/state"),
        Some(&json!("missing_site_root"))
    );
    assert_eq!(
        inspect_body.pointer("/data/guardrails/safe_to_reconcile"),
        Some(&json!(false))
    );
    assert!(
        inspect_body
            .pointer("/data/guardrails/blocking_reasons")
            .and_then(Value::as_array)
            .expect("blocking reasons should exist")
            .iter()
            .any(|value| value == "conflicting_rule_endpoints"),
        "conflicting endpoints should appear in guardrails"
    );

    let preview = admin
        .client
        .get(format!(
            "{}/api/v1/replication/sites/{}/reconcile-preview",
            admin.base_url, site_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("site reconcile preview request should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview_body = preview
        .json::<Value>()
        .await
        .expect("site reconcile preview response should be json");
    assert_eq!(
        preview_body.pointer("/data/mode"),
        Some(&json!("dry-run-reconcile"))
    );
    assert!(
        preview_body
            .pointer("/data/guardrails/preview_actions")
            .and_then(Value::as_array)
            .expect("preview actions should exist")
            .iter()
            .any(|value| value == "create_bucket_root:preview-bucket"),
        "preview should explain bucket root creation action"
    );

    let reconcile = admin
        .client
        .post(format!(
            "{}/api/v1/replication/sites/{}/reconcile",
            admin.base_url, site_id
        ))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({ "reason": "preview guardrail test" }))
        .send()
        .await
        .expect("site reconcile request should complete");
    assert_eq!(reconcile.status(), StatusCode::BAD_REQUEST);
    let reconcile_body = reconcile
        .json::<Value>()
        .await
        .expect("site reconcile guardrail response should be json");
    let message = reconcile_body
        .pointer("/message")
        .or_else(|| reconcile_body.pointer("/error/message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("复制站点收敛预检失败")
            || message.contains("replication site reconcile preflight failed"),
        "guardrail error message should explain reconcile preflight failure"
    );

    admin.stop().await;
}

#[tokio::test]
async fn cluster_backup_export_and_restore_roundtrip_runtime_state() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;
    let now = Utc::now();
    let bucket = "backup-roundtrip";
    let remote_root = admin.data_dir.join("backup-remote-tier");
    std::fs::create_dir_all(&remote_root).expect("remote tier root should be creatable");

    let bucket_spec = BucketSpec {
        name: bucket.to_string(),
        tenant_id: "default".to_string(),
        versioning: true,
        object_lock: false,
        ilm_policy: Some("archive-after-30d".to_string()),
        replication_policy: Some("dr-primary".to_string()),
    };
    let remote_tier = RemoteTierConfig {
        name: "BACKUP-TIER".to_string(),
        endpoint: format!("file://{}", remote_root.display()),
        backend: "filesystem".to_string(),
        prefix: Some("exports".to_string()),
        storage_class: "GLACIER".to_string(),
        enabled: true,
        credential_key: None,
        credential_secret: None,
        credential_token: None,
        extra_headers: HashMap::new(),
        secret_version: 1,
        health_status: "healthy".to_string(),
        last_checked_at: Some(now),
        last_success_at: Some(now),
        last_error: None,
    };
    let replication = ReplicationStatus {
        rule_id: "backup-rule-1".to_string(),
        source_bucket: bucket.to_string(),
        target_site: "dr-site-backup".to_string(),
        rule_name: Some("backup-roundtrip-rule".to_string()),
        endpoint: Some("https://dr-site-backup.example.internal".to_string()),
        prefix: Some("finance/".to_string()),
        suffix: None,
        tags: vec![],
        priority: 7,
        replicate_existing: true,
        sync_deletes: true,
        lag_seconds: 0,
        status: "healthy".to_string(),
    };
    let service_account = ServiceAccount {
        access_key: "sa-backup-roundtrip".to_string(),
        secret_key: "sa-backup-roundtrip-secret".to_string(),
        owner: "admin".to_string(),
        created_at: now,
        status: "enabled".to_string(),
    };

    admin
        .state
        .buckets
        .write()
        .await
        .insert(bucket.to_string(), bucket_spec.clone());
    admin
        .state
        .remote_tiers
        .write()
        .await
        .insert(remote_tier.name.clone(), remote_tier.clone());
    admin
        .state
        .replications
        .write()
        .await
        .push(replication.clone());
    admin
        .state
        .service_accounts
        .write()
        .await
        .push(service_account.clone());

    let export = admin
        .client
        .get(format!("{}/api/v1/cluster/backup/export", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("cluster backup export request should complete");
    assert_eq!(export.status(), StatusCode::OK);
    let export_disposition = export
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .expect("cluster backup export should expose content-disposition");
    assert!(
        export_disposition.contains("rustio-cluster-backup-"),
        "cluster backup export file name should include commit index"
    );
    let backup = export
        .json::<Value>()
        .await
        .expect("cluster backup export should decode as json");
    assert_eq!(
        backup.pointer("/format_version"),
        Some(&json!("cluster-backup.v1"))
    );
    assert!(
        backup
            .pointer("/snapshot/snapshot/buckets")
            .and_then(Value::as_array)
            .expect("cluster backup snapshot buckets should exist")
            .iter()
            .any(|item| item.pointer("/name") == Some(&json!(bucket))),
        "cluster backup snapshot should include injected bucket state"
    );

    let committed_mutation = admin
        .client
        .put(format!("{}/api/v1/storage/tiers", admin.base_url))
        .bearer_auth(&access_token)
        .json(&json!([]))
        .send()
        .await
        .expect("post-export committed mutation should complete");
    assert_eq!(committed_mutation.status(), StatusCode::OK);

    admin.state.buckets.write().await.clear();
    admin.state.remote_tiers.write().await.clear();
    admin.state.replications.write().await.clear();
    admin
        .state
        .service_accounts
        .write()
        .await
        .retain(|account| account.access_key != service_account.access_key);

    let remote_tiers_path = admin
        .data_dir
        .join(".rustio_system")
        .join("remote-tiers.json");
    let _ = std::fs::remove_file(&remote_tiers_path);

    let restore = admin
        .client
        .post(format!("{}/api/v1/cluster/backup/restore", admin.base_url))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "reason": "cluster backup roundtrip regression",
            "backup": backup,
            "rewrite_cluster_id": true,
            "rewrite_peer_id": true
        }))
        .send()
        .await
        .expect("cluster backup restore request should complete");
    assert_eq!(restore.status(), StatusCode::OK);
    let restore_body = restore
        .json::<Value>()
        .await
        .expect("cluster backup restore response should be json");
    assert_eq!(
        restore_body.pointer("/data/format_version"),
        Some(&json!("cluster-backup.v1"))
    );
    assert_eq!(
        restore_body.pointer("/data/reason"),
        Some(&json!("cluster backup roundtrip regression"))
    );

    let buckets = admin.state.buckets.read().await;
    assert_eq!(
        buckets.get(bucket).map(|item| item.name.as_str()),
        Some(bucket)
    );
    drop(buckets);

    let remote_tiers = admin.state.remote_tiers.read().await;
    assert_eq!(
        remote_tiers
            .get("BACKUP-TIER")
            .map(|item| item.storage_class.as_str()),
        Some("GLACIER")
    );
    drop(remote_tiers);

    let replications = admin.state.replications.read().await;
    assert!(
        replications
            .iter()
            .any(|item| item.rule_id == replication.rule_id
                && item.target_site == replication.target_site),
        "replication runtime state should be restored from backup"
    );
    drop(replications);

    let service_accounts = admin.state.service_accounts.read().await;
    assert!(
        service_accounts
            .iter()
            .any(|item| item.access_key == service_account.access_key),
        "service account runtime state should be restored from backup"
    );
    drop(service_accounts);

    let persisted_remote_tiers = std::fs::read_to_string(&remote_tiers_path)
        .expect("remote tier snapshot should be persisted after restore");
    assert!(
        persisted_remote_tiers.contains("\"BACKUP-TIER\""),
        "persisted remote tier snapshot should include restored tier"
    );

    admin.stop().await;
}

#[tokio::test]
async fn storage_archive_report_and_prewarm_restore_remote_objects() {
    let admin = AdminServer::spawn().await;
    let bucket = "archive-regression";
    let access_token = admin.login_access_token().await;
    let remote_root = admin.data_dir.join("archive-remote-tier");
    let tier_prefix = "cold";
    let tier_name = "ARCHIVE-TIER";
    let object_key = "reports/2025/q4.csv";
    let current_version_id = "current-v1";
    let archived_version_id = "archived-v1";
    let current_remote_payload = b"current-object-from-remote".to_vec();
    let archived_remote_payload = b"archived-object-from-remote".to_vec();
    let now = Utc::now();

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create archive regression bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let tier_config = RemoteTierConfig {
        name: tier_name.to_string(),
        endpoint: format!("file://{}", remote_root.display()),
        backend: "filesystem".to_string(),
        prefix: Some(tier_prefix.to_string()),
        storage_class: "GLACIER".to_string(),
        enabled: true,
        credential_key: None,
        credential_secret: None,
        credential_token: None,
        extra_headers: HashMap::new(),
        secret_version: 1,
        health_status: "healthy".to_string(),
        last_checked_at: Some(now),
        last_success_at: Some(now),
        last_error: None,
    };
    admin
        .state
        .remote_tiers
        .write()
        .await
        .insert(tier_name.to_string(), tier_config.clone());

    let current_meta = S3ObjectMeta {
        bucket: bucket.to_string(),
        key: object_key.to_string(),
        version_id: current_version_id.to_string(),
        size: current_remote_payload.len() as u64,
        etag: sha256_hex_test(&current_remote_payload),
        created_at: now - ChronoDuration::days(2),
        storage_class: "STANDARD".to_string(),
        retention_mode: None,
        retention_until: None,
        legal_hold: false,
        delete_marker: false,
        remote_tier: Some(ObjectRemoteTierStatus {
            tier: tier_name.to_string(),
            storage_class: "GLACIER".to_string(),
            transitioned_at: now - ChronoDuration::days(1),
        }),
        restore: None,
        tags: vec![],
        user_metadata: HashMap::new(),
        encryption: Default::default(),
    };
    let archived_meta = S3ObjectMeta {
        bucket: bucket.to_string(),
        key: object_key.to_string(),
        version_id: archived_version_id.to_string(),
        size: archived_remote_payload.len() as u64,
        etag: sha256_hex_test(&archived_remote_payload),
        created_at: now - ChronoDuration::days(3),
        storage_class: "STANDARD".to_string(),
        retention_mode: None,
        retention_until: None,
        legal_hold: false,
        delete_marker: false,
        remote_tier: Some(ObjectRemoteTierStatus {
            tier: tier_name.to_string(),
            storage_class: "GLACIER".to_string(),
            transitioned_at: now - ChronoDuration::days(2),
        }),
        restore: None,
        tags: vec![],
        user_metadata: HashMap::new(),
        encryption: Default::default(),
    };

    let current_meta_path = object_meta_path_for(&admin.data_dir, bucket, object_key);
    std::fs::create_dir_all(
        current_meta_path
            .parent()
            .expect("current metadata file should have parent directory"),
    )
    .expect("current metadata directory should be creatable");
    std::fs::write(
        &current_meta_path,
        serde_json::to_vec_pretty(&current_meta).expect("current metadata should serialize"),
    )
    .expect("current metadata should be writable");

    let archived_meta_path =
        archived_object_meta_path_for(&admin.data_dir, bucket, object_key, archived_version_id);
    std::fs::create_dir_all(
        archived_meta_path
            .parent()
            .expect("archived metadata file should have parent directory"),
    )
    .expect("archived metadata directory should be creatable");
    std::fs::write(
        &archived_meta_path,
        serde_json::to_vec_pretty(&archived_meta).expect("archived metadata should serialize"),
    )
    .expect("archived metadata should be writable");

    let current_remote_payload_path = remote_tier_payload_path_for(
        &remote_root,
        bucket,
        tier_config.prefix.as_deref(),
        object_key,
        current_version_id,
    );
    std::fs::create_dir_all(
        current_remote_payload_path
            .parent()
            .expect("current remote payload should have parent directory"),
    )
    .expect("current remote payload directory should be creatable");
    std::fs::write(&current_remote_payload_path, &current_remote_payload)
        .expect("current remote payload should be writable");

    let archived_remote_payload_path = remote_tier_payload_path_for(
        &remote_root,
        bucket,
        tier_config.prefix.as_deref(),
        object_key,
        archived_version_id,
    );
    std::fs::create_dir_all(
        archived_remote_payload_path
            .parent()
            .expect("archived remote payload should have parent directory"),
    )
    .expect("archived remote payload directory should be creatable");
    std::fs::write(&archived_remote_payload_path, &archived_remote_payload)
        .expect("archived remote payload should be writable");

    let report = admin
        .client
        .get(format!(
            "{}/api/v1/storage/archive/report?bucket={}",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("archive report request should complete");
    assert_eq!(report.status(), StatusCode::OK);
    let report_body = report
        .json::<Value>()
        .await
        .expect("archive report response should be json");
    assert_eq!(
        report_body.pointer("/data/summary/total_objects"),
        Some(&json!(2))
    );
    assert_eq!(
        report_body.pointer("/data/summary/remote_objects"),
        Some(&json!(2))
    );
    assert_eq!(
        report_body.pointer("/data/summary/current_versions"),
        Some(&json!(1))
    );
    assert_eq!(
        report_body.pointer("/data/summary/noncurrent_versions"),
        Some(&json!(1))
    );
    assert_eq!(
        report_body.pointer("/data/summary/cold_objects"),
        Some(&json!(2))
    );
    assert!(
        report_body
            .pointer("/data/items")
            .and_then(Value::as_array)
            .expect("archive report items should exist")
            .iter()
            .all(|item| item.pointer("/archive_state") == Some(&json!("cold-remote"))),
        "archive report should mark remote objects as cold before prewarm"
    );

    let inventory_export = admin
        .client
        .get(format!(
            "{}/api/v1/storage/inventory/export?bucket={}&format=csv",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("storage inventory export request should complete");
    assert_eq!(inventory_export.status(), StatusCode::OK);
    let inventory_csv = inventory_export
        .text()
        .await
        .expect("storage inventory export body should be readable");
    assert!(
        inventory_csv.contains("archive_state"),
        "inventory export csv should include archive_state column"
    );
    assert!(
        inventory_csv.contains("cold-remote"),
        "inventory export csv should include cold remote rows"
    );

    let report_export = admin
        .client
        .get(format!(
            "{}/api/v1/storage/archive/report/export?bucket={}&format=json",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("archive report export request should complete");
    assert_eq!(report_export.status(), StatusCode::OK);
    let report_export_body = report_export
        .text()
        .await
        .expect("archive report export body should be readable");
    assert!(
        report_export_body.contains("\"remote_objects\": 2"),
        "archive report export should include summary payload"
    );

    let prewarm = admin
        .client
        .post(format!("{}/api/v1/storage/archive/prewarm", admin.base_url))
        .bearer_auth(&access_token)
        .header("x-rustio-confirm", "true")
        .json(&json!({
            "reason": "archive prewarm regression",
            "bucket": bucket,
            "restore_days": 1
        }))
        .send()
        .await
        .expect("archive prewarm request should complete");
    assert_eq!(prewarm.status(), StatusCode::OK);
    let prewarm_body = prewarm
        .json::<Value>()
        .await
        .expect("archive prewarm response should be json");
    assert_eq!(prewarm_body.pointer("/data/matched"), Some(&json!(2)));
    assert_eq!(prewarm_body.pointer("/data/restored"), Some(&json!(2)));
    assert_eq!(prewarm_body.pointer("/data/failed"), Some(&json!(0)));

    let current_hot_payload_path =
        current_object_payload_path_for(&admin.data_dir, bucket, object_key);
    assert_eq!(
        std::fs::read(&current_hot_payload_path).expect("current hot payload should exist"),
        current_remote_payload
    );

    let archived_hot_payload_path =
        archived_object_payload_path_for(&admin.data_dir, bucket, object_key, archived_version_id);
    assert_eq!(
        std::fs::read(&archived_hot_payload_path).expect("archived hot payload should exist"),
        archived_remote_payload
    );

    let restored_current_meta = read_object_meta_file(&admin.data_dir, bucket, object_key);
    assert!(
        restored_current_meta
            .restore
            .as_ref()
            .and_then(|item| item.expiry_at)
            .is_some(),
        "current object metadata should record restore expiry"
    );
    let restored_archived_meta =
        read_archived_object_meta_file(&admin.data_dir, bucket, object_key, archived_version_id);
    assert!(
        restored_archived_meta
            .restore
            .as_ref()
            .and_then(|item| item.expiry_at)
            .is_some(),
        "archived object metadata should record restore expiry"
    );

    let mut expiring_current_meta = restored_current_meta.clone();
    expiring_current_meta
        .restore
        .as_mut()
        .expect("current restore should exist")
        .expiry_at = Some(Utc::now() + ChronoDuration::minutes(30));
    std::fs::write(
        object_meta_path_for(&admin.data_dir, bucket, object_key),
        serde_json::to_vec_pretty(&expiring_current_meta)
            .expect("updated current metadata should serialize"),
    )
    .expect("updated current metadata should be writable");

    let mut expiring_archived_meta = restored_archived_meta.clone();
    expiring_archived_meta
        .restore
        .as_mut()
        .expect("archived restore should exist")
        .expiry_at = Some(Utc::now() + ChronoDuration::minutes(30));
    std::fs::write(
        archived_object_meta_path_for(&admin.data_dir, bucket, object_key, archived_version_id),
        serde_json::to_vec_pretty(&expiring_archived_meta)
            .expect("updated archived metadata should serialize"),
    )
    .expect("updated archived metadata should be writable");

    let restored_report = admin
        .client
        .get(format!(
            "{}/api/v1/storage/archive/report?bucket={}",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("restored archive report request should complete");
    assert_eq!(restored_report.status(), StatusCode::OK);
    let restored_report_body = restored_report
        .json::<Value>()
        .await
        .expect("restored archive report response should be json");
    assert_eq!(
        restored_report_body.pointer("/data/summary/restored_objects"),
        Some(&json!(2))
    );
    assert_eq!(
        restored_report_body.pointer("/data/summary/expiring_soon_objects"),
        Some(&json!(2))
    );
    assert!(
        restored_report_body
            .pointer("/data/items")
            .and_then(Value::as_array)
            .expect("restored archive report items should exist")
            .iter()
            .all(|item| item.pointer("/archive_state") == Some(&json!("restored-hot-copy"))),
        "restored archive report should mark remote objects as restored hot copies"
    );

    let inventory = admin
        .client
        .get(format!(
            "{}/api/v1/storage/inventory?bucket={}&restore_state=restored&restored_only=true&restore_expiring_within_minutes=60",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("storage inventory request should complete");
    assert_eq!(inventory.status(), StatusCode::OK);
    let inventory_body = inventory
        .json::<Value>()
        .await
        .expect("storage inventory response should be json");
    let items = inventory_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("storage inventory data should be an array");
    assert_eq!(items.len(), 2);
    assert!(
        items.iter().all(|item| {
            item.pointer("/restored") == Some(&json!(true))
                && item
                    .pointer("/restore_remaining_seconds")
                    .and_then(Value::as_i64)
                    .map(|seconds| seconds > 0)
                    .unwrap_or(false)
                && item.pointer("/restore_expiring_soon") == Some(&json!(true))
        }),
        "storage inventory should expose restored state and expiry window fields"
    );

    admin.stop().await;
}

#[tokio::test]
async fn replication_rule_update_supports_prefix_priority_endpoint_and_multi_rule_catch_up() {
    let admin = AdminServer::spawn().await;
    let bucket = "reports";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, payload) in [
        ("logs/a.txt", "log-a"),
        ("logs/b.txt", "log-b"),
        ("images/c.txt", "image-c"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .body(payload.to_string())
            .send()
            .await
            .expect("seed object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let access_token = admin.login_access_token().await;
    let create_logs_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "logs-dr",
            "target_site": "dr-site-c",
            "endpoint": "https://dr-site-c.example.com",
            "prefix": "logs/",
            "priority": 5,
            "replicate_existing": true,
            "sync_deletes": false,
            "enabled": true
        }))
        .send()
        .await
        .expect("create replication rule request should complete");
    assert_eq!(create_logs_rule.status(), StatusCode::OK);
    let create_logs_rule_body = create_logs_rule
        .json::<Value>()
        .await
        .expect("create replication rule response should be json");
    assert_eq!(
        create_logs_rule_body.pointer("/data/rule_name"),
        Some(&json!("logs-dr"))
    );
    assert_eq!(
        create_logs_rule_body.pointer("/data/endpoint"),
        Some(&json!("https://dr-site-c.example.com"))
    );
    assert_eq!(
        create_logs_rule_body.pointer("/data/prefix"),
        Some(&json!("logs/"))
    );
    assert_eq!(
        create_logs_rule_body.pointer("/data/priority"),
        Some(&json!(5))
    );
    assert_eq!(
        create_logs_rule_body.pointer("/data/replicate_existing"),
        Some(&json!(true))
    );
    assert_eq!(
        create_logs_rule_body.pointer("/data/sync_deletes"),
        Some(&json!(false))
    );

    {
        let backlog = admin.state.replication_backlog.read().await;
        let log_keys = backlog
            .iter()
            .map(|item| item.object_key.clone())
            .collect::<Vec<_>>();
        assert_eq!(log_keys.len(), 2);
        assert!(log_keys.iter().all(|key| key.starts_with("logs/")));
    }

    let create_images_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "images-dr",
            "target_site": "dr-site-c",
            "endpoint": "https://dr-site-c.example.com",
            "prefix": "images/",
            "priority": 15,
            "replicate_existing": true,
            "sync_deletes": true,
            "enabled": true
        }))
        .send()
        .await
        .expect("create second replication rule request should complete");
    assert_eq!(create_images_rule.status(), StatusCode::OK);

    let rules_response = admin
        .client
        .get(format!(
            "{}/api/v1/buckets/replication/status",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("replication status request should complete");
    assert_eq!(rules_response.status(), StatusCode::OK);
    let rules_body = rules_response
        .json::<Value>()
        .await
        .expect("replication status response should be json");
    let bucket_rules = rules_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("replication rules should be an array")
        .iter()
        .filter(|item| item.pointer("/source_bucket") == Some(&json!(bucket)))
        .collect::<Vec<_>>();
    assert_eq!(bucket_rules.len(), 2);

    let sites_response = admin
        .client
        .get(format!("{}/api/v1/replication/sites", admin.base_url))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("site replication request should complete");
    assert_eq!(sites_response.status(), StatusCode::OK);
    let sites_body = sites_response
        .json::<Value>()
        .await
        .expect("site replication response should be json");
    let dr_site_c = sites_body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("site replication response should contain array")
        .iter()
        .find(|item| item.pointer("/site_id") == Some(&json!("dr-site-c")))
        .expect("dr-site-c should exist");
    assert_eq!(
        dr_site_c.pointer("/endpoint"),
        Some(&json!("https://dr-site-c.example.com"))
    );
    assert_eq!(dr_site_c.pointer("/managed_buckets"), Some(&json!(1)));

    admin.stop().await;
}

#[tokio::test]
async fn replication_rule_supports_suffix_and_tag_filters() {
    let admin = AdminServer::spawn().await;
    let bucket = "reports-filtered";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    for (key, payload, tagging) in [
        ("logs/report-prod.csv", "prod-csv", "env=prod&team=data"),
        ("logs/report-dev.csv", "dev-csv", "env=dev&team=data"),
        ("logs/report-prod.json", "prod-json", "env=prod&team=data"),
    ] {
        let put_object = admin
            .client
            .put(format!("{}/{}/{}", admin.base_url, bucket, key))
            .basic_auth("rustioadmin", Some("rustioadmin"))
            .header("x-amz-tagging", tagging)
            .body(payload.to_string())
            .send()
            .await
            .expect("seed filtered object request should complete");
        assert_eq!(put_object.status(), StatusCode::OK);
    }

    let access_token = admin.login_access_token().await;
    let create_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "logs-prod-csv",
            "target_site": "dr-site-filter",
            "endpoint": "https://dr-site-filter.example.com",
            "prefix": "logs/",
            "suffix": ".csv",
            "tags": [
                { "key": "env", "value": "prod" }
            ],
            "priority": 9,
            "replicate_existing": true,
            "sync_deletes": true,
            "enabled": true
        }))
        .send()
        .await
        .expect("create filtered replication rule request should complete");
    assert_eq!(create_rule.status(), StatusCode::OK);
    let create_rule_body = create_rule
        .json::<Value>()
        .await
        .expect("create filtered replication rule response should be json");
    assert_eq!(
        create_rule_body.pointer("/data/suffix"),
        Some(&json!(".csv"))
    );
    assert_eq!(
        create_rule_body.pointer("/data/tags"),
        Some(&json!([{ "key": "env", "value": "prod" }]))
    );

    {
        let backlog = admin.state.replication_backlog.read().await;
        let keys = backlog
            .iter()
            .map(|item| item.object_key.clone())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["logs/report-prod.csv".to_string()]);
    }

    admin.state.replication_backlog.write().await.clear();

    let put_matching = admin
        .client
        .put(format!(
            "{}/{}/{}",
            admin.base_url, bucket, "logs/new-prod.csv"
        ))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .header("x-amz-tagging", "env=prod&team=ops")
        .body("matching object".to_string())
        .send()
        .await
        .expect("put matching filtered object request should complete");
    assert_eq!(put_matching.status(), StatusCode::OK);
    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].object_key, "logs/new-prod.csv");
        assert_eq!(backlog[0].operation, "put");
    }

    admin.state.replication_backlog.write().await.clear();

    let put_nonmatching = admin
        .client
        .put(format!(
            "{}/{}/{}",
            admin.base_url, bucket, "logs/new-dev.csv"
        ))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .header("x-amz-tagging", "env=dev&team=ops")
        .body("non matching object".to_string())
        .send()
        .await
        .expect("put nonmatching filtered object request should complete");
    assert_eq!(put_nonmatching.status(), StatusCode::OK);
    assert!(
        admin.state.replication_backlog.read().await.is_empty(),
        "nonmatching tag should not enqueue replication"
    );

    let put_tag_late = admin
        .client
        .put(format!(
            "{}/{}/{}",
            admin.base_url, bucket, "logs/tag-late.csv"
        ))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .header("x-amz-tagging", "env=dev&team=ops")
        .body("tag-late object".to_string())
        .send()
        .await
        .expect("put tag-late object request should complete");
    assert_eq!(put_tag_late.status(), StatusCode::OK);
    admin.state.replication_backlog.write().await.clear();

    let retag_xml = r#"<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag><Tag><Key>team</Key><Value>ops</Value></Tag></TagSet></Tagging>"#;
    let retag = admin
        .client
        .put(format!(
            "{}/{}/{}?tagging",
            admin.base_url, bucket, "logs/tag-late.csv"
        ))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .header(reqwest::header::CONTENT_TYPE, "application/xml")
        .body(retag_xml.to_string())
        .send()
        .await
        .expect("retag object request should complete");
    assert_eq!(retag.status(), StatusCode::OK);
    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].object_key, "logs/tag-late.csv");
        assert_eq!(backlog[0].operation, "put");
    }

    admin.state.replication_backlog.write().await.clear();

    let delete_matching = admin
        .client
        .delete(format!(
            "{}/{}/{}",
            admin.base_url, bucket, "logs/tag-late.csv"
        ))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("delete matching filtered object request should complete");
    assert_eq!(delete_matching.status(), StatusCode::NO_CONTENT);
    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].object_key, "logs/tag-late.csv");
        assert_eq!(backlog[0].operation, "delete");
    }

    admin.stop().await;
}

#[tokio::test]
async fn replication_rule_rejects_conflicting_site_endpoint_and_delete_cleans_rule_backlog() {
    let admin = AdminServer::spawn().await;
    let bucket = "replication-governance-delete";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let access_token = admin.login_access_token().await;
    let create_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "delete-target",
            "target_site": "dr-site-delete",
            "endpoint": "https://dr-site-delete.example.com",
            "prefix": "logs/",
            "priority": 7,
            "replicate_existing": false,
            "sync_deletes": true,
            "enabled": true
        }))
        .send()
        .await
        .expect("create replication rule request should complete");
    assert_eq!(create_rule.status(), StatusCode::OK);
    let create_rule_body = create_rule
        .json::<Value>()
        .await
        .expect("create replication rule response should be json");
    let rule_id = create_rule_body
        .pointer("/data/rule_id")
        .and_then(Value::as_str)
        .expect("rule id should exist")
        .to_string();

    let conflicting_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "delete-target-conflict",
            "target_site": "dr-site-delete",
            "endpoint": "https://conflict.example.com",
            "prefix": "images/",
            "priority": 11,
            "replicate_existing": false,
            "sync_deletes": true,
            "enabled": true
        }))
        .send()
        .await
        .expect("conflicting replication rule request should complete");
    assert_eq!(conflicting_rule.status(), StatusCode::BAD_REQUEST);
    let conflicting_rule_body = conflicting_rule
        .json::<Value>()
        .await
        .expect("conflicting replication rule response should be json");
    let conflicting_message = conflicting_rule_body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .expect("conflicting replication rule error should include message");
    assert!(conflicting_message.contains("端点必须保持一致"));

    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.clear();
        backlog.extend([
            test_replication_backlog_item(
                "repl-delete-pending",
                bucket,
                "dr-site-delete",
                "logs/a.txt",
                Some(&rule_id),
                7,
                "put",
                11,
                "pending",
            ),
            test_replication_backlog_item(
                "repl-delete-failed",
                bucket,
                "dr-site-delete",
                "logs/b.txt",
                Some(&rule_id),
                7,
                "put",
                12,
                "failed",
            ),
            test_replication_backlog_item(
                "repl-delete-dead",
                bucket,
                "dr-site-delete",
                "logs/c.txt",
                Some(&rule_id),
                7,
                "delete",
                13,
                "dead_letter",
            ),
            test_replication_backlog_item(
                "repl-delete-done",
                bucket,
                "dr-site-delete",
                "logs/d.txt",
                Some(&rule_id),
                7,
                "put",
                14,
                "done",
            ),
            test_replication_backlog_item(
                "repl-delete-other",
                bucket,
                "dr-site-other",
                "logs/e.txt",
                Some("other-rule"),
                50,
                "put",
                15,
                "pending",
            ),
        ]);
    }

    let delete_rule = admin
        .client
        .delete(format!(
            "{}/api/v1/buckets/{}/replication/{}",
            admin.base_url, bucket, rule_id
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("delete replication rule request should complete");
    assert_eq!(delete_rule.status(), StatusCode::OK);

    let rules_response = admin
        .client
        .get(format!(
            "{}/api/v1/buckets/replication/status",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("replication status request should complete");
    assert_eq!(rules_response.status(), StatusCode::OK);
    let rules_body = rules_response
        .json::<Value>()
        .await
        .expect("replication status response should be json");
    assert!(
        rules_body
            .pointer("/data")
            .and_then(Value::as_array)
            .expect("replication rules should be an array")
            .iter()
            .all(|item| item.pointer("/rule_id") != Some(&json!(rule_id))),
        "deleted rule should not remain in replication status"
    );

    {
        let backlog = admin.state.replication_backlog.read().await;
        let remaining_ids = backlog
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(remaining_ids.len(), 2);
        assert!(remaining_ids.contains(&"repl-delete-done"));
        assert!(remaining_ids.contains(&"repl-delete-other"));
        assert!(
            backlog.iter().all(|item| {
                item.rule_id.as_deref() != Some(rule_id.as_str())
                    || !matches!(item.status.as_str(), "pending" | "failed" | "dead_letter")
            }),
            "deleted rule should not keep retryable backlog items"
        );
    }

    admin.stop().await;
}

#[tokio::test]
async fn replication_queue_prefers_lower_priority_rule_before_lower_ranked_entries() {
    let admin =
        AdminServer::spawn_with_env(&[("RUSTIO_REPLICATION_WORKER_INTERVAL_MS", "5000")]).await;
    let bucket = "replication-priority-check";
    let key = "logs/priority.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let access_token = admin.login_access_token().await;
    for (target_site, priority) in [("dr-site-fast", 5), ("dr-site-slow", 50)] {
        let create_rule = admin
            .client
            .post(format!(
                "{}/api/v1/buckets/{}/replication",
                admin.base_url, bucket
            ))
            .bearer_auth(&access_token)
            .json(&json!({
                "rule_name": format!("{target_site}-rule"),
                "target_site": target_site,
                "endpoint": format!("https://{target_site}.example.com"),
                "prefix": "logs/",
                "priority": priority,
                "replicate_existing": false,
                "sync_deletes": true,
                "enabled": true
            }))
            .send()
            .await
            .expect("create replication rule request should complete");
        assert_eq!(create_rule.status(), StatusCode::OK);
    }

    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.clear();
    }

    let put_object = admin
        .client
        .put(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .body("priority payload".to_string())
        .send()
        .await
        .expect("s3 put object request should complete");
    assert_eq!(put_object.status(), StatusCode::OK);

    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 2);
        let fast_item = backlog
            .iter()
            .find(|item| item.target_site == "dr-site-fast")
            .expect("fast priority replication item should exist");
        let slow_item = backlog
            .iter()
            .find(|item| item.target_site == "dr-site-slow")
            .expect("slow priority replication item should exist");
        assert_eq!(fast_item.priority, 5);
        assert_eq!(slow_item.priority, 50);
        assert_eq!(fast_item.status, "pending");
        assert_eq!(slow_item.status, "pending");
    }

    let processed = admin
        .state
        .process_replication_queue_once("priority-test-worker")
        .await;
    assert_eq!(processed, 1);

    {
        let backlog = admin.state.replication_backlog.read().await;
        let fast_item = backlog
            .iter()
            .find(|item| item.target_site == "dr-site-fast")
            .expect("fast priority replication item should remain in backlog");
        let slow_item = backlog
            .iter()
            .find(|item| item.target_site == "dr-site-slow")
            .expect("slow priority replication item should remain in backlog");
        assert_eq!(fast_item.status, "done");
        assert_eq!(slow_item.status, "pending");
    }

    admin.stop().await;
}

#[tokio::test]
async fn replication_rule_respects_sync_deletes_on_s3_write_and_delete() {
    let admin = AdminServer::spawn().await;
    let bucket = "sync-delete-check";
    let key = "logs/new.txt";

    let create_bucket = admin
        .client
        .put(format!("{}/{}", admin.base_url, bucket))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("create bucket request should complete");
    assert_eq!(create_bucket.status(), StatusCode::OK);

    let access_token = admin.login_access_token().await;
    let create_rule = admin
        .client
        .post(format!(
            "{}/api/v1/buckets/{}/replication",
            admin.base_url, bucket
        ))
        .bearer_auth(&access_token)
        .json(&json!({
            "rule_name": "logs-put-only",
            "target_site": "dr-site-d",
            "prefix": "logs/",
            "replicate_existing": false,
            "sync_deletes": false,
            "enabled": true
        }))
        .send()
        .await
        .expect("create replication rule request should complete");
    assert_eq!(create_rule.status(), StatusCode::OK);
    assert!(admin.state.replication_backlog.read().await.is_empty());

    let put_object = admin
        .client
        .put(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .body("hello replication".to_string())
        .send()
        .await
        .expect("s3 put object request should complete");
    assert_eq!(put_object.status(), StatusCode::OK);
    {
        let backlog = admin.state.replication_backlog.read().await;
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].object_key, key);
        assert_eq!(backlog[0].operation, "put");
    }

    admin.state.replication_backlog.write().await.clear();

    let delete_object = admin
        .client
        .delete(format!("{}/{}/{}", admin.base_url, bucket, key))
        .basic_auth("rustioadmin", Some("rustioadmin"))
        .send()
        .await
        .expect("s3 delete object request should complete");
    assert_eq!(delete_object.status(), StatusCode::NO_CONTENT);
    assert!(
        admin.state.replication_backlog.read().await.is_empty(),
        "delete should not enqueue replication when sync_deletes is disabled"
    );

    admin.stop().await;
}

#[tokio::test]
async fn prometheus_metrics_endpoint_exposes_core_gauges() {
    let admin = AdminServer::spawn().await;
    let now = Utc::now();

    {
        let mut backlog = admin.state.replication_backlog.write().await;
        backlog.clear();
        backlog.extend([
            ReplicationBacklogItem {
                id: "metrics-failed".to_string(),
                source_bucket: "logs".to_string(),
                target_site: "dr-site-a".to_string(),
                object_key: "2026/03/metrics-a.log".to_string(),
                rule_id: None,
                priority: 100,
                operation: "put".to_string(),
                checkpoint: 1,
                idempotency_key: "metrics-a".to_string(),
                version_id: Some("v1".to_string()),
                attempts: 1,
                status: "failed".to_string(),
                last_error: "timeout".to_string(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(2),
                last_attempt_at: now,
            },
            ReplicationBacklogItem {
                id: "metrics-dead-letter".to_string(),
                source_bucket: "logs".to_string(),
                target_site: "dr-site-b".to_string(),
                object_key: "2026/03/metrics-b.log".to_string(),
                rule_id: None,
                priority: 100,
                operation: "delete".to_string(),
                checkpoint: 2,
                idempotency_key: "metrics-b".to_string(),
                version_id: None,
                attempts: 5,
                status: "dead_letter".to_string(),
                last_error: "not found".to_string(),
                lease_owner: None,
                lease_until: None,
                queued_at: now - ChronoDuration::minutes(1),
                last_attempt_at: now - ChronoDuration::minutes(1),
            },
        ]);
    }
    {
        let mut security = admin.state.security.write().await;
        security.oidc_enabled = true;
        security.ldap_enabled = false;
        security.kms_healthy = true;
    }
    {
        let mut governance = admin.state.storage_governance.write().await;
        governance.last_heal_duration_seconds = 9.5;
        governance.scan_runs_total = 4;
        governance.scan_failures_total = 1;
        governance.heal_objects_total = 2;
        governance.heal_failures_total = 1;
    }

    let response = admin
        .client
        .get(format!("{}/metrics", admin.base_url))
        .send()
        .await
        .expect("prometheus metrics request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("metrics response should expose content type")
        .to_string();
    assert!(
        content_type.contains("text/plain; version=0.0.4"),
        "unexpected metrics content type: {content_type}"
    );
    let body = response
        .text()
        .await
        .expect("metrics response body should be readable");

    for needle in [
        "rustio_nodes_total 3",
        "rustio_nodes_online 3",
        "rustio_tenants_total 2",
        "rustio_replication_backlog_total 2",
        "rustio_replication_backlog_failed 1",
        "rustio_replication_backlog_dead_letter 1",
        "rustio_alert_channels_total 2",
        "rustio_security_oidc_enabled 1",
        "rustio_security_ldap_enabled 0",
        "rustio_security_kms_healthy 1",
        "rustio_replication_site_lag_seconds{site_id=\"dr-site-a\",state=\"healthy\",backlog_sla_status=\"healthy\"} 0",
        "rustio_replication_site_backlog_total{site_id=\"dr-site-b\",status=\"dead_letter\",backlog_sla_status=\"healthy\"} 1",
        "rustio_sessions_total{kind=\"admin_sessions_active\"} 0",
        "rustio_security_feature_enabled{feature=\"oidc\"} 1",
        "rustio_storage_scan_runs_total 4",
        "rustio_storage_scan_failures_total 1",
        "rustio_storage_heal_objects_total 2",
        "rustio_storage_heal_failures_total 1",
        "rustio_storage_heal_duration_seconds 9.5",
    ] {
        assert!(
            body.contains(needle),
            "prometheus output should contain `{needle}`, body: {body}"
        );
    }

    admin.stop().await;
}

#[tokio::test]
async fn audit_events_support_category_and_detail_filters() {
    let admin = AdminServer::spawn().await;
    let access_token = admin.login_access_token().await;
    let now = Utc::now();

    {
        let mut audits = admin.state.audits.write().await;
        audits.clear();
        audits.extend([
            AuditEvent {
                id: "audit-auth".to_string(),
                actor: "admin".to_string(),
                action: "auth.login".to_string(),
                resource: "auth/session/admin".to_string(),
                outcome: "success".to_string(),
                reason: None,
                timestamp: now - ChronoDuration::minutes(3),
                details: json!({ "provider": "local" }),
            },
            AuditEvent {
                id: "audit-kms".to_string(),
                actor: "admin".to_string(),
                action: "security.kms.rotate".to_string(),
                resource: "security/kms".to_string(),
                outcome: "partial_failed".to_string(),
                reason: Some("夜间轮换".to_string()),
                timestamp: now - ChronoDuration::minutes(2),
                details: json!({
                    "status": "partial_failed",
                    "retry_only_failed": false,
                    "failed": 1
                }),
            },
            AuditEvent {
                id: "audit-alert".to_string(),
                actor: "alert-worker".to_string(),
                action: "alerts.channel.test".to_string(),
                resource: "alerts/channel/email".to_string(),
                outcome: "failed".to_string(),
                reason: Some("smtp auth".to_string()),
                timestamp: now - ChronoDuration::minutes(1),
                details: json!({ "channel_id": "email", "kind": "smtp" }),
            },
        ]);
    }

    let response = admin
        .client
        .get(format!(
            "{}/api/v1/audit/events?category=kms&detail_key=status&detail_value=partial_failed&reason=夜间轮换",
            admin.base_url
        ))
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("audit filtered request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .json::<Value>()
        .await
        .expect("audit filtered response should be json");
    let rows = body
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("audit rows should be array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pointer("/id"), Some(&json!("audit-kms")));
    assert_eq!(
        rows[0].pointer("/details/status"),
        Some(&json!("partial_failed"))
    );

    admin.stop().await;
}
