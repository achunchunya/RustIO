//! S3 对象版本列举与 KMS 包裹前缀

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn s3_list_object_versions_xml(
    state: Arc<AppState>,
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    key_marker: &str,
    version_id_marker: &str,
    encoding_url: bool,
) -> Response {
    let bucket_root = match bucket_path(&state, bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_root.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            bucket,
        );
    }

    let mut keys = HashSet::new();
    let mut listed_objects = Vec::new();
    if let Err(err) = collect_objects(&state, bucket, &bucket_root, &bucket_root, &mut listed_objects)
    {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to enumerate bucket objects: {err}"),
            bucket,
        );
    }
    for item in listed_objects {
        keys.insert(item.key);
    }

    let mut meta_files = Vec::new();
    // current 对象元数据已下沉 redb,直接从 scan_bucket 收集 key(含 delete marker)。
    for meta in state.meta_store.scan_bucket(bucket).unwrap_or_default() {
        keys.insert(meta.key);
    }
    // archived 历史版本仍扫 .rustio_versions JSON。
    if let Err(err) = collect_json_files(&bucket_root.join(".rustio_versions"), &mut meta_files) {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to enumerate object version metadata files: {err}"),
            bucket,
        );
    }

    for file in meta_files {
        let bytes = match std::fs::read(&file) {
            Ok(bytes) => bytes,
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read object metadata file: {err}"),
                    bucket,
                );
            }
        };
        let Ok(meta) = serde_json::from_slice::<S3ObjectMeta>(&bytes) else {
            continue;
        };
        if meta.bucket == bucket {
            keys.insert(meta.key);
        }
    }

    let mut records = Vec::new();
    for key in keys {
        if !key.starts_with(prefix) {
            continue;
        }
        let versions = match list_object_versions(&state, bucket, &key).await {
            Ok(items) => items,
            Err(response) => return response,
        };
        if versions.is_empty() {
            continue;
        }

        let latest_version_id = versions.first().map(|item| item.version_id.clone());
        for version in versions {
            let is_latest = latest_version_id
                .as_ref()
                .map(|value| value == &version.version_id)
                .unwrap_or(false);
            records.push((key.clone(), version, is_latest));
        }
    }

    records.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| right.1.created_at.cmp(&left.1.created_at))
    });

    // marker 过滤：从 key-marker/version-id-marker 之后开始
    if !key_marker.is_empty() {
        if !version_id_marker.is_empty() {
            // 找到精确 marker 位置，保留其后的记录；找不到则退化为 key > key-marker
            if let Some(position) = records
                .iter()
                .position(|(key, meta, _)| key == key_marker && meta.version_id == version_id_marker)
            {
                records.drain(..=position);
            } else {
                records.retain(|(key, _, _)| key.as_str() > key_marker);
            }
        } else {
            records.retain(|(key, _, _)| key.as_str() > key_marker);
        }
    }

    // delimiter 折叠：prefix 之后含 delimiter 的 key 归入 CommonPrefixes
    enum VersionEntry {
        Record(String, Box<S3ObjectMeta>, bool),
        CommonPrefix(String),
    }
    let mut entries: Vec<VersionEntry> = Vec::new();
    let mut seen_prefixes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (key, meta, is_latest) in records {
        if !delimiter.is_empty() {
            let rest = &key[prefix.len()..];
            if let Some(pos) = rest.find(delimiter) {
                let common = format!("{prefix}{}{delimiter}", &rest[..pos]);
                if seen_prefixes.insert(common.clone()) {
                    entries.push(VersionEntry::CommonPrefix(common));
                }
                continue;
            }
        }
        entries.push(VersionEntry::Record(key, Box::new(meta), is_latest));
    }

    let truncated = entries.len() > max_keys;
    entries.truncate(max_keys);
    // 截断时输出 Next 标记，客户端凭此翻页
    let (next_key_marker, next_version_id_marker) = if truncated {
        match entries.last() {
            Some(VersionEntry::Record(key, meta, _)) => (key.clone(), meta.version_id.clone()),
            Some(VersionEntry::CommonPrefix(common)) => (common.clone(), String::new()),
            None => (String::new(), String::new()),
        }
    } else {
        (String::new(), String::new())
    };

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str("<Name>");
    xml.push_str(&xml_escape(bucket));
    xml.push_str("</Name><Prefix>");
    xml.push_str(&xml_escape(&s3_encode_key(prefix, encoding_url)));
    xml.push_str("</Prefix><KeyMarker>");
    xml.push_str(&xml_escape(&s3_encode_key(key_marker, encoding_url)));
    xml.push_str("</KeyMarker><VersionIdMarker>");
    xml.push_str(&xml_escape(version_id_marker));
    xml.push_str("</VersionIdMarker>");
    if encoding_url {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    if !delimiter.is_empty() {
        xml.push_str("<Delimiter>");
        xml.push_str(&xml_escape(&s3_encode_key(delimiter, encoding_url)));
        xml.push_str("</Delimiter>");
    }
    if truncated {
        xml.push_str("<NextKeyMarker>");
        xml.push_str(&xml_escape(&s3_encode_key(&next_key_marker, encoding_url)));
        xml.push_str("</NextKeyMarker><NextVersionIdMarker>");
        xml.push_str(&xml_escape(&next_version_id_marker));
        xml.push_str("</NextVersionIdMarker>");
    }
    xml.push_str("<MaxKeys>");
    xml.push_str(&max_keys.to_string());
    xml.push_str("</MaxKeys><IsTruncated>");
    xml.push_str(if truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated>");

    for entry in &entries {
        let (meta, is_latest) = match entry {
            VersionEntry::CommonPrefix(common) => {
                xml.push_str("<CommonPrefixes><Prefix>");
                xml.push_str(&xml_escape(&s3_encode_key(common, encoding_url)));
                xml.push_str("</Prefix></CommonPrefixes>");
                continue;
            }
            VersionEntry::Record(_, meta, is_latest) => (meta, *is_latest),
        };
        if meta.delete_marker {
            xml.push_str("<DeleteMarker>");
        } else {
            xml.push_str("<Version>");
        }
        xml.push_str("<Key>");
        xml.push_str(&xml_escape(&s3_encode_key(&meta.key, encoding_url)));
        xml.push_str("</Key><VersionId>");
        xml.push_str(&xml_escape(&meta.version_id));
        xml.push_str("</VersionId><IsLatest>");
        xml.push_str(if is_latest { "true" } else { "false" });
        xml.push_str("</IsLatest><LastModified>");
        xml.push_str(&meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true));
        xml.push_str("</LastModified>");
        if !meta.delete_marker {
            xml.push_str("<ETag>\"");
            xml.push_str(&xml_escape(&meta.etag));
            xml.push_str("\"</ETag><Size>");
            xml.push_str(&meta.size.to_string());
            xml.push_str("</Size><StorageClass>");
            xml.push_str(&xml_escape(object_storage_class(meta)));
            xml.push_str("</StorageClass>");
        }
        if meta.delete_marker {
            xml.push_str("</DeleteMarker>");
        } else {
            xml.push_str("</Version>");
        }
    }

    xml.push_str("</ListVersionsResult>");
    s3_xml_response(StatusCode::OK, xml)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EcShardInfo {
    pub(crate) shard_index: usize,
    pub(crate) disk_index: usize,
    pub(crate) path: PathBuf,
    pub(crate) checksum: String,
    /// 分片所在节点 ID(集群模式)。None/0=本地(单机或向后兼容旧 manifest)。
    #[serde(default)]
    pub(crate) node_id: Option<u64>,
    /// 分片所在节点的 API 地址(集群模式远程读取用)。None=本地。
    #[serde(default)]
    pub(crate) node_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EcObjectManifest {
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) total_size: u64,
    pub(crate) shard_size: usize,
    pub(crate) data_shards: usize,
    pub(crate) parity_shards: usize,
    pub(crate) shards: Vec<EcShardInfo>,
    pub(crate) updated_at: DateTime<Utc>,
}

pub(crate) fn ec_manifest_path(bucket_root: &FsPath, key: &str) -> PathBuf {
    bucket_root
        .join(".rustio_ec_meta")
        .join(format!("{}.json", sha256_hex(key.as_bytes())))
}

pub(crate) fn ec_layout() -> (usize, usize) {
    let data_shards = std::env::var("RUSTIO_EC_DATA_SHARDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(4);
    let parity_shards = std::env::var("RUSTIO_EC_PARITY_SHARDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);
    (data_shards, parity_shards)
}

/// 集群模式按节点数派生 EC 布局:**每节点恰好 1 个分片**(total_shards = node_count),
/// 因此丢失任意 `parity` 个节点都可由 Reed-Solomon 重建,实现节点级容错。
///
/// parity 取 `RUSTIO_EC_PARITY_SHARDS`(默认 1),clamp 到 `[1, node_count-1]`;data = node_count - parity。
/// node_count ≤ 1 时回退到磁盘级 `ec_layout()`(单节点无节点级容错可言)。
pub(crate) fn cluster_ec_layout(node_count: usize) -> (usize, usize) {
    if node_count <= 1 {
        return ec_layout();
    }
    let parity = std::env::var("RUSTIO_EC_PARITY_SHARDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
        .clamp(1, node_count - 1);
    let data = node_count - parity;
    (data, parity)
}

/// 解析当前对象写入应使用的 EC 布局。
///
/// - 集群模式(`local_node_id > 0`):按集群节点数派生节点级容错布局(见 [`cluster_ec_layout`])。
/// - 单机模式:沿用磁盘级 `ec_layout()`(默认 4+1,提供单机多盘冗余)。
pub(crate) async fn ec_layout_for(state: &AppState) -> (usize, usize) {
    if state.local_node_id == 0 {
        return ec_layout();
    }
    // 仅统计非 draining 节点:退役中节点不计入布局,新写入分片数随之收缩,
    // 不再落到待退役节点(与 resolve_shard_placements 的 draining 过滤一致)。
    let node_count = state
        .cluster_peers
        .read()
        .await
        .values()
        .filter(|peer| !peer.draining)
        .count();
    cluster_ec_layout(node_count)
}

pub(crate) fn encryption_enabled(meta: &S3ObjectMeta) -> bool {
    meta.encryption.enabled && !meta.encryption.algorithm.trim().is_empty()
}

pub(crate) fn ensure_supported_encryption_algorithm(
    meta: &S3ObjectMeta,
    resource: &str,
) -> Result<(), Response> {
    let algorithm = meta.encryption.algorithm.trim();
    if algorithm.eq_ignore_ascii_case("AES256") || algorithm.eq_ignore_ascii_case("aws:kms") {
        return Ok(());
    }
    Err(s3_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        "Object encryption algorithm is not supported",
        resource,
    ))
}

pub(crate) fn derive_object_encryption_key(state: &AppState, meta: &S3ObjectMeta) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"rustio-sse-v1");
    hasher.update(state.s3_access_key.as_bytes());
    hasher.update(state.s3_secret_key.as_bytes());
    hasher.update(meta.bucket.as_bytes());
    hasher.update(meta.key.as_bytes());
    hasher.update(meta.version_id.as_bytes());
    hasher.update(meta.encryption.algorithm.as_bytes());
    if let Some(kms_key_id) = meta.encryption.kms_key_id.as_deref() {
        hasher.update(kms_key_id.as_bytes());
    }
    if let Some(wrapped_key) = meta.encryption.wrapped_key_base64.as_deref() {
        hasher.update(wrapped_key.as_bytes());
    }
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

pub(crate) fn random_32_bytes() -> [u8; 32] {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(first.as_bytes());
    output[16..].copy_from_slice(second.as_bytes());
    output
}

pub(crate) fn random_12_bytes() -> [u8; 12] {
    let nonce_uuid = Uuid::new_v4();
    let mut output = [0u8; 12];
    output.copy_from_slice(&nonce_uuid.as_bytes()[..12]);
    output
}

pub(crate) fn derive_object_wrapping_key(state: &AppState, meta: &S3ObjectMeta) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"rustio-kek-v1");
    hasher.update(state.s3_access_key.as_bytes());
    hasher.update(state.s3_secret_key.as_bytes());
    hasher.update(meta.encryption.algorithm.as_bytes());
    if let Some(kms_key_id) = meta.encryption.kms_key_id.as_deref() {
        hasher.update(kms_key_id.as_bytes());
    }
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

pub(crate) fn wrap_object_data_key_local(
    state: &AppState,
    resource: &str,
    meta: &S3ObjectMeta,
    data_key: &[u8; 32],
) -> Result<String, Response> {
    let wrapping_key = derive_object_wrapping_key(state, meta);
    let wrapping_nonce = random_12_bytes();
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize object key wrapper: {err}"),
            resource,
        )
    })?;
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&wrapping_nonce), data_key.as_slice())
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to wrap object data key",
                resource,
            )
        })?;
    let mut blob = Vec::with_capacity(wrapped.len() + wrapping_nonce.len());
    blob.extend_from_slice(&wrapping_nonce);
    blob.extend_from_slice(&wrapped);
    Ok(BASE64.encode(blob))
}

pub(crate) fn unwrap_object_data_key_local(
    state: &AppState,
    resource: &str,
    meta: &S3ObjectMeta,
    wrapped_key_base64: &str,
) -> Result<[u8; 32], Response> {
    let wrapped = BASE64.decode(wrapped_key_base64).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to decode wrapped object key: {err}"),
            resource,
        )
    })?;
    if wrapped.len() < 12 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Wrapped object key metadata is invalid",
            resource,
        ));
    }
    let (wrapping_nonce, ciphertext) = wrapped.split_at(12);
    let wrapping_key = derive_object_wrapping_key(state, meta);
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize object key unwrapper: {err}"),
            resource,
        )
    })?;
    let data_key = cipher
        .decrypt(Nonce::from_slice(wrapping_nonce), ciphertext)
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to unwrap object data key",
                resource,
            )
        })?;
    if data_key.len() != 32 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Unwrapped object data key length is invalid",
            resource,
        ));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&data_key[..32]);
    Ok(output)
}

#[derive(Debug, Serialize)]
pub(crate) struct KmsEncryptDataKeyRequest {
    pub(crate) key_id: String,
    pub(crate) plaintext_base64: String,
    pub(crate) context: Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct KmsEncryptDataKeyResponse {
    pub(crate) ciphertext_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct KmsDecryptDataKeyRequest {
    pub(crate) ciphertext_base64: String,
    pub(crate) context: Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct KmsDecryptDataKeyResponse {
    pub(crate) plaintext_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultTransitEncryptDataKeyRequest {
    pub(crate) plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) context: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VaultTransitEncryptDataKeyResponseEnvelope {
    pub(crate) data: VaultTransitEncryptDataKeyResponse,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VaultTransitEncryptDataKeyResponse {
    pub(crate) ciphertext: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultTransitDecryptDataKeyRequest {
    pub(crate) ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) context: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VaultTransitDecryptDataKeyResponseEnvelope {
    pub(crate) data: VaultTransitDecryptDataKeyResponse,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VaultTransitDecryptDataKeyResponse {
    pub(crate) plaintext: String,
}

pub(crate) const KMS_WRAP_PREFIX_GENERIC: &str = "kms-generic:";
pub(crate) const KMS_WRAP_PREFIX_VAULT: &str = "kms-vault:";
pub(crate) const KMS_WRAP_PREFIX_KES: &str = "kms-kes:";
pub(crate) const SSEC_WRAP_PREFIX: &str = "ssec:";

#[derive(Debug, Serialize)]
pub(crate) struct KesGenerateDataKeyRequest {
    pub(crate) plaintext: String,
    pub(crate) length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) associated_data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct KesGenerateDataKeyResponse {
    pub(crate) plaintext: String,
    pub(crate) ciphertext: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct KesDecryptDataKeyRequest {
    pub(crate) ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) associated_data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct KesDecryptDataKeyResponse {
    pub(crate) plaintext: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KmsProviderKind {
    Generic,
    VaultTransit,
    Kes,
}

pub(crate) fn kms_external_enabled() -> bool {
    std::env::var("RUSTIO_KMS_EXTERNAL_ENABLED")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub(crate) fn kms_provider_kind() -> KmsProviderKind {
    match std::env::var("RUSTIO_KMS_PROVIDER")
        .unwrap_or_else(|_| "generic".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "kes" => KmsProviderKind::Kes,
        "vault" | "vault-transit" | "vault_transit" => KmsProviderKind::VaultTransit,
        _ => KmsProviderKind::Generic,
    }
}

pub(crate) fn kms_provider_label() -> &'static str {
    match kms_provider_kind() {
        KmsProviderKind::Generic => "generic",
        KmsProviderKind::VaultTransit => "vault-transit",
        KmsProviderKind::Kes => "kes",
    }
}

pub(crate) fn kms_token() -> Option<String> {
    std::env::var("RUSTIO_KMS_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn kms_api_key() -> Option<String> {
    std::env::var("RUSTIO_KMS_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn kms_auth_mode() -> String {
    match (
        kms_token().is_some(),
        kms_api_key().is_some(),
        kms_provider_kind(),
    ) {
        (true, true, KmsProviderKind::Kes) => "bearer+x-kes-api-key".to_string(),
        (true, _, KmsProviderKind::Kes) => "bearer".to_string(),
        (false, true, KmsProviderKind::Kes) => "x-kes-api-key".to_string(),
        (true, _, _) => "bearer+x-vault-token".to_string(),
        _ => "none".to_string(),
    }
}

pub(crate) fn kms_endpoint_valid(endpoint: &str) -> bool {
    !endpoint.is_empty() && (endpoint.starts_with("http://") || endpoint.starts_with("https://"))
}

pub(crate) fn s3_kms_not_configured(resource: &str, message: &str) -> Response {
    s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "KMSNotConfigured",
        message,
        resource,
    )
}

