//! S3 桶级操作与事件流

use super::*;

#[derive(Debug, Deserialize, Default)]
pub(crate) struct S3BucketQuery {
    #[serde(rename = "list-type")]
    pub(crate) list_type: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) delimiter: Option<String>,
    pub(crate) marker: Option<String>,
    #[serde(rename = "continuation-token")]
    pub(crate) continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    pub(crate) start_after: Option<String>,
    #[serde(rename = "max-keys")]
    pub(crate) max_keys: Option<usize>,
    #[serde(rename = "key-marker")]
    pub(crate) key_marker: Option<String>,
    #[serde(rename = "version-id-marker")]
    pub(crate) version_id_marker: Option<String>,
    #[serde(rename = "encoding-type")]
    pub(crate) encoding_type: Option<String>,
    pub(crate) location: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CompleteMultipartUploadRequest {
    #[serde(rename = "Part", default)]
    pub(crate) parts: Vec<CompleteMultipartPart>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CompleteMultipartPart {
    pub(crate) part_number: u32,
    pub(crate) etag: Option<String>,
    #[serde(rename = "ChecksumCRC32")]
    pub(crate) checksum_crc32: Option<String>,
    #[serde(rename = "ChecksumCRC32C")]
    pub(crate) checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumSHA1")]
    pub(crate) checksum_sha1: Option<String>,
    #[serde(rename = "ChecksumSHA256")]
    pub(crate) checksum_sha256: Option<String>,
    #[serde(rename = "ChecksumCRC64NVME")]
    pub(crate) checksum_crc64nvme: Option<String>,
}

impl CompleteMultipartPart {
    /// 取请求 XML 中携带的 checksum（算法, base64 值）；多个并存时返回 Err。
    pub(crate) fn declared_checksum(&self) -> Result<Option<(ChecksumAlgorithm, String)>, String> {
        let mut found: Vec<(ChecksumAlgorithm, String)> = Vec::new();
        let candidates = [
            (ChecksumAlgorithm::Crc32, &self.checksum_crc32),
            (ChecksumAlgorithm::Crc32c, &self.checksum_crc32c),
            (ChecksumAlgorithm::Sha1, &self.checksum_sha1),
            (ChecksumAlgorithm::Sha256, &self.checksum_sha256),
            (ChecksumAlgorithm::Crc64Nvme, &self.checksum_crc64nvme),
        ];
        for (algorithm, value) in candidates {
            if let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                found.push((algorithm, value.to_string()));
            }
        }
        if found.len() > 1 {
            return Err("Expecting a single checksum per part".to_string());
        }
        Ok(found.pop())
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectObjectContentRequestBody {
    pub(crate) expression: Option<String>,
    pub(crate) expression_type: Option<String>,
    pub(crate) input_serialization: Option<SelectInputSerialization>,
    pub(crate) output_serialization: Option<SelectOutputSerialization>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectInputSerialization {
    #[serde(rename = "CSV")]
    pub(crate) csv: Option<SelectCsvInputSerialization>,
    #[serde(rename = "JSON")]
    pub(crate) json: Option<SelectJsonInputSerialization>,
    pub(crate) compression_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectCsvInputSerialization {
    pub(crate) file_header_info: Option<String>,
    pub(crate) field_delimiter: Option<String>,
    pub(crate) quote_character: Option<String>,
    pub(crate) quote_escape_character: Option<String>,
    pub(crate) record_delimiter: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectJsonInputSerialization {
    #[serde(rename = "Type")]
    pub(crate) json_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectOutputSerialization {
    #[serde(rename = "CSV")]
    pub(crate) csv: Option<SelectCsvOutputSerialization>,
    #[serde(rename = "JSON")]
    pub(crate) json: Option<SelectJsonOutputSerialization>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectCsvOutputSerialization {
    pub(crate) field_delimiter: Option<String>,
    pub(crate) quote_character: Option<String>,
    pub(crate) quote_escape_character: Option<String>,
    pub(crate) record_delimiter: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SelectJsonOutputSerialization {
    pub(crate) record_delimiter: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum SelectInputFormat {
    Csv(SelectCsvRuntimeConfig),
    Json(SelectJsonRuntimeConfig),
}

#[derive(Debug, Clone)]
pub(crate) struct SelectCsvRuntimeConfig {
    pub(crate) file_header_info: String,
    pub(crate) field_delimiter: u8,
    pub(crate) quote_character: u8,
    pub(crate) quote_escape_character: u8,
    pub(crate) record_delimiter: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SelectJsonRuntimeConfig {
    pub(crate) json_type: String,
}

#[derive(Debug, Clone)]
pub(crate) enum SelectOutputFormat {
    Csv(SelectCsvOutputRuntimeConfig),
    Json(SelectJsonOutputRuntimeConfig),
}

#[derive(Debug, Clone)]
pub(crate) struct SelectCsvOutputRuntimeConfig {
    pub(crate) field_delimiter: u8,
    pub(crate) quote_character: u8,
    pub(crate) quote_escape_character: u8,
    pub(crate) record_delimiter: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SelectJsonOutputRuntimeConfig {
    pub(crate) record_delimiter: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedSelectExpression {
    pub(crate) projections: Vec<SelectProjection>,
    pub(crate) where_clause: Option<SelectPredicate>,
}

#[derive(Debug, Clone)]
pub(crate) struct SelectProjection {
    pub(crate) path: Option<String>,
    pub(crate) alias: String,
    pub(crate) star: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SelectPredicate {
    pub(crate) path: String,
    pub(crate) operator: String,
    pub(crate) value: Value,
}

#[derive(Debug, Clone)]
pub(crate) enum SelectRow {
    Csv {
        values: Vec<String>,
        headers: Option<Vec<String>>,
    },
    Json(Value),
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3VersioningConfiguration {
    pub(crate) status: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3ObjectLockLegalHoldBody {
    pub(crate) status: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3ObjectLockRetentionBody {
    pub(crate) mode: Option<String>,
    pub(crate) retain_until_date: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename = "RestoreRequest", rename_all = "PascalCase")]
pub(crate) struct S3RestoreObjectRequestBody {
    pub(crate) days: Option<u32>,
    pub(crate) glacier_job_parameters: Option<S3RestoreGlacierJobParameters>,
    pub(crate) tier: Option<String>,
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3RestoreGlacierJobParameters {
    pub(crate) tier: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3BucketObjectLockConfigurationBody {
    pub(crate) object_lock_enabled: Option<String>,
    pub(crate) rule: Option<S3BucketObjectLockRuleBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3BucketObjectLockRuleBody {
    pub(crate) default_retention: Option<S3BucketDefaultRetentionBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3BucketDefaultRetentionBody {
    pub(crate) mode: Option<String>,
    pub(crate) days: Option<u32>,
    pub(crate) years: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3CorsConfigurationBody {
    #[serde(rename = "CORSRule", default)]
    pub(crate) cors_rules: Vec<S3CorsRuleBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3CorsRuleBody {
    #[serde(rename = "ID")]
    pub(crate) id: Option<String>,
    #[serde(rename = "AllowedOrigin", default)]
    pub(crate) allowed_origins: Vec<String>,
    #[serde(rename = "AllowedMethod", default)]
    pub(crate) allowed_methods: Vec<String>,
    #[serde(rename = "AllowedHeader", default)]
    pub(crate) allowed_headers: Vec<String>,
    #[serde(rename = "ExposeHeader", default)]
    pub(crate) expose_headers: Vec<String>,
    #[serde(rename = "MaxAgeSeconds")]
    pub(crate) max_age_seconds: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3TaggingBody {
    #[serde(rename = "TagSet")]
    pub(crate) tag_set: Option<S3TagSetBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3TagSetBody {
    #[serde(rename = "Tag", default)]
    pub(crate) tags: Vec<S3TagBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3TagBody {
    pub(crate) key: Option<String>,
    pub(crate) value: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3EncryptionConfigurationBody {
    #[serde(rename = "Rule", default)]
    pub(crate) rules: Vec<S3EncryptionRuleBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3EncryptionRuleBody {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    pub(crate) default: Option<S3EncryptionDefaultBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3EncryptionDefaultBody {
    #[serde(rename = "SSEAlgorithm")]
    pub(crate) sse_algorithm: Option<String>,
    #[serde(rename = "KMSMasterKeyID")]
    pub(crate) kms_master_key_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleConfigurationBody {
    #[serde(rename = "Rule", default)]
    pub(crate) rules: Vec<S3LifecycleRuleBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleRuleBody {
    #[serde(rename = "ID")]
    pub(crate) id: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) filter: Option<S3LifecycleFilterBody>,
    pub(crate) status: Option<String>,
    pub(crate) expiration: Option<S3LifecycleExpirationBody>,
    pub(crate) transition: Option<S3LifecycleTransitionBody>,
    pub(crate) noncurrent_version_expiration: Option<S3LifecycleNoncurrentExpirationBody>,
    pub(crate) noncurrent_version_transition: Option<S3LifecycleNoncurrentTransitionBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleFilterBody {
    pub(crate) prefix: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleExpirationBody {
    pub(crate) days: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleTransitionBody {
    pub(crate) days: Option<u32>,
    pub(crate) storage_class: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleNoncurrentExpirationBody {
    pub(crate) noncurrent_days: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3LifecycleNoncurrentTransitionBody {
    pub(crate) noncurrent_days: Option<u32>,
    pub(crate) storage_class: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3NotificationConfigurationBody {
    #[serde(rename = "TopicConfiguration", default)]
    pub(crate) topic_configurations: Vec<S3NotificationTargetBody>,
    #[serde(rename = "QueueConfiguration", default)]
    pub(crate) queue_configurations: Vec<S3NotificationTargetBody>,
    #[serde(rename = "CloudFunctionConfiguration", default)]
    pub(crate) cloud_function_configurations: Vec<S3NotificationTargetBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3NotificationTargetBody {
    #[serde(rename = "Id")]
    pub(crate) id: Option<String>,
    #[serde(rename = "Event", default)]
    pub(crate) events: Vec<String>,
    #[serde(rename = "Topic")]
    pub(crate) topic: Option<String>,
    #[serde(rename = "Queue")]
    pub(crate) queue: Option<String>,
    #[serde(rename = "CloudFunction")]
    pub(crate) cloud_function: Option<String>,
    pub(crate) filter: Option<S3NotificationFilterBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3NotificationFilterBody {
    #[serde(rename = "S3Key")]
    pub(crate) s3_key: Option<S3NotificationS3KeyBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3NotificationS3KeyBody {
    #[serde(rename = "FilterRule", default)]
    pub(crate) filter_rules: Vec<S3NotificationFilterRuleBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3NotificationFilterRuleBody {
    pub(crate) name: Option<String>,
    pub(crate) value: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3AccessControlPolicyBody {
    pub(crate) access_control_list: Option<S3AccessControlListBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3AccessControlListBody {
    #[serde(rename = "Grant", default)]
    pub(crate) grants: Vec<S3AccessControlGrantBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3AccessControlGrantBody {
    pub(crate) grantee: Option<S3AccessControlGranteeBody>,
    pub(crate) permission: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3AccessControlGranteeBody {
    pub(crate) uri: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3DeleteObjectsBody {
    #[serde(rename = "Quiet")]
    pub(crate) quiet: Option<String>,
    #[serde(rename = "Object", default)]
    pub(crate) objects: Vec<S3DeleteObjectItemBody>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3DeleteObjectItemBody {
    pub(crate) key: Option<String>,
    #[serde(rename = "VersionId")]
    pub(crate) version_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct S3DeleteObjectResultEntry {
    pub(crate) key: String,
    pub(crate) version_id: Option<String>,
    pub(crate) delete_marker: bool,
    pub(crate) delete_marker_version_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct S3DeleteObjectErrorEntry {
    pub(crate) key: String,
    pub(crate) version_id: Option<String>,
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct S3PublicAccessBlockConfigurationBody {
    pub(crate) block_public_acls: Option<bool>,
    pub(crate) ignore_public_acls: Option<bool>,
    pub(crate) block_public_policy: Option<bool>,
    pub(crate) restrict_public_buckets: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct DiskObjectEntry {
    pub(crate) key: String,
    pub(crate) size: u64,
    pub(crate) etag: String,
    pub(crate) last_modified: String,
    pub(crate) storage_class: String,
}

pub(crate) async fn s3_root_create_bucket(
    State(state): State<Arc<AppState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = ensure_s3_auth(&headers, &method, &uri, Some(body.as_ref()), &state) {
        return response;
    }

    if query_has_key(uri.query(), "policy") {
        return s3_root_put_bucket_policy(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "acl") {
        return s3_root_put_bucket_acl(state, bucket, headers, body).await;
    }

    if query_has_key(uri.query(), "cors") {
        return s3_root_put_bucket_cors(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "tagging") {
        return s3_root_put_bucket_tagging(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "encryption") {
        return s3_root_put_bucket_encryption(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "lifecycle") {
        return s3_root_put_bucket_lifecycle(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "object-lock") {
        return s3_root_put_bucket_object_lock(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "notification") {
        return s3_root_put_bucket_notification(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "publicAccessBlock")
        || query_has_key(uri.query(), "public-access-block")
    {
        return s3_root_put_bucket_public_access_block(state, bucket, body).await;
    }

    if query_has_key(uri.query(), "versioning") {
        return s3_root_update_bucket_versioning(state, bucket, body).await;
    }

    let bucket_path = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if bucket_path.exists() {
        return s3_error(
            StatusCode::CONFLICT,
            "BucketAlreadyOwnedByYou",
            "Bucket already exists",
            &bucket,
        );
    }

    if let Err(err) = tokio::fs::create_dir_all(&bucket_path).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to create bucket: {err}"),
            &bucket,
        );
    }

    let object_lock_enabled = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-bucket-object-lock-enabled",
        ))
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let spec = BucketSpec {
        name: bucket.clone(),
        tenant_id: "default".to_string(),
        versioning: true,
        object_lock: object_lock_enabled,
        ilm_policy: None,
        replication_policy: None,
    };

    if let Err(err) = state
        .submit_metadata_command(MetadataCommand::CreateBucket(Box::new(spec)))
        .await
    {
        return s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "InternalError",
            &format!("metadata raft commit failed: {err}"),
            "/",
        );
    }

    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_update_bucket_versioning(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let xml_text = String::from_utf8_lossy(&body);
    let parsed = match from_xml_str::<S3VersioningConfiguration>(&xml_text) {
        Ok(parsed) => parsed,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse bucket versioning XML: {err}"),
                &bucket,
            );
        }
    };

    let status = parsed
        .status
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let versioning = match status.as_str() {
        "enabled" => true,
        "suspended" => false,
        _ => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "Versioning status must be Enabled or Suspended",
                &bucket,
            );
        }
    };

    {
        let mut buckets = state.buckets.write().await;
        let bucket_spec = buckets.entry(bucket.clone()).or_insert_with(|| BucketSpec {
            name: bucket.clone(),
            tenant_id: "default".to_string(),
            versioning: true,
            object_lock: false,
            ilm_policy: None,
            replication_policy: None,
        });
        bucket_spec.versioning = versioning;
    }

    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_get_bucket_policy(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state.bucket_policies.read().await.get(&bucket).cloned();
    if cached.is_none() {
        let policy_path = bucket_policy_path(&bucket_dir);
        match tokio::fs::read(&policy_path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode bucket policy: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_policies
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read bucket policy: {err}"),
                    &bucket,
                )
            }
        }
    }

    let Some(policy) = cached else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucketPolicy",
            "The bucket policy does not exist",
            &bucket,
        );
    };

    let body = match serde_json::to_string_pretty(&policy) {
        Ok(body) => body,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to serialize bucket policy: {err}"),
                &bucket,
            )
        }
    };
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

pub(crate) async fn s3_root_put_bucket_policy(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedPolicy",
                &format!("Invalid policy JSON: {err}"),
                &bucket,
            )
        }
    };
    if !parsed.is_object() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedPolicy",
            "Policy document must be a JSON object",
            &bucket,
        );
    }

    let path = bucket_policy_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create policy directory: {err}"),
                &bucket,
            );
        }
    }

    let bytes = match serde_json::to_vec_pretty(&parsed) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode bucket policy: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist bucket policy: {err}"),
            &bucket,
        );
    }
    state.bucket_policies.write().await.insert(bucket, parsed);
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_delete_bucket_policy(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    state.bucket_policies.write().await.remove(&bucket);
    let path = bucket_policy_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(&path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to delete bucket policy: {err}"),
                &bucket,
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) fn infer_acl_from_policy_body(body: &S3AccessControlPolicyBody) -> String {
    let mut public_read = false;
    let mut public_write = false;
    let mut authenticated_read = false;

    for grant in body
        .access_control_list
        .as_ref()
        .map(|list| list.grants.iter())
        .into_iter()
        .flatten()
    {
        let permission = grant
            .permission
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase();
        let uri = grant
            .grantee
            .as_ref()
            .and_then(|item| item.uri.as_deref())
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if uri.contains("/allusers") {
            if permission == "READ" {
                public_read = true;
            }
            if permission == "WRITE" || permission == "FULL_CONTROL" {
                public_write = true;
            }
        }
        if uri.contains("/authenticatedusers") && permission == "READ" {
            authenticated_read = true;
        }
    }

    if public_write {
        "public-read-write".to_string()
    } else if public_read {
        "public-read".to_string()
    } else if authenticated_read {
        "authenticated-read".to_string()
    } else {
        "private".to_string()
    }
}

pub(crate) async fn s3_root_get_bucket_acl(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state.bucket_acls.read().await.get(&bucket).cloned();
    if cached.is_none() {
        let path = bucket_acl_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<BucketAclConfig>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode bucket acl: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_acls
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read bucket acl: {err}"),
                    &bucket,
                )
            }
        }
    }

    let acl = cached.unwrap_or_else(default_bucket_acl_config);
    s3_xml_response(StatusCode::OK, build_bucket_acl_xml(&bucket, &acl.acl))
}

pub(crate) async fn s3_root_put_bucket_acl(
    state: Arc<AppState>,
    bucket: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let acl = if let Some(raw_acl) =
        headers.get(axum::http::header::HeaderName::from_static("x-amz-acl"))
    {
        match raw_acl.to_str() {
            Ok(value) => match normalize_bucket_acl_value(value) {
                Ok(normalized) => normalized,
                Err(err) => {
                    return s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidArgument",
                        &err.message,
                        &bucket,
                    )
                }
            },
            Err(_) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "x-amz-acl header is invalid",
                    &bucket,
                )
            }
        }
    } else if body.is_empty() {
        "private".to_string()
    } else {
        let parsed =
            match from_xml_str::<S3AccessControlPolicyBody>(&String::from_utf8_lossy(&body)) {
                Ok(value) => value,
                Err(err) => {
                    return s3_error(
                        StatusCode::BAD_REQUEST,
                        "MalformedXML",
                        &format!("Failed to parse ACL XML: {err}"),
                        &bucket,
                    )
                }
            };
        infer_acl_from_policy_body(&parsed)
    };

    let config = BucketAclConfig { acl };
    let path = bucket_acl_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create ACL directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&config) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode bucket ACL: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist bucket ACL: {err}"),
            &bucket,
        );
    }
    state.bucket_acls.write().await.insert(bucket, config);
    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_get_bucket_public_access_block(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state
        .bucket_public_access_blocks
        .read()
        .await
        .get(&bucket)
        .cloned();
    if cached.is_none() {
        let path = bucket_public_access_block_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<BucketPublicAccessBlockConfig>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode public access block: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_public_access_blocks
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read public access block: {err}"),
                    &bucket,
                )
            }
        }
    }

    let config = cached.unwrap_or_else(default_bucket_public_access_block_config);
    s3_xml_response(
        StatusCode::OK,
        build_bucket_public_access_block_xml(&config),
    )
}

pub(crate) async fn s3_root_put_bucket_public_access_block(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed =
        match from_xml_str::<S3PublicAccessBlockConfigurationBody>(&String::from_utf8_lossy(&body))
        {
            Ok(value) => value,
            Err(err) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    &format!("Failed to parse public access block XML: {err}"),
                    &bucket,
                )
            }
        };

    let config = BucketPublicAccessBlockConfig {
        block_public_acls: parsed.block_public_acls.unwrap_or(false),
        ignore_public_acls: parsed.ignore_public_acls.unwrap_or(false),
        block_public_policy: parsed.block_public_policy.unwrap_or(false),
        restrict_public_buckets: parsed.restrict_public_buckets.unwrap_or(false),
    };
    let path = bucket_public_access_block_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create public access block directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&config) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode public access block: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist public access block: {err}"),
            &bucket,
        );
    }
    state
        .bucket_public_access_blocks
        .write()
        .await
        .insert(bucket, config);
    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_delete_bucket_public_access_block(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    state
        .bucket_public_access_blocks
        .write()
        .await
        .remove(&bucket);
    let path = bucket_public_access_block_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to delete public access block: {err}"),
                &bucket,
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_get_bucket_cors(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state.bucket_cors_rules.read().await.get(&bucket).cloned();
    if cached.is_none() {
        let path = bucket_cors_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<Vec<BucketCorsRule>>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode bucket cors: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_cors_rules
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read bucket cors: {err}"),
                    &bucket,
                )
            }
        }
    }

    let Some(rules) = cached else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchCORSConfiguration",
            "The CORS configuration does not exist",
            &bucket,
        );
    };
    s3_xml_response(StatusCode::OK, build_bucket_cors_xml(&rules))
}

pub(crate) async fn s3_root_put_bucket_cors(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed = match from_xml_str::<S3CorsConfigurationBody>(&String::from_utf8_lossy(&body)) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse bucket cors XML: {err}"),
                &bucket,
            )
        }
    };

    if parsed.cors_rules.is_empty() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "CORSRule cannot be empty",
            &bucket,
        );
    }

    let mut normalized = Vec::with_capacity(parsed.cors_rules.len());
    let mut ids = HashSet::new();
    for (index, rule) in parsed.cors_rules.into_iter().enumerate() {
        let generated_id = format!("rule-{}", index + 1);
        let normalized_rule = match normalize_cors_rule(BucketCorsRule {
            id: rule.id.unwrap_or(generated_id),
            allowed_origins: rule.allowed_origins,
            allowed_methods: rule.allowed_methods,
            allowed_headers: rule.allowed_headers,
            expose_headers: rule.expose_headers,
            max_age_seconds: rule.max_age_seconds,
        }) {
            Ok(value) => value,
            Err(err) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &err.message,
                    &bucket,
                )
            }
        };
        if !ids.insert(normalized_rule.id.clone()) {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "CORSRule ID must be unique",
                &bucket,
            );
        }
        normalized.push(normalized_rule);
    }

    let path = bucket_cors_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create cors directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&normalized) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode bucket cors: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist bucket cors: {err}"),
            &bucket,
        );
    }

    state
        .bucket_cors_rules
        .write()
        .await
        .insert(bucket, normalized);
    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_delete_bucket_cors(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    state.bucket_cors_rules.write().await.remove(&bucket);
    let path = bucket_cors_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to delete bucket cors: {err}"),
                &bucket,
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_get_bucket_tagging(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state.bucket_tags.read().await.get(&bucket).cloned();
    if cached.is_none() {
        let path = bucket_tags_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<Vec<BucketTag>>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode bucket tags: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_tags
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read bucket tags: {err}"),
                    &bucket,
                )
            }
        }
    }

    let Some(tags) = cached else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchTagSet",
            "The TagSet does not exist",
            &bucket,
        );
    };
    s3_xml_response(StatusCode::OK, build_bucket_tagging_xml(&tags))
}

pub(crate) async fn s3_root_put_bucket_tagging(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed = match from_xml_str::<S3TaggingBody>(&String::from_utf8_lossy(&body)) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse bucket tagging XML: {err}"),
                &bucket,
            )
        }
    };

    let tag_rows = parsed.tag_set.unwrap_or_default().tags;
    let normalized = match normalize_s3_tagset(
        tag_rows
            .into_iter()
            .map(|tag| BucketTag {
                key: tag.key.unwrap_or_default(),
                value: tag.value.unwrap_or_default(),
            })
            .collect(),
        false,
    ) {
        Ok(tags) => tags,
        Err(message) => return s3_error(StatusCode::BAD_REQUEST, "InvalidTag", message, &bucket),
    };

    let path = bucket_tags_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create tags directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&normalized) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode bucket tags: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist bucket tags: {err}"),
            &bucket,
        );
    }
    state.bucket_tags.write().await.insert(bucket, normalized);
    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_delete_bucket_tagging(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }
    state.bucket_tags.write().await.remove(&bucket);
    let path = bucket_tags_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to delete bucket tags: {err}"),
                &bucket,
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_get_bucket_encryption(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state.bucket_encryptions.read().await.get(&bucket).cloned();
    if cached.is_none() {
        let path = bucket_encryption_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<BucketEncryptionConfig>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode bucket encryption: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_encryptions
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read bucket encryption: {err}"),
                    &bucket,
                )
            }
        }
    }

    let Some(config) = cached else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "ServerSideEncryptionConfigurationNotFoundError",
            "The server-side encryption configuration was not found",
            &bucket,
        );
    };
    s3_xml_response(StatusCode::OK, build_bucket_encryption_xml(&config))
}

pub(crate) async fn s3_root_put_bucket_encryption(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed =
        match from_xml_str::<S3EncryptionConfigurationBody>(&String::from_utf8_lossy(&body)) {
            Ok(value) => value,
            Err(err) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    &format!("Failed to parse bucket encryption XML: {err}"),
                    &bucket,
                )
            }
        };

    let Some(default_config) = parsed.rules.into_iter().find_map(|rule| rule.default) else {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "ApplyServerSideEncryptionByDefault is required",
            &bucket,
        );
    };

    let normalized = match normalize_bucket_encryption(BucketEncryptionConfig {
        enabled: true,
        algorithm: default_config.sse_algorithm.unwrap_or_default(),
        kms_key_id: default_config.kms_master_key_id,
    }) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                &err.message,
                &bucket,
            )
        }
    };

    let path = bucket_encryption_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create encryption directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&normalized) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode bucket encryption: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist bucket encryption: {err}"),
            &bucket,
        );
    }
    state
        .bucket_encryptions
        .write()
        .await
        .insert(bucket, normalized);
    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_delete_bucket_encryption(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }
    state.bucket_encryptions.write().await.remove(&bucket);
    let path = bucket_encryption_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to delete bucket encryption: {err}"),
                &bucket,
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) async fn s3_root_get_bucket_object_lock(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let bucket_spec = state.buckets.read().await.get(&bucket).cloned();
    let config = state
        .bucket_object_locks
        .read()
        .await
        .get(&bucket)
        .cloned()
        .or_else(|| bucket_spec.as_ref().map(default_object_lock_config));

    let Some(config) = config else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "ObjectLockConfigurationNotFoundError",
            "Object Lock configuration does not exist for this bucket",
            &bucket,
        );
    };
    if !config.enabled {
        return s3_error(
            StatusCode::NOT_FOUND,
            "ObjectLockConfigurationNotFoundError",
            "Object Lock configuration does not exist for this bucket",
            &bucket,
        );
    }

    s3_xml_response(StatusCode::OK, build_bucket_object_lock_xml(&config))
}

pub(crate) async fn s3_root_put_bucket_object_lock(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed = match from_xml_str::<S3BucketObjectLockConfigurationBody>(
        &String::from_utf8_lossy(&body),
    ) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse object lock XML: {err}"),
                &bucket,
            )
        }
    };

    let enabled = parsed
        .object_lock_enabled
        .as_deref()
        .map(|value| value.trim().eq_ignore_ascii_case("Enabled"))
        .unwrap_or(true);
    if !enabled {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "ObjectLockEnabled must be Enabled",
            &bucket,
        );
    }

    let default_retention = parsed.rule.and_then(|rule| rule.default_retention);
    let mode = default_retention
        .as_ref()
        .and_then(|retention| retention.mode.clone())
        .unwrap_or_else(|| "GOVERNANCE".to_string());
    let mode = match normalize_retention_mode(&mode) {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                &err.message,
                &bucket,
            )
        }
    };

    let default_retention_days = if let Some(retention) = default_retention {
        if let Some(days) = retention.days {
            if days == 0 {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "Default retention days must be greater than 0",
                    &bucket,
                );
            }
            days
        } else if let Some(years) = retention.years {
            if years == 0 {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "Default retention years must be greater than 0",
                    &bucket,
                );
            }
            years.saturating_mul(365)
        } else {
            30
        }
    } else {
        30
    };

    let config = BucketObjectLockConfig {
        enabled: true,
        mode,
        default_retention_days,
    };
    state
        .bucket_object_locks
        .write()
        .await
        .insert(bucket.clone(), config);
    if let Some(spec) = state.buckets.write().await.get_mut(&bucket) {
        spec.object_lock = true;
    }

    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_get_bucket_lifecycle(state: Arc<AppState>, bucket: String) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state
        .bucket_lifecycle_rules
        .read()
        .await
        .get(&bucket)
        .cloned();
    if cached.is_none() {
        let path = bucket_lifecycle_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<Vec<BucketLifecycleRule>>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode lifecycle configuration: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_lifecycle_rules
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read lifecycle configuration: {err}"),
                    &bucket,
                )
            }
        }
    }

    let Some(rules) = cached else {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchLifecycleConfiguration",
            "The lifecycle configuration does not exist",
            &bucket,
        );
    };
    s3_xml_response(StatusCode::OK, build_bucket_lifecycle_xml(&rules))
}

pub(crate) async fn s3_root_put_bucket_lifecycle(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed = match from_xml_str::<S3LifecycleConfigurationBody>(&String::from_utf8_lossy(&body))
    {
        Ok(value) => value,
        Err(err) => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!("Failed to parse lifecycle XML: {err}"),
                &bucket,
            )
        }
    };
    if parsed.rules.is_empty() {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "Rule cannot be empty",
            &bucket,
        );
    }

    let mut normalized = Vec::with_capacity(parsed.rules.len());
    let mut ids = HashSet::new();
    for (index, rule) in parsed.rules.into_iter().enumerate() {
        let prefix = rule
            .filter
            .and_then(|item| item.prefix)
            .or(rule.prefix)
            .and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_string()));
        let normalized_rule = match normalize_lifecycle_rule(BucketLifecycleRule {
            id: rule.id.unwrap_or_else(|| format!("rule-{}", index + 1)),
            prefix,
            status: rule.status.unwrap_or_else(|| "Enabled".to_string()),
            expiration_days: rule.expiration.and_then(|item| item.days),
            transition_days: rule.transition.as_ref().and_then(|item| item.days),
            transition_tier: rule.transition.and_then(|item| item.storage_class),
            noncurrent_expiration_days: rule
                .noncurrent_version_expiration
                .and_then(|item| item.noncurrent_days),
            noncurrent_transition_days: rule
                .noncurrent_version_transition
                .as_ref()
                .and_then(|item| item.noncurrent_days),
            noncurrent_transition_tier: rule
                .noncurrent_version_transition
                .and_then(|item| item.storage_class),
        }) {
            Ok(value) => value,
            Err(err) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &err.message,
                    &bucket,
                )
            }
        };
        if !ids.insert(normalized_rule.id.clone()) {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Lifecycle rule ID must be unique",
                &bucket,
            );
        }
        normalized.push(normalized_rule);
    }

    let path = bucket_lifecycle_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create lifecycle directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&normalized) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode lifecycle configuration: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist lifecycle configuration: {err}"),
            &bucket,
        );
    }

    state
        .bucket_lifecycle_rules
        .write()
        .await
        .insert(bucket, normalized);
    StatusCode::OK.into_response()
}

pub(crate) async fn s3_root_delete_bucket_lifecycle(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }
    state.bucket_lifecycle_rules.write().await.remove(&bucket);
    let path = bucket_lifecycle_path(&bucket_dir);
    if let Err(err) = tokio::fs::remove_file(path).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to delete lifecycle configuration: {err}"),
                &bucket,
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) fn notification_prefix_suffix(
    filter: Option<S3NotificationFilterBody>,
) -> (Option<String>, Option<String>) {
    let mut prefix = None;
    let mut suffix = None;
    let rules = filter
        .and_then(|item| item.s3_key)
        .map(|item| item.filter_rules)
        .unwrap_or_default();

    for rule in rules {
        let name = rule.name.unwrap_or_default().trim().to_ascii_lowercase();
        let value = rule.value.unwrap_or_default().trim().to_string();
        if value.is_empty() {
            continue;
        }
        match name.as_str() {
            "prefix" => prefix = Some(value),
            "suffix" => suffix = Some(value),
            _ => {}
        }
    }

    (prefix, suffix)
}

pub(crate) async fn s3_root_get_bucket_notification(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let mut cached = state
        .bucket_notifications
        .read()
        .await
        .get(&bucket)
        .cloned();
    if cached.is_none() {
        let path = bucket_notifications_path(&bucket_dir);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let parsed = match serde_json::from_slice::<Vec<BucketNotificationRule>>(&bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        return s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to decode bucket notification: {err}"),
                            &bucket,
                        )
                    }
                };
                state
                    .bucket_notifications
                    .write()
                    .await
                    .insert(bucket.clone(), parsed.clone());
                cached = Some(parsed);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read bucket notification: {err}"),
                    &bucket,
                )
            }
        }
    }

    let rules = cached.unwrap_or_default();
    s3_xml_response(StatusCode::OK, build_bucket_notification_xml(&rules))
}

pub(crate) async fn s3_root_put_bucket_notification(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let bucket_dir = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };
    if !bucket_dir.exists() {
        return s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            &bucket,
        );
    }

    let parsed =
        match from_xml_str::<S3NotificationConfigurationBody>(&String::from_utf8_lossy(&body)) {
            Ok(value) => value,
            Err(err) => {
                return s3_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    &format!("Failed to parse notification XML: {err}"),
                    &bucket,
                )
            }
        };

    let mut normalized = Vec::new();
    let mut ids = HashSet::new();
    let mut sequence: usize = 1;

    let mut append_target_configs = |configs: Vec<S3NotificationTargetBody>,
                                     target_getter: fn(
        &S3NotificationTargetBody,
    ) -> Option<String>|
     -> Result<(), Response> {
        for config in configs {
            let target = target_getter(&config)
                .unwrap_or_default()
                .trim()
                .to_string();
            if target.is_empty() {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "Notification target cannot be empty",
                    &bucket,
                ));
            }

            let base_id = config.id.unwrap_or_else(|| {
                let current = sequence;
                sequence += 1;
                format!("rule-{current}")
            });
            let (prefix, suffix) = notification_prefix_suffix(config.filter);
            if config.events.is_empty() {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "Notification Event cannot be empty",
                    &bucket,
                ));
            }
            let event_count = config.events.len();
            for (index, event_raw) in config.events.into_iter().enumerate() {
                let id = if event_count == 1 {
                    base_id.clone()
                } else {
                    format!("{base_id}-{}", index + 1)
                };
                let normalized_rule = match normalize_notification_rule(BucketNotificationRule {
                    id,
                    event: event_raw,
                    target: target.clone(),
                    prefix: prefix.clone(),
                    suffix: suffix.clone(),
                    enabled: true,
                }) {
                    Ok(value) => value,
                    Err(err) => {
                        return Err(s3_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidArgument",
                            &err.message,
                            &bucket,
                        ))
                    }
                };
                if !ids.insert(normalized_rule.id.clone()) {
                    return Err(s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidArgument",
                        "Notification rule ID must be unique",
                        &bucket,
                    ));
                }
                normalized.push(normalized_rule);
            }
        }
        Ok(())
    };

    if let Err(response) =
        append_target_configs(parsed.topic_configurations, |config| config.topic.clone())
    {
        return response;
    }
    if let Err(response) =
        append_target_configs(parsed.queue_configurations, |config| config.queue.clone())
    {
        return response;
    }
    if let Err(response) = append_target_configs(parsed.cloud_function_configurations, |config| {
        config.cloud_function.clone()
    }) {
        return response;
    }

    let path = bucket_notifications_path(&bucket_dir);
    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create notification directory: {err}"),
                &bucket,
            );
        }
    }
    let bytes = match serde_json::to_vec_pretty(&normalized) {
        Ok(bytes) => bytes,
        Err(err) => {
            return s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode notification configuration: {err}"),
                &bucket,
            )
        }
    };
    if let Err(err) = tokio::fs::write(&path, bytes).await {
        return s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to persist notification configuration: {err}"),
            &bucket,
        );
    }

    state
        .bucket_notifications
        .write()
        .await
        .insert(bucket, normalized);
    StatusCode::OK.into_response()
}
