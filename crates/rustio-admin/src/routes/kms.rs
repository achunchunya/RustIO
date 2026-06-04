//! KMS 远端数据密钥加解密

use super::*;

pub(crate) fn s3_kms_unavailable(resource: &str, message: &str) -> Response {
    s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "KMSUnavailable",
        message,
        resource,
    )
}

pub(crate) fn kms_context_json(meta: &S3ObjectMeta) -> Value {
    json!({
        "bucket": meta.bucket,
        "key": meta.key,
        "version_id": meta.version_id,
        "algorithm": meta.encryption.algorithm,
    })
}

pub(crate) fn kms_context_base64(meta: &S3ObjectMeta) -> String {
    let bytes = serde_json::to_vec(&kms_context_json(meta)).unwrap_or_else(|_| b"{}".to_vec());
    BASE64.encode(bytes)
}

pub(crate) fn kms_request_builder(client: &Client, url: String) -> reqwest::RequestBuilder {
    let mut request = client.post(url);
    match kms_provider_kind() {
        KmsProviderKind::Kes => {
            if let Some(token) = kms_token() {
                request = request.bearer_auth(token);
            }
            if let Some(api_key) = kms_api_key() {
                request = request.header("x-kes-api-key", api_key);
            }
        }
        KmsProviderKind::Generic | KmsProviderKind::VaultTransit => {
            if let Some(token) = kms_token() {
                request = request
                    .header("x-vault-token", token.clone())
                    .bearer_auth(token);
            }
        }
    }
    request
}

pub(crate) async fn kms_encrypt_data_key_remote(
    state: &AppState,
    resource: &str,
    meta: &S3ObjectMeta,
    data_key: &[u8; 32],
) -> Result<Option<String>, Response> {
    if !meta.encryption.algorithm.eq_ignore_ascii_case("aws:kms") || !kms_external_enabled() {
        return Ok(None);
    }

    let (endpoint, default_key_id) = {
        let security = state.security.read().await;
        (
            security
                .kms_endpoint
                .trim()
                .trim_end_matches('/')
                .to_string(),
            "rustio-default-kms-key".to_string(),
        )
    };
    if !kms_endpoint_valid(&endpoint) {
        mark_kms_health_failure(
            state,
            bilingual_s3_message(
                "KMSNotConfigured",
                "KMS endpoint is not configured for external mode",
            ),
        )
        .await;
        return Err(s3_kms_not_configured(
            resource,
            "KMS endpoint is not configured for external mode",
        ));
    }

    let key_id = meta.encryption.kms_key_id.clone().unwrap_or(default_key_id);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to initialize KMS client: {err}"),
                resource,
            )
        })?;
    let provider = kms_provider_kind();
    let wrapped = match provider {
        KmsProviderKind::Generic => {
            let request = KmsEncryptDataKeyRequest {
                key_id: key_id.clone(),
                plaintext_base64: BASE64.encode(data_key),
                context: kms_context_json(meta),
            };
            let response = kms_request_builder(&client, format!("{endpoint}/v1/crypto/encrypt"))
                .json(&request)
                .send()
                .await;
            let response = match response {
                Ok(value) => value,
                Err(err) => {
                    mark_kms_health_failure(
                        state,
                        bilingual_s3_message(
                            "KMSUnavailable",
                            &format!("KMS encrypt request failed: {err}"),
                        ),
                    )
                    .await;
                    return Err(s3_kms_unavailable(
                        resource,
                        &format!("KMS encrypt request failed: {err}"),
                    ));
                }
            };
            if !response.status().is_success() {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        &format!("KMS encrypt status: {}", response.status()),
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    &format!("KMS encrypt status: {}", response.status()),
                ));
            }
            let parsed = response
                .json::<KmsEncryptDataKeyResponse>()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode KMS encrypt response: {err}"),
                        resource,
                    )
                })?;
            format!("{KMS_WRAP_PREFIX_GENERIC}{}", parsed.ciphertext_base64)
        }
        KmsProviderKind::VaultTransit => {
            let key_path = utf8_percent_encode(&key_id, NON_ALPHANUMERIC).to_string();
            let request = VaultTransitEncryptDataKeyRequest {
                plaintext: BASE64.encode(data_key),
                context: Some(kms_context_base64(meta)),
            };
            let response =
                kms_request_builder(&client, format!("{endpoint}/v1/transit/encrypt/{key_path}"))
                    .json(&request)
                    .send()
                    .await;
            let response = match response {
                Ok(value) => value,
                Err(err) => {
                    mark_kms_health_failure(
                        state,
                        bilingual_s3_message(
                            "KMSUnavailable",
                            &format!("KMS encrypt request failed: {err}"),
                        ),
                    )
                    .await;
                    return Err(s3_kms_unavailable(
                        resource,
                        &format!("KMS encrypt request failed: {err}"),
                    ));
                }
            };
            if !response.status().is_success() {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        &format!("KMS encrypt status: {}", response.status()),
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    &format!("KMS encrypt status: {}", response.status()),
                ));
            }
            let parsed = response
                .json::<VaultTransitEncryptDataKeyResponseEnvelope>()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode Vault transit encrypt response: {err}"),
                        resource,
                    )
                })?;
            format!("{KMS_WRAP_PREFIX_VAULT}{}", parsed.data.ciphertext)
        }
        KmsProviderKind::Kes => {
            let key_path = utf8_percent_encode(&key_id, NON_ALPHANUMERIC).to_string();
            let request = KesGenerateDataKeyRequest {
                plaintext: BASE64.encode(data_key),
                length: data_key.len(),
                associated_data: Some(kms_context_base64(meta)),
            };
            let response =
                kms_request_builder(&client, format!("{endpoint}/v1/key/generate/{key_path}"))
                    .json(&request)
                    .send()
                    .await;
            let response = match response {
                Ok(value) => value,
                Err(err) => {
                    mark_kms_health_failure(
                        state,
                        bilingual_s3_message(
                            "KMSUnavailable",
                            &format!("KMS encrypt request failed: {err}"),
                        ),
                    )
                    .await;
                    return Err(s3_kms_unavailable(
                        resource,
                        &format!("KMS encrypt request failed: {err}"),
                    ));
                }
            };
            if !response.status().is_success() {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        &format!("KMS encrypt status: {}", response.status()),
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    &format!("KMS encrypt status: {}", response.status()),
                ));
            }
            let parsed = response
                .json::<KesGenerateDataKeyResponse>()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode KES encrypt response: {err}"),
                        resource,
                    )
                })?;
            if parsed.plaintext != BASE64.encode(data_key) {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        "KES plaintext data key does not match generated key",
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    "KES plaintext data key does not match generated key",
                ));
            }
            format!("{KMS_WRAP_PREFIX_KES}{}", parsed.ciphertext)
        }
    };
    mark_kms_health_success(state).await;
    Ok(Some(wrapped))
}

pub(crate) async fn kms_decrypt_data_key_remote(
    state: &AppState,
    resource: &str,
    meta: &S3ObjectMeta,
    wrapped_key_base64: &str,
) -> Result<Option<[u8; 32]>, Response> {
    if !meta.encryption.algorithm.eq_ignore_ascii_case("aws:kms") {
        return Ok(None);
    }
    let wrapped = wrapped_key_base64.trim();
    let external_required = kms_external_enabled()
        || wrapped.starts_with(KMS_WRAP_PREFIX_GENERIC)
        || wrapped.starts_with(KMS_WRAP_PREFIX_VAULT)
        || wrapped.starts_with(KMS_WRAP_PREFIX_KES);
    let (provider, ciphertext) = if let Some(value) = wrapped.strip_prefix(KMS_WRAP_PREFIX_GENERIC)
    {
        if !kms_external_enabled() {
            mark_kms_health_failure(
                state,
                bilingual_s3_message(
                    "KMSUnavailable",
                    "KMS external is required to decrypt wrapped key",
                ),
            )
            .await;
            return Err(s3_kms_unavailable(
                resource,
                "KMS external is required to decrypt wrapped key",
            ));
        }
        (KmsProviderKind::Generic, value.to_string())
    } else if let Some(value) = wrapped.strip_prefix(KMS_WRAP_PREFIX_VAULT) {
        if !kms_external_enabled() {
            mark_kms_health_failure(
                state,
                bilingual_s3_message(
                    "KMSUnavailable",
                    "KMS external is required to decrypt wrapped key",
                ),
            )
            .await;
            return Err(s3_kms_unavailable(
                resource,
                "KMS external is required to decrypt wrapped key",
            ));
        }
        (KmsProviderKind::VaultTransit, value.to_string())
    } else if let Some(value) = wrapped.strip_prefix(KMS_WRAP_PREFIX_KES) {
        if !kms_external_enabled() {
            mark_kms_health_failure(
                state,
                bilingual_s3_message(
                    "KMSUnavailable",
                    "KMS external is required to decrypt wrapped key",
                ),
            )
            .await;
            return Err(s3_kms_unavailable(
                resource,
                "KMS external is required to decrypt wrapped key",
            ));
        }
        (KmsProviderKind::Kes, value.to_string())
    } else {
        if !kms_external_enabled() {
            return Ok(None);
        }
        (kms_provider_kind(), wrapped.to_string())
    };

    let endpoint = {
        let security = state.security.read().await;
        security
            .kms_endpoint
            .trim()
            .trim_end_matches('/')
            .to_string()
    };
    if !kms_endpoint_valid(&endpoint) {
        if external_required {
            mark_kms_health_failure(
                state,
                bilingual_s3_message(
                    "KMSNotConfigured",
                    "KMS endpoint is not configured for external mode",
                ),
            )
            .await;
            return Err(s3_kms_not_configured(
                resource,
                "KMS endpoint is not configured for external mode",
            ));
        }
        return Ok(None);
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to initialize KMS client: {err}"),
                resource,
            )
        })?;
    let plaintext_base64 = match provider {
        KmsProviderKind::Generic => {
            let request = KmsDecryptDataKeyRequest {
                ciphertext_base64: ciphertext.clone(),
                context: kms_context_json(meta),
            };
            let response = kms_request_builder(&client, format!("{endpoint}/v1/crypto/decrypt"))
                .json(&request)
                .send()
                .await;
            let response = match response {
                Ok(value) => value,
                Err(err) => {
                    mark_kms_health_failure(
                        state,
                        bilingual_s3_message(
                            "KMSUnavailable",
                            &format!("KMS decrypt request failed: {err}"),
                        ),
                    )
                    .await;
                    return Err(s3_kms_unavailable(
                        resource,
                        &format!("KMS decrypt request failed: {err}"),
                    ));
                }
            };
            if !response.status().is_success() {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        &format!("KMS decrypt status: {}", response.status()),
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    &format!("KMS decrypt status: {}", response.status()),
                ));
            }
            response
                .json::<KmsDecryptDataKeyResponse>()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode KMS decrypt response: {err}"),
                        resource,
                    )
                })?
                .plaintext_base64
        }
        KmsProviderKind::VaultTransit => {
            let key_id = meta
                .encryption
                .kms_key_id
                .clone()
                .unwrap_or_else(|| "rustio-default-kms-key".to_string());
            let key_path = utf8_percent_encode(&key_id, NON_ALPHANUMERIC).to_string();
            let request = VaultTransitDecryptDataKeyRequest {
                ciphertext: ciphertext.clone(),
                context: Some(kms_context_base64(meta)),
            };
            let response =
                kms_request_builder(&client, format!("{endpoint}/v1/transit/decrypt/{key_path}"))
                    .json(&request)
                    .send()
                    .await;
            let response = match response {
                Ok(value) => value,
                Err(err) => {
                    mark_kms_health_failure(
                        state,
                        bilingual_s3_message(
                            "KMSUnavailable",
                            &format!("KMS decrypt request failed: {err}"),
                        ),
                    )
                    .await;
                    return Err(s3_kms_unavailable(
                        resource,
                        &format!("KMS decrypt request failed: {err}"),
                    ));
                }
            };
            if !response.status().is_success() {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        &format!("KMS decrypt status: {}", response.status()),
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    &format!("KMS decrypt status: {}", response.status()),
                ));
            }
            response
                .json::<VaultTransitDecryptDataKeyResponseEnvelope>()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode Vault transit decrypt response: {err}"),
                        resource,
                    )
                })?
                .data
                .plaintext
        }
        KmsProviderKind::Kes => {
            let key_id = meta
                .encryption
                .kms_key_id
                .clone()
                .unwrap_or_else(|| "rustio-default-kms-key".to_string());
            let key_path = utf8_percent_encode(&key_id, NON_ALPHANUMERIC).to_string();
            let request = KesDecryptDataKeyRequest {
                ciphertext: ciphertext.clone(),
                associated_data: Some(kms_context_base64(meta)),
            };
            let response =
                kms_request_builder(&client, format!("{endpoint}/v1/key/decrypt/{key_path}"))
                    .json(&request)
                    .send()
                    .await;
            let response = match response {
                Ok(value) => value,
                Err(err) => {
                    mark_kms_health_failure(
                        state,
                        bilingual_s3_message(
                            "KMSUnavailable",
                            &format!("KMS decrypt request failed: {err}"),
                        ),
                    )
                    .await;
                    return Err(s3_kms_unavailable(
                        resource,
                        &format!("KMS decrypt request failed: {err}"),
                    ));
                }
            };
            if !response.status().is_success() {
                mark_kms_health_failure(
                    state,
                    bilingual_s3_message(
                        "KMSUnavailable",
                        &format!("KMS decrypt status: {}", response.status()),
                    ),
                )
                .await;
                return Err(s3_kms_unavailable(
                    resource,
                    &format!("KMS decrypt status: {}", response.status()),
                ));
            }
            response
                .json::<KesDecryptDataKeyResponse>()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode KES decrypt response: {err}"),
                        resource,
                    )
                })?
                .plaintext
        }
    };
    let decoded = BASE64.decode(plaintext_base64).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to decode KMS plaintext key: {err}"),
            resource,
        )
    })?;
    if decoded.len() != 32 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "KMS plaintext key length is invalid",
            resource,
        ));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded[..32]);
    mark_kms_health_success(state).await;
    Ok(Some(output))
}

pub(crate) async fn wrap_object_data_key(
    state: &AppState,
    resource: &str,
    meta: &S3ObjectMeta,
    data_key: &[u8; 32],
    customer_key: Option<&[u8; 32]>,
) -> Result<String, Response> {
    // SSE-C：客户密钥直接本地包装 DEK
    if let Some(ck) = customer_key {
        return wrap_object_data_key_with_customer_key(resource, data_key, ck);
    }
    if let Some(remote_wrapped) =
        kms_encrypt_data_key_remote(state, resource, meta, data_key).await?
    {
        return Ok(remote_wrapped);
    }
    wrap_object_data_key_local(state, resource, meta, data_key)
}

pub(crate) async fn unwrap_object_data_key(
    state: &AppState,
    resource: &str,
    meta: &S3ObjectMeta,
    wrapped_key_base64: &str,
    customer_key: Option<&[u8; 32]>,
) -> Result<[u8; 32], Response> {
    // SSE-C：检测 ssec: 前缀，用客户密钥本地解包装 DEK
    if let Some(payload) = wrapped_key_base64.strip_prefix(SSEC_WRAP_PREFIX) {
        let ck = customer_key.ok_or_else(|| {
            s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "对象需要 SSE-C 客户密钥才能解密 / object requires SSE-C customer key for decryption",
                resource,
            )
        })?;
        return unwrap_object_data_key_with_customer_key(resource, payload, ck);
    }
    if let Some(remote_data_key) =
        kms_decrypt_data_key_remote(state, resource, meta, wrapped_key_base64).await?
    {
        return Ok(remote_data_key);
    }
    unwrap_object_data_key_local(state, resource, meta, wrapped_key_base64)
}

pub(crate) async fn encrypt_payload_for_storage(
    state: &AppState,
    resource: &str,
    payload: &[u8],
    meta: &mut S3ObjectMeta,
    customer_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Response> {
    if !encryption_enabled(meta) {
        meta.encryption.nonce_base64 = None;
        meta.encryption.wrapped_key_base64 = None;
        return Ok(payload.to_vec());
    }
    ensure_supported_encryption_algorithm(meta, resource)?;
    if meta.encryption.algorithm.eq_ignore_ascii_case("aws:kms")
        && meta.encryption.kms_key_id.is_none()
    {
        meta.encryption.kms_key_id = Some("rustio-default-kms-key".to_string());
    }
    let payload_nonce = random_12_bytes();
    meta.encryption.nonce_base64 = Some(BASE64.encode(payload_nonce));
    let data_key = random_32_bytes();
    meta.encryption.wrapped_key_base64 =
        Some(wrap_object_data_key(state, resource, meta, &data_key, customer_key).await?);
    let cipher = Aes256Gcm::new_from_slice(&data_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize object encryption cipher: {err}"),
            resource,
        )
    })?;
    cipher
        .encrypt(Nonce::from_slice(&payload_nonce), payload)
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to encrypt object payload",
                resource,
            )
        })
}

pub(crate) async fn decrypt_payload_from_storage(
    state: &AppState,
    resource: &str,
    payload: Vec<u8>,
    meta: Option<&S3ObjectMeta>,
    customer_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Response> {
    let Some(meta) = meta else {
        return Ok(payload);
    };
    if !encryption_enabled(meta) {
        return Ok(payload);
    }
    ensure_supported_encryption_algorithm(meta, resource)?;
    let nonce_base64 = meta.encryption.nonce_base64.as_deref().ok_or_else(|| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Missing object encryption nonce metadata",
            resource,
        )
    })?;
    let nonce = BASE64.decode(nonce_base64).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to decode object encryption nonce: {err}"),
            resource,
        )
    })?;
    if nonce.len() != 12 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Object encryption nonce length is invalid",
            resource,
        ));
    }
    let data_key = if let Some(wrapped) = meta.encryption.wrapped_key_base64.as_deref() {
        unwrap_object_data_key(state, resource, meta, wrapped, customer_key).await?
    } else {
        derive_object_encryption_key(state, meta)
    };
    let cipher = Aes256Gcm::new_from_slice(&data_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize object decryption cipher: {err}"),
            resource,
        )
    })?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), payload.as_ref())
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to decrypt object payload",
                resource,
            )
        })
}

pub(crate) async fn cleanup_ec_written_shards(shards: &[EcShardInfo]) -> usize {
    let mut cleanup_failed = 0usize;
    for shard in shards {
        if shard.checksum.is_empty() {
            continue;
        }
        if let Err(err) = tokio::fs::remove_file(&shard.path).await {
            if err.kind() != std::io::ErrorKind::NotFound {
                cleanup_failed += 1;
            }
        }
    }
    cleanup_failed
}

/// 单个 EC 分片加密：base_nonce XOR shard_index 保证每个分片 nonce 唯一（AES-GCM 安全要求）。
#[allow(dead_code)]
pub(crate) async fn encrypt_shard(
    state: &AppState,
    resource: &str,
    shard_data: &[u8],
    meta: &S3ObjectMeta,
    shard_index: usize,
    customer_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Response> {
    let nonce = derive_shard_nonce(meta, shard_index)?;
    let data_key = if let Some(wrapped) = meta.encryption.wrapped_key_base64.as_deref() {
        if !wrapped.is_empty() {
            unwrap_object_data_key(state, resource, meta, wrapped, customer_key)
                .await?
                .to_vec()
        } else {
            derive_object_encryption_key(state, meta).to_vec()
        }
    } else {
        derive_object_encryption_key(state, meta).to_vec()
    };
    let cipher = Aes256Gcm::new_from_slice(&data_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize shard encryption cipher: {err}"),
            resource,
        )
    })?;
    cipher
        .encrypt(Nonce::from_slice(&nonce), shard_data)
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to encrypt shard payload",
                resource,
            )
        })
}

/// 单个 EC 分片解密。
#[allow(dead_code)]
pub(crate) async fn decrypt_shard(
    state: &AppState,
    resource: &str,
    shard_data: Vec<u8>,
    meta: &S3ObjectMeta,
    shard_index: usize,
    customer_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, Response> {
    let nonce = derive_shard_nonce(meta, shard_index)?;
    let data_key = if let Some(wrapped) = meta.encryption.wrapped_key_base64.as_deref() {
        if !wrapped.is_empty() {
            unwrap_object_data_key(state, resource, meta, wrapped, customer_key)
                .await?
                .to_vec()
        } else {
            derive_object_encryption_key(state, meta).to_vec()
        }
    } else {
        derive_object_encryption_key(state, meta).to_vec()
    };
    let cipher = Aes256Gcm::new_from_slice(&data_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to initialize shard decryption cipher: {err}"),
            resource,
        )
    })?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), shard_data.as_ref())
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to decrypt shard payload",
                resource,
            )
        })
}

/// base_nonce XOR (shard_index_be_bytes)，保证每个分片 nonce 唯一。
#[allow(dead_code)]
fn derive_shard_nonce(meta: &S3ObjectMeta, shard_index: usize) -> Result<[u8; 12], Response> {    let nonce_b64 = meta.encryption.nonce_base64.as_deref().ok_or_else(|| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Missing object encryption nonce metadata",
            &meta.key,
        )
    })?;
    let base = BASE64.decode(nonce_b64).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to decode encryption nonce: {err}"),
            &meta.key,
        )
    })?;
    if base.len() != 12 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "Encryption nonce length is invalid",
            &meta.key,
        ));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&base);
    let idx_bytes = (shard_index as u32).to_be_bytes();
    nonce[8] ^= idx_bytes[0];
    nonce[9] ^= idx_bytes[1];
    nonce[10] ^= idx_bytes[2];
    nonce[11] ^= idx_bytes[3];
    Ok(nonce)
}

/// SSE-C 客户密钥本地包装 DEK (AES-256-GCM)。
/// 格式: 12-byte nonce || ciphertext
fn wrap_object_data_key_with_customer_key(
    resource: &str,
    data_key: &[u8; 32],
    customer_key: &[u8; 32],
) -> Result<String, Response> {
    let wrap_nonce = random_12_bytes();
    let cipher = Aes256Gcm::new_from_slice(customer_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "初始化 SSE-C 密钥包装加密器失败 / failed to init SSE-C key wrap cipher: {err}"
            ),
            resource,
        )
    })?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&wrap_nonce), data_key.as_slice())
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "SSE-C 客户密钥包装 DEK 失败 / failed to wrap data key with SSE-C key",
                resource,
            )
        })?;
    let mut wrapped = Vec::with_capacity(12 + ciphertext.len());
    wrapped.extend_from_slice(&wrap_nonce);
    wrapped.extend_from_slice(&ciphertext);
    Ok(format!("{SSEC_WRAP_PREFIX}{}", BASE64.encode(&wrapped)))
}

/// SSE-C 客户密钥本地解包装 DEK。
fn unwrap_object_data_key_with_customer_key(
    resource: &str,
    payload: &str,
    customer_key: &[u8; 32],
) -> Result<[u8; 32], Response> {
    let raw = BASE64.decode(payload).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("SSE-C 包装密钥 Base64 解码失败 / failed to decode SSE-C wrapped key: {err}"),
            resource,
        )
    })?;
    if raw.len() < 13 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "SSE-C 包装密钥数据长度不足 / SSE-C wrapped key length invalid",
            resource,
        ));
    }
    let wrap_nonce = &raw[..12];
    let ciphertext = &raw[12..];
    let cipher = Aes256Gcm::new_from_slice(customer_key).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "初始化 SSE-C 密钥解包装加密器失败 / failed to init SSE-C key unwrap cipher: {err}"
            ),
            resource,
        )
    })?;
    let dek = cipher
        .decrypt(Nonce::from_slice(wrap_nonce), ciphertext)
        .map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "SSE-C 客户密钥解包装 DEK 失败，客户密钥可能不正确 / failed to unwrap data key with SSE-C key — wrong customer key?",
                resource,
            )
        })?;
    if dek.len() != 32 {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "SSE-C 解包装后 DEK 长度不正确 / unwrapped SSE-C data key length invalid",
            resource,
        ));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&dek);
    Ok(output)
}
