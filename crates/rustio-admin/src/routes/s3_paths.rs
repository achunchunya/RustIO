//! S3 存储路径解析与远端分层 helper

use super::*;

pub(crate) fn bucket_path(state: &AppState, bucket: &str) -> Result<PathBuf, Response> {
    if !valid_bucket_name(bucket) {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            "The specified bucket is not valid.",
            bucket,
        ));
    }

    if let Some(path) = failover_bucket_path(state, bucket) {
        let _ = std::fs::create_dir_all(&path);
        return Ok(path);
    }
    Ok(state.data_dir.join(bucket))
}

pub(crate) fn failover_bucket_path(state: &AppState, bucket: &str) -> Option<PathBuf> {
    let sites = state.site_replications.try_read().ok()?;
    let active_site = sites
        .iter()
        .find(|site| site.role == "primary" && !site.preferred_primary)?
        .site_id
        .clone();
    drop(sites);

    let rules = state.replications.try_read().ok()?;
    let managed = rules.iter().any(|rule| {
        rule.source_bucket == bucket && rule.target_site == active_site && rule.status != "paused"
    });
    drop(rules);
    if !managed {
        return None;
    }

    Some(
        state
            .data_dir
            .join(".rustio_sites")
            .join(active_site)
            .join("data")
            .join(bucket),
    )
}

pub(crate) fn bucket_policy_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root.join(".rustio_meta").join("bucket-policy.json")
}

pub(crate) fn bucket_lifecycle_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root
        .join(".rustio_meta")
        .join("bucket-lifecycle.json")
}

pub(crate) fn bucket_notifications_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root
        .join(".rustio_meta")
        .join("bucket-notifications.json")
}

pub(crate) fn bucket_acl_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root.join(".rustio_meta").join("bucket-acl.json")
}

pub(crate) fn bucket_public_access_block_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root
        .join(".rustio_meta")
        .join("bucket-public-access-block.json")
}

pub(crate) fn bucket_cors_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root.join(".rustio_meta").join("bucket-cors.json")
}

pub(crate) fn bucket_tags_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root.join(".rustio_meta").join("bucket-tags.json")
}

pub(crate) fn bucket_encryption_path(bucket_root: &FsPath) -> PathBuf {
    bucket_root
        .join(".rustio_meta")
        .join("bucket-encryption.json")
}

pub(crate) fn object_path(bucket_root: &FsPath, key: &str) -> Result<PathBuf, Response> {
    if key.is_empty() {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidObjectName",
            "Object key cannot be empty",
            key,
        ));
    }

    let key_path = FsPath::new(key);
    for component in key_path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidObjectName",
                    "Invalid object key path",
                    key,
                ));
            }
        }
    }
    Ok(bucket_root.join(key_path))
}

pub(crate) fn is_reserved_internal_key(key: &str) -> bool {
    key == ".rustio_meta"
        || key.starts_with(".rustio_meta/")
        || key == ".rustio_versions"
        || key.starts_with(".rustio_versions/")
}

pub(crate) fn valid_version_id(version_id: &str) -> bool {
    !version_id.is_empty()
        && version_id.len() <= 128
        && version_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

pub(crate) fn object_versions_dir(bucket_root: &FsPath, key: &str) -> PathBuf {
    bucket_root
        .join(".rustio_versions")
        .join(sha256_hex(key.as_bytes()))
}

pub(crate) fn object_version_meta_path(
    bucket_root: &FsPath,
    key: &str,
    version_id: &str,
) -> Result<PathBuf, Response> {
    if !valid_version_id(version_id) {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidVersionId",
            "The specified version id is not valid",
            key,
        ));
    }
    Ok(object_versions_dir(bucket_root, key).join(format!("{version_id}.json")))
}

pub(crate) fn object_version_payload_path(
    bucket_root: &FsPath,
    key: &str,
    version_id: &str,
) -> Result<PathBuf, Response> {
    if !valid_version_id(version_id) {
        return Err(s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidVersionId",
            "The specified version id is not valid",
            key,
        ));
    }
    Ok(object_versions_dir(bucket_root, key).join(format!("{version_id}.bin")))
}

pub(crate) fn remote_tier_root_path(config: &RemoteTierConfig) -> Result<PathBuf, String> {
    if !matches!(
        remote_tier_backend_kind(config)?,
        RemoteTierBackendKind::Filesystem
    ) {
        return Err(
            "仅 filesystem backend 支持本地路径 / only filesystem backend supports local paths"
                .to_string(),
        );
    }
    let endpoint = config.endpoint.trim();
    let path = endpoint
        .strip_prefix("file://")
        .unwrap_or(endpoint)
        .trim()
        .to_string();
    if path.is_empty() {
        return Err("远端层端点不能为空 / remote tier endpoint cannot be empty".to_string());
    }
    Ok(PathBuf::from(path))
}

pub(crate) fn remote_tier_object_name(
    config: &RemoteTierConfig,
    key: &str,
    version_id: &str,
    extension: &str,
) -> Result<String, String> {
    if !valid_version_id(version_id) {
        return Err("版本号无效 / invalid version id".to_string());
    }
    let mut parts = Vec::new();
    if let Some(prefix) = config.prefix.as_deref() {
        parts.extend(
            prefix
                .trim_matches('/')
                .split('/')
                .filter(|part| !part.trim().is_empty())
                .map(|part| part.trim().to_string()),
        );
    }
    parts.push(sha256_hex(key.as_bytes()));
    parts.push(format!("{version_id}.{extension}"));
    Ok(parts.join("/"))
}

pub(crate) fn remote_tier_object_dir(
    config: &RemoteTierConfig,
    bucket: &str,
    key: &str,
) -> Result<PathBuf, String> {
    let mut root = remote_tier_root_path(config)?;
    root.push(bucket);
    if let Some(prefix) = config.prefix.as_deref() {
        if !prefix.trim().is_empty() {
            root.push(prefix.trim());
        }
    }
    root.push(sha256_hex(key.as_bytes()));
    Ok(root)
}

pub(crate) fn remote_tier_object_meta_path(
    config: &RemoteTierConfig,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<PathBuf, String> {
    if !valid_version_id(version_id) {
        return Err("版本号无效 / invalid version id".to_string());
    }
    Ok(remote_tier_object_dir(config, bucket, key)?.join(format!("{version_id}.json")))
}

pub(crate) fn remote_tier_object_payload_path(
    config: &RemoteTierConfig,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<PathBuf, String> {
    if !valid_version_id(version_id) {
        return Err("版本号无效 / invalid version id".to_string());
    }
    Ok(remote_tier_object_dir(config, bucket, key)?.join(format!("{version_id}.bin")))
}

pub(crate) fn remote_tier_http_object_url(
    config: &RemoteTierConfig,
    bucket: &str,
    key: &str,
    version_id: &str,
    extension: &str,
) -> Result<String, String> {
    let base = config.endpoint.trim().trim_end_matches('/');
    let bucket_component = url_encode_component(bucket);
    let object_name = remote_tier_object_name(config, key, version_id, extension)?;
    match remote_tier_backend_kind(config)? {
        RemoteTierBackendKind::Gcs => Ok(format!(
            "{base}/storage/v1/b/{bucket_component}/o/{}?alt=media",
            url_encode_component(&object_name)
        )),
        RemoteTierBackendKind::Filesystem => Err(
            "filesystem backend 不支持 HTTP URL / filesystem backend does not support http urls"
                .to_string(),
        ),
        RemoteTierBackendKind::S3Compatible
        | RemoteTierBackendKind::Minio
        | RemoteTierBackendKind::AzureBlob => {
            let encoded = object_name
                .split('/')
                .map(url_encode_component)
                .collect::<Vec<_>>()
                .join("/");
            Ok(format!("{base}/{bucket_component}/{encoded}"))
        }
    }
}

pub(crate) fn remote_tier_http_upload_url(
    config: &RemoteTierConfig,
    bucket: &str,
    key: &str,
    version_id: &str,
    extension: &str,
) -> Result<String, String> {
    let base = config.endpoint.trim().trim_end_matches('/');
    let bucket_component = url_encode_component(bucket);
    let object_name = remote_tier_object_name(config, key, version_id, extension)?;
    match remote_tier_backend_kind(config)? {
        RemoteTierBackendKind::Gcs => Ok(format!(
            "{base}/upload/storage/v1/b/{bucket_component}/o?uploadType=media&name={}",
            url_encode_component(&object_name)
        )),
        _ => remote_tier_http_object_url(config, bucket, key, version_id, extension),
    }
}

pub(crate) fn remote_tier_http_client() -> Result<Client, String> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| {
            format!("创建远端层客户端失败 / failed to initialize remote tier client: {err}")
        })
}

pub(crate) fn remote_tier_http_request_builder(
    client: &Client,
    config: &RemoteTierConfig,
    method: reqwest::Method,
    url: String,
) -> reqwest::RequestBuilder {
    let mut request = client.request(method.clone(), url);
    if let Some(token) = config.credential_token.as_deref() {
        request = request.bearer_auth(token);
    }
    if let (Some(username), Some(password)) = (
        config.credential_key.as_deref(),
        config.credential_secret.as_deref(),
    ) {
        request = request.basic_auth(username, Some(password));
    }
    for (key, value) in &config.extra_headers {
        request = request.header(key, value);
    }
    if matches!(
        remote_tier_backend_kind(config),
        Ok(RemoteTierBackendKind::AzureBlob)
    ) {
        request = request.header("x-ms-version", "2023-11-03");
        if method == reqwest::Method::PUT {
            request = request.header("x-ms-blob-type", "BlockBlob");
        }
    }
    request
}

pub(crate) async fn update_remote_tier_runtime<F>(state: &AppState, tier_name: &str, mutate: F)
where
    F: FnOnce(&mut RemoteTierConfig),
{
    let snapshot = {
        let mut tiers = state.remote_tiers.write().await;
        let Some(tier) = tiers.get_mut(&normalize_remote_tier_name(tier_name)) else {
            return;
        };
        mutate(tier);
        tiers.clone()
    };
    let _ = AppState::persist_remote_tiers_snapshot(&state.data_dir, &snapshot);
}

pub(crate) async fn mark_remote_tier_health_failure(
    state: &AppState,
    tier_name: &str,
    message: impl Into<String>,
) {
    let now = Utc::now();
    let message = message.into();
    update_remote_tier_runtime(state, tier_name, move |tier| {
        tier.health_status = if tier.enabled {
            "degraded".to_string()
        } else {
            "paused".to_string()
        };
        tier.last_checked_at = Some(now);
        tier.last_error = Some(message.clone());
    })
    .await;
}

pub(crate) async fn mark_remote_tier_health_success(state: &AppState, tier_name: &str) {
    let now = Utc::now();
    update_remote_tier_runtime(state, tier_name, move |tier| {
        tier.health_status = if tier.enabled {
            "healthy".to_string()
        } else {
            "paused".to_string()
        };
        tier.last_checked_at = Some(now);
        tier.last_success_at = Some(now);
        tier.last_error = None;
    })
    .await;
}

pub(crate) async fn probe_remote_tier_connectivity(
    mut config: RemoteTierConfig,
) -> RemoteTierConfig {
    let now = Utc::now();
    config.last_checked_at = Some(now);
    if !config.enabled {
        config.health_status = "paused".to_string();
        config.last_error = None;
        return config;
    }

    let result = match remote_tier_backend_kind(&config) {
        Ok(RemoteTierBackendKind::Filesystem) => match remote_tier_root_path(&config) {
            Ok(path) => tokio::fs::create_dir_all(path).await.map_err(|err| {
                format!("创建远端层目录失败 / failed to create remote tier directory: {err}")
            }),
            Err(err) => Err(err),
        },
        Ok(_) => match remote_tier_http_client() {
            Ok(client) => {
                let response = remote_tier_http_request_builder(
                    &client,
                    &config,
                    reqwest::Method::GET,
                    config.endpoint.trim().to_string(),
                )
                .send()
                .await;
                match response {
                    Ok(response) if !response.status().is_server_error() => Ok(()),
                    Ok(response) => Err(format!(
                        "远端层健康检查返回非可用状态：{} / remote tier health probe returned unavailable status: {}",
                        response.status(),
                        response.status()
                    )),
                    Err(err) => Err(format!(
                        "远端层健康检查失败 / remote tier health probe failed: {err}"
                    )),
                }
            }
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    };

    match result {
        Ok(()) => {
            config.health_status = "healthy".to_string();
            config.last_success_at = Some(now);
            config.last_error = None;
        }
        Err(err) => {
            config.health_status = "degraded".to_string();
            config.last_error = Some(err);
        }
    }
    config
}

pub(crate) async fn lookup_remote_tier_config(
    state: &AppState,
    tier_name: &str,
) -> Result<RemoteTierConfig, String> {
    let normalized_name = normalize_remote_tier_name(tier_name);
    let tiers = state.remote_tiers.read().await;
    let Some(config) = tiers.get(&normalized_name).cloned() else {
        return Err(format!(
            "远端层不存在：{normalized_name} / remote tier not found: {normalized_name}"
        ));
    };
    if !config.enabled {
        return Err(format!(
            "远端层未启用：{normalized_name} / remote tier is disabled: {normalized_name}"
        ));
    }
    Ok(config)
}

pub(crate) async fn read_remote_tier_payload_for_meta(
    state: &AppState,
    meta: &S3ObjectMeta,
) -> Result<Option<Vec<u8>>, Response> {
    let Some(remote_tier) = meta.remote_tier.as_ref() else {
        return Ok(None);
    };
    let config = match lookup_remote_tier_config(state, &remote_tier.tier).await {
        Ok(config) => config,
        Err(_) => return Ok(None),
    };
    let bytes = match remote_tier_backend_kind(&config) {
        Ok(RemoteTierBackendKind::Filesystem) => {
            let payload_path =
                remote_tier_object_payload_path(&config, &meta.bucket, &meta.key, &meta.version_id)
                    .map_err(|err| {
                        s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &err,
                            &meta.key,
                        )
                    })?;
            match tokio::fs::read(&payload_path).await {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(err) => {
                    mark_remote_tier_health_failure(
                        state,
                        &config.name,
                        format!("读取远端层对象失败 / failed to read remote tier object: {err}"),
                    )
                    .await;
                    return Err(s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to read remote tier payload: {err}"),
                        &meta.key,
                    ));
                }
            }
        }
        Ok(_) => {
            let url = remote_tier_http_object_url(
                &config,
                &meta.bucket,
                &meta.key,
                &meta.version_id,
                "bin",
            )
            .map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &err,
                    &meta.key,
                )
            })?;
            let client = remote_tier_http_client().map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &err,
                    &meta.key,
                )
            })?;
            let response =
                remote_tier_http_request_builder(&client, &config, reqwest::Method::GET, url)
                    .send()
                    .await
                    .map_err(|err| {
                        s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &format!("Failed to read remote tier payload: {err}"),
                            &meta.key,
                        )
                    })?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                mark_remote_tier_health_failure(
                    state,
                    &config.name,
                    format!(
                        "远端层读取返回异常状态：{} / remote tier read returned unexpected status: {}",
                        response.status(),
                        response.status()
                    ),
                )
                .await;
                return Err(s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to read remote tier payload: {}", response.status()),
                    &meta.key,
                ));
            }
            response
                .bytes()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to decode remote tier payload: {err}"),
                        &meta.key,
                    )
                })?
                .to_vec()
        }
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &err,
                &meta.key,
            ))
        }
    };
    mark_remote_tier_health_success(state, &config.name).await;
    Ok(Some(bytes))
}

pub(crate) async fn persist_remote_tier_object(
    state: &AppState,
    config: &RemoteTierConfig,
    meta: &S3ObjectMeta,
    payload: &[u8],
) -> Result<(), String> {
    let meta_bytes = serde_json::to_vec_pretty(meta).map_err(|err| {
        format!("编码远端层元数据失败 / failed to encode remote tier metadata: {err}")
    })?;
    let result: Result<(), String> = match remote_tier_backend_kind(config)? {
        RemoteTierBackendKind::Filesystem => {
            let payload_path =
                remote_tier_object_payload_path(config, &meta.bucket, &meta.key, &meta.version_id)?;
            let meta_path =
                remote_tier_object_meta_path(config, &meta.bucket, &meta.key, &meta.version_id)?;
            if let Some(parent) = payload_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|err| {
                    format!("创建远端层目录失败 / failed to create remote tier directory: {err}")
                })?;
            }
            tokio::fs::write(&payload_path, payload)
                .await
                .map_err(|err| {
                    format!("写入远端层对象失败 / failed to persist remote tier object: {err}")
                })?;
            tokio::fs::write(&meta_path, meta_bytes)
                .await
                .map_err(|err| {
                    format!("写入远端层元数据失败 / failed to persist remote tier metadata: {err}")
                })?;
            Ok(())
        }
        RemoteTierBackendKind::S3Compatible
        | RemoteTierBackendKind::Minio
        | RemoteTierBackendKind::AzureBlob
        | RemoteTierBackendKind::Gcs => {
            let client = remote_tier_http_client()?;
            let payload_url = remote_tier_http_upload_url(
                config,
                &meta.bucket,
                &meta.key,
                &meta.version_id,
                "bin",
            )?;
            let meta_url = remote_tier_http_upload_url(
                config,
                &meta.bucket,
                &meta.key,
                &meta.version_id,
                "json",
            )?;
            let payload_method = if matches!(
                remote_tier_backend_kind(config),
                Ok(RemoteTierBackendKind::Gcs)
            ) {
                reqwest::Method::POST
            } else {
                reqwest::Method::PUT
            };
            let payload_response = remote_tier_http_request_builder(
                &client,
                config,
                payload_method.clone(),
                payload_url,
            )
            .header(CONTENT_TYPE.as_str(), "application/octet-stream")
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|err| {
                format!("写入远端层对象失败 / failed to persist remote tier object: {err}")
            })?;
            if !payload_response.status().is_success() {
                return Err(format!(
                    "写入远端层对象返回非成功状态：{} / failed to persist remote tier object with status {}",
                    payload_response.status(),
                    payload_response.status()
                ));
            }
            let meta_response =
                remote_tier_http_request_builder(&client, config, payload_method, meta_url)
                    .header(CONTENT_TYPE.as_str(), "application/json")
                    .body(meta_bytes)
                    .send()
                    .await
                    .map_err(|err| {
                        format!(
                            "写入远端层元数据失败 / failed to persist remote tier metadata: {err}"
                        )
                    })?;
            if !meta_response.status().is_success() {
                return Err(format!(
                    "写入远端层元数据返回非成功状态：{} / failed to persist remote tier metadata with status {}",
                    meta_response.status(),
                    meta_response.status()
                ));
            }
            Ok(())
        }
    };
    match result {
        Ok(()) => {
            mark_remote_tier_health_success(state, &config.name).await;
            Ok(())
        }
        Err(err) => {
            mark_remote_tier_health_failure(state, &config.name, err.clone()).await;
            Err(err)
        }
    }
}

pub(crate) async fn remove_remote_tier_payload_for_meta(
    state: &AppState,
    meta: &S3ObjectMeta,
) -> Result<(), Response> {
    let Some(remote_tier) = meta.remote_tier.as_ref() else {
        return Ok(());
    };
    let config = match lookup_remote_tier_config(state, &remote_tier.tier).await {
        Ok(config) => config,
        Err(_) => return Ok(()),
    };
    let result = match remote_tier_backend_kind(&config) {
        Ok(RemoteTierBackendKind::Filesystem) => {
            let meta_path =
                remote_tier_object_meta_path(&config, &meta.bucket, &meta.key, &meta.version_id)
                    .map_err(|err| {
                        s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &err,
                            &meta.key,
                        )
                    })?;
            let payload_path =
                remote_tier_object_payload_path(&config, &meta.bucket, &meta.key, &meta.version_id)
                    .map_err(|err| {
                        s3_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            &err,
                            &meta.key,
                        )
                    })?;
            match tokio::fs::remove_file(&meta_path).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to remove remote tier metadata: {err}"),
                        &meta.key,
                    ))
                }
            }
            match tokio::fs::remove_file(&payload_path).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to remove remote tier payload: {err}"),
                        &meta.key,
                    ))
                }
            }
            if let Some(parent) = payload_path.parent() {
                let mut root = match remote_tier_root_path(&config) {
                    Ok(path) => path.join(&meta.bucket),
                    Err(_) => return Ok(()),
                };
                if let Some(prefix) = config.prefix.as_deref() {
                    if !prefix.trim().is_empty() {
                        root = root.join(prefix.trim());
                    }
                }
                let _ = remove_empty_dirs_until(parent, &root);
            }
            Ok(())
        }
        Ok(_) => {
            let client = remote_tier_http_client().map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &err,
                    &meta.key,
                )
            })?;
            for extension in ["json", "bin"] {
                let url = remote_tier_http_object_url(
                    &config,
                    &meta.bucket,
                    &meta.key,
                    &meta.version_id,
                    extension,
                )
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &err,
                        &meta.key,
                    )
                })?;
                let response = remote_tier_http_request_builder(
                    &client,
                    &config,
                    reqwest::Method::DELETE,
                    url,
                )
                .send()
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to remove remote tier payload: {err}"),
                        &meta.key,
                    )
                })?;
                if response.status() != reqwest::StatusCode::NOT_FOUND
                    && !response.status().is_success()
                {
                    return Err(s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!(
                            "Failed to remove remote tier payload: {}",
                            response.status()
                        ),
                        &meta.key,
                    ));
                }
            }
            Ok(())
        }
        Err(err) => Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &err,
            &meta.key,
        )),
    };
    match result {
        Ok(()) => {
            mark_remote_tier_health_success(state, &config.name).await;
            Ok(())
        }
        Err(err) => {
            mark_remote_tier_health_failure(
                state,
                &config.name,
                "删除远端层对象失败 / failed to remove remote tier object".to_string(),
            )
            .await;
            Err(err)
        }
    }
}

pub(crate) async fn read_current_object_payload(
    state: &AppState,
    bucket: &str,
    key: &str,
    meta: Option<&S3ObjectMeta>,
    customer_key: Option<&[u8; 32]>,
) -> Result<Option<Vec<u8>>, Response> {
    if let Some(meta) = meta {
        if object_restore_is_active(meta) {
            if let Some(bytes) = read_current_hot_object_payload(state, bucket, key).await? {
                return Ok(Some(bytes));
            }
        }
        if let Some(bytes) = read_remote_tier_payload_for_meta(state, meta).await? {
            return Ok(Some(bytes));
        }
    }
    match read_ec_object(state, bucket, key, meta, customer_key).await? {
        Some(bytes) => Ok(Some(bytes)),
        None => {
            let bucket_root = bucket_path(state, bucket)?;
            let target_path = object_path(&bucket_root, key)?;
            let bytes = match tokio::fs::read(&target_path).await {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(err) => {
                    return Err(s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to read object: {err}"),
                        key,
                    ))
                }
            };
            Ok(Some(bytes))
        }
    }
}

pub(crate) async fn read_current_hot_object_payload(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Option<Vec<u8>>, Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let target_path = object_path(&bucket_root, key)?;
    let bytes = match tokio::fs::read(&target_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read object: {err}"),
                key,
            ))
        }
    };
    Ok(Some(bytes))
}

pub(crate) async fn persist_restored_current_object_payload(
    state: &AppState,
    meta: &S3ObjectMeta,
    payload: &[u8],
) -> Result<(), Response> {
    let bucket_root = bucket_path(state, &meta.bucket)?;
    let target_path = object_path(&bucket_root, &meta.key)?;
    if let Some(parent) = target_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create restore directory: {err}"),
                &meta.key,
            )
        })?;
    }
    tokio::fs::write(&target_path, payload)
        .await
        .map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to restore object payload: {err}"),
                &meta.key,
            )
        })?;
    Ok(())
}

pub(crate) async fn remove_current_hot_object_payload(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<(), Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let target_path = object_path(&bucket_root, key)?;
    match tokio::fs::remove_file(&target_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to remove current object payload: {err}"),
                key,
            ))
        }
    }
    remove_ec_object(state, bucket, key).await?;
    if let Some(parent) = target_path.parent() {
        let _ = remove_empty_dirs_until(parent, &bucket_root);
    }
    Ok(())
}
