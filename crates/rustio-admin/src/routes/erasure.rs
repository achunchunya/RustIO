//! 纠删码（EC）对象读写

use super::*;

pub(crate) async fn write_ec_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    payload: &[u8],
    meta: &mut S3ObjectMeta,
) -> Result<(), Response> {
    let payload = encrypt_payload_for_storage(state, key, payload, meta).await?;
    let (data_shards, parity_shards) = ec_layout();
    let total_shards = data_shards + parity_shards;
    if state.data_disks.len() < total_shards {
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "erasure disk count is not enough",
            key,
        ));
    }
    let placement =
        preferred_storage_disk_indices_for_key(state, key, total_shards, &HashSet::new())
            .await
            .map_err(|message| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &message,
                    key,
                )
            })?;

    let bucket_root = bucket_path(state, bucket)?;
    let shard_size = payload.len().div_ceil(data_shards).max(1);
    let mut shards = vec![vec![0u8; shard_size]; total_shards];
    for (index, byte) in payload.iter().enumerate() {
        let shard_index = index / shard_size;
        let offset = index % shard_size;
        if shard_index < data_shards {
            shards[shard_index][offset] = *byte;
        }
    }
    let reed_solomon = ReedSolomon::new(data_shards, parity_shards).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to create Reed-Solomon encoder: {err}"),
            key,
        )
    })?;
    reed_solomon.encode(&mut shards).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to encode Reed-Solomon shards: {err}"),
            key,
        )
    })?;

    let object_hash = sha256_hex(key.as_bytes());
    let mut shard_infos = Vec::with_capacity(total_shards);
    let mut successful_shards = 0usize;
    for shard_index in 0..total_shards {
        let disk_index = placement[shard_index];
        let shard_path = state.data_disks[disk_index]
            .join(bucket)
            .join(".rustio_ec")
            .join(&object_hash)
            .join(format!("{shard_index}.bin"));
        let mut checksum = String::new();
        let mut write_failed = false;
        if let Some(parent) = shard_path.parent() {
            if tokio::fs::create_dir_all(parent).await.is_err() {
                write_failed = true;
            }
        } else {
            write_failed = true;
        }
        if !write_failed
            && tokio::fs::write(&shard_path, &shards[shard_index])
                .await
                .is_ok()
        {
            checksum = sha256_hex(&shards[shard_index]);
            successful_shards += 1;
        }
        shard_infos.push(EcShardInfo {
            shard_index,
            disk_index,
            path: shard_path,
            checksum,
        });
    }
    if successful_shards < data_shards {
        let cleanup_failed = cleanup_ec_written_shards(&shard_infos).await;
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "纠删码写入未达到法定票数（{successful_shards}/{data_shards}），已回滚已写分片，清理失败 {cleanup_failed} 个 / erasure write quorum not reached ({successful_shards}/{data_shards}); written shards rolled back, cleanup failed for {cleanup_failed} shard(s)"
            ),
            key,
        ));
    }

    let manifest = EcObjectManifest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        total_size: payload.len() as u64,
        shard_size,
        data_shards,
        parity_shards,
        shards: shard_infos.clone(),
        updated_at: Utc::now(),
    };
    let manifest_path = ec_manifest_path(&bucket_root, key);
    if let Some(parent) = manifest_path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            let cleanup_failed = cleanup_ec_written_shards(&shard_infos).await;
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!(
                    "创建纠删码清单目录失败，已回滚已写分片：{err}，清理失败 {cleanup_failed} 个 / failed to create erasure manifest directory; written shards rolled back: {err}; cleanup failed for {cleanup_failed} shard(s)"
                ),
                key,
            ));
        }
    }
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|err| {
        s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("Failed to encode erasure manifest: {err}"),
            key,
        )
    })?;
    if let Err(err) = tokio::fs::write(&manifest_path, bytes).await {
        let cleanup_failed = cleanup_ec_written_shards(&shard_infos).await;
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "写入纠删码清单失败，已回滚已写分片：{err}，清理失败 {cleanup_failed} 个 / failed to persist erasure manifest; written shards rolled back: {err}; cleanup failed for {cleanup_failed} shard(s)"
            ),
            key,
        ));
    }
    Ok(())
}

pub(crate) async fn read_ec_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    meta: Option<&S3ObjectMeta>,
) -> Result<Option<Vec<u8>>, Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let manifest_path = ec_manifest_path(&bucket_root, key);
    let manifest_bytes = match tokio::fs::read(&manifest_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read erasure manifest: {err}"),
                key,
            ));
        }
    };
    let mut manifest = match serde_json::from_slice::<EcObjectManifest>(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            let _ = upsert_storage_job(
                state,
                StorageJobDraft {
                    kind: "scrub".to_string(),
                    target: format!("{bucket}/{key}"),
                    bucket: Some(bucket.to_string()),
                    key: Some(key.to_string()),
                    version_id: meta.map(|item| item.version_id.clone()),
                    priority: Some(900),
                    affected_disks: vec![],
                    missing_shards: 0,
                    corrupted_shards: 0,
                    source: "read_failure".to_string(),
                    details: json!({
                        "bucket": bucket,
                        "key": key,
                        "error": err.to_string(),
                    }),
                },
                "pending",
            )
            .await;
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to decode erasure manifest: {err}"),
                key,
            ));
        }
    };
    if manifest.data_shards == 0 {
        return Ok(None);
    }

    let total_shards = manifest.data_shards + manifest.parity_shards;
    if manifest.shards.len() < total_shards {
        let existing = manifest
            .shards
            .iter()
            .map(|shard| shard.shard_index)
            .collect::<HashSet<_>>();
        let object_hash = sha256_hex(key.as_bytes());
        for shard_index in 0..total_shards {
            if existing.contains(&shard_index) {
                continue;
            }
            let disk_index = manifest_disk_index_for_shard(&manifest, shard_index)
                .unwrap_or(shard_index % state.data_disks.len().max(1));
            let shard_path = state.data_disks[disk_index]
                .join(bucket)
                .join(".rustio_ec")
                .join(&object_hash)
                .join(format!("{shard_index}.bin"));
            manifest.shards.push(EcShardInfo {
                shard_index,
                disk_index,
                path: shard_path,
                checksum: String::new(),
            });
        }
    }
    let reed_solomon =
        ReedSolomon::new(manifest.data_shards, manifest.parity_shards).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to create Reed-Solomon decoder: {err}"),
                key,
            )
        })?;
    let mut loaded = vec![None::<Vec<u8>>; total_shards];
    let mut failed = HashSet::new();
    for shard in &manifest.shards {
        if shard.shard_index >= total_shards {
            continue;
        }
        let bytes = match tokio::fs::read(&shard.path).await {
            Ok(bytes) => bytes,
            Err(_) => {
                failed.insert(shard.shard_index);
                continue;
            }
        };
        if bytes.len() != manifest.shard_size || sha256_hex(&bytes) != shard.checksum {
            failed.insert(shard.shard_index);
            continue;
        }
        loaded[shard.shard_index] = Some(bytes);
    }
    let existing = manifest
        .shards
        .iter()
        .map(|shard| shard.shard_index)
        .collect::<HashSet<_>>();
    #[allow(clippy::needless_range_loop)]
    for shard_index in 0..total_shards {
        if !existing.contains(&shard_index) || loaded[shard_index].is_none() {
            failed.insert(shard_index);
        }
    }

    let available_shards = loaded.iter().filter(|item| item.is_some()).count();
    if available_shards < manifest.data_shards {
        let affected_disks = failed
            .iter()
            .map(|shard_index| {
                manifest_disk_id_for_shard(&manifest, *shard_index, state.data_disks.len())
            })
            .collect::<Vec<_>>();
        let _ = upsert_storage_job(
            state,
            StorageJobDraft {
                kind: "rebuild".to_string(),
                target: format!("{bucket}/{key}"),
                bucket: Some(bucket.to_string()),
                key: Some(key.to_string()),
                version_id: meta.map(|item| item.version_id.clone()),
                priority: Some(1200),
                affected_disks,
                missing_shards: failed.len(),
                corrupted_shards: 0,
                source: "read_failure".to_string(),
                details: json!({
                    "bucket": bucket,
                    "key": key,
                    "available_shards": available_shards,
                    "required_shards": manifest.data_shards,
                }),
            },
            "pending",
        )
        .await;
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!(
                "纠删码读取未达到法定票数：可用分片 {available_shards}/{total_shards}，至少需要 {} / erasure read quorum not reached: {available_shards}/{total_shards} shards available, need at least {}",
                manifest.data_shards,
                manifest.data_shards
            ),
            key,
        ));
    }
    if failed.len() > manifest.parity_shards {
        let affected_disks = failed
            .iter()
            .map(|shard_index| {
                manifest_disk_id_for_shard(&manifest, *shard_index, state.data_disks.len())
            })
            .collect::<Vec<_>>();
        let _ = upsert_storage_job(
            state,
            StorageJobDraft {
                kind: "rebuild".to_string(),
                target: format!("{bucket}/{key}"),
                bucket: Some(bucket.to_string()),
                key: Some(key.to_string()),
                version_id: meta.map(|item| item.version_id.clone()),
                priority: Some(1300),
                affected_disks,
                missing_shards: failed.len(),
                corrupted_shards: failed.len(),
                source: "read_failure".to_string(),
                details: json!({
                    "bucket": bucket,
                    "key": key,
                    "failed_shards": failed.len(),
                    "parity_shards": manifest.parity_shards,
                }),
            },
            "pending",
        )
        .await;
        return Err(s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "纠删码分片损坏超出奇偶校验恢复能力 / erasure shards corrupted beyond parity recovery",
            key,
        ));
    }
    if !failed.is_empty() {
        reed_solomon.reconstruct(&mut loaded).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to reconstruct Reed-Solomon shards: {err}"),
                key,
            )
        })?;
        for shard_info in manifest.shards.iter_mut() {
            if !failed.contains(&shard_info.shard_index) {
                continue;
            }
            let Some(recovered) = loaded
                .get(shard_info.shard_index)
                .and_then(|item| item.as_ref())
            else {
                continue;
            };
            if let Some(parent) = shard_info.path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to create shard directory during recovery: {err}"),
                        key,
                    )
                })?;
            }
            tokio::fs::write(&shard_info.path, recovered)
                .await
                .map_err(|err| {
                    s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("Failed to persist recovered shard: {err}"),
                        key,
                    )
                })?;
            shard_info.checksum = sha256_hex(recovered);
        }
        let updated_manifest = serde_json::to_vec_pretty(&manifest).map_err(|err| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to encode recovered manifest: {err}"),
                key,
            )
        })?;
        tokio::fs::write(&manifest_path, updated_manifest)
            .await
            .map_err(|err| {
                s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("Failed to persist recovered manifest: {err}"),
                    key,
                )
            })?;
    }

    let mut payload = Vec::with_capacity(manifest.total_size as usize);
    #[allow(clippy::needless_range_loop)]
    for shard_index in 0..manifest.data_shards {
        let Some(bytes) = loaded[shard_index].as_ref() else {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "缺少纠删码数据分片 / missing erasure data shard",
                key,
            ));
        };
        payload.extend_from_slice(bytes);
    }
    payload.truncate(manifest.total_size as usize);
    touch_object_access_heat(state, bucket, key).await;
    Ok(Some(
        decrypt_payload_from_storage(state, key, payload, meta).await?,
    ))
}

pub(crate) async fn remove_ec_object(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<(), Response> {
    let bucket_root = bucket_path(state, bucket)?;
    let manifest_path = ec_manifest_path(&bucket_root, key);
    let manifest_bytes = match tokio::fs::read(&manifest_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("Failed to read erasure manifest: {err}"),
                key,
            ));
        }
    };
    if let Ok(manifest) = serde_json::from_slice::<EcObjectManifest>(&manifest_bytes) {
        for shard in manifest.shards {
            let _ = tokio::fs::remove_file(shard.path).await;
        }
    }
    let _ = tokio::fs::remove_file(&manifest_path).await;
    Ok(())
}
