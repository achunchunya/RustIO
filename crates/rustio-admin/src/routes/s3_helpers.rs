//! S3 基础操作与通用 helper（建桶、列举、对象元数据、XML 转义、wrap）

use super::*;

pub(crate) fn valid_bucket_name(name: &str) -> bool {
    if name.len() < 3 || name.len() > 63 {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') || name.starts_with('-') || name.ends_with('-')
    {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-')
}

pub(crate) fn collect_objects(
    state: &AppState,
    bucket: &str,
    bucket_root: &FsPath,
    dir: &FsPath,
    output: &mut Vec<DiskObjectEntry>,
) -> std::io::Result<()> {
    let mut entries = HashMap::<String, DiskObjectEntry>::new();
    collect_object_payload_files(bucket_root, dir, &mut entries)?;
    collect_object_meta_entries(state, bucket, &mut entries);
    output.extend(entries.into_values());
    Ok(())
}

/// 纯 redb 索引枚举对象(LIST 主路径):直接 scan_bucket(有序范围扫,O(对象数) 顺序读),
/// **不 walk 文件系统、无 per-object stat 系统调用**——这是相对 MinIO「walk fs + 逐对象 stat」
/// 列举模型的结构性性能优势(MinIO 海量对象 LIST 的瓶颈正是逐对象 fs stat)。
/// current 对象元数据已完全下沉 redb(真相源),故索引枚举即完整。
/// 异常恢复(元数据丢失但 payload 在)可经 `RUSTIO_LIST_WALK_FS=1` 回退到 `collect_objects` walk-fs。
pub(crate) fn collect_objects_indexed(state: &AppState, bucket: &str) -> Vec<DiskObjectEntry> {
    let mut output = Vec::new();
    for meta in state.meta_store.scan_bucket(bucket).unwrap_or_default() {
        if meta.delete_marker {
            continue;
        }
        output.push(DiskObjectEntry {
            key: meta.key.clone(),
            size: meta.size,
            etag: meta.etag.clone(),
            last_modified: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            storage_class: object_storage_class(&meta).to_string(),
        });
    }
    output
}

/// LIST 是否回退到 walk-fs 模式(异常恢复 / 基准对比 MinIO 行为用)。默认 false=纯 redb 索引。
pub(crate) fn list_walk_fs_fallback_enabled() -> bool {
    std::env::var("RUSTIO_LIST_WALK_FS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// redb range 真分页枚举(LIST 无 delimiter 快路径):从 `start_after`(不含)起,
/// 按 key 有序取至多 `limit` 个、且 key 以 `prefix` 开头的对象。
/// **延迟与 bucket 总对象数解耦**(O(log n + page))——无论 bucket 有 1 万还是 1 亿对象,
/// 单页 LIST 恒定延迟。这是相对 MinIO「每次 LIST 都 walk 全 bucket」的代际优势。
/// 返回 (本页对象, 是否还有更多)。
pub(crate) fn collect_objects_page_indexed(
    state: &AppState,
    bucket: &str,
    prefix: &str,
    start_after: &str,
    limit: usize,
) -> (Vec<DiskObjectEntry>, bool) {
    // range 起点 = max(prefix, start_after)。两者 exclusive/inclusive 语义不同:
    //   - start_after(分页 continuation):exclusive,从其之后开始;
    //   - prefix(范围下界):inclusive,等于 prefix 的对象必须保留
    //     (否则 LIST(prefix=某对象完整key) 会漏掉该对象)。
    let use_start_after = start_after > prefix;
    let effective_start = if use_start_after { start_after } else { prefix };
    // 多取 1 个判断是否截断;delete_marker 需跳过,故循环补取直到够数或耗尽。
    let mut out: Vec<DiskObjectEntry> = Vec::with_capacity(limit.min(4096));
    let mut cursor = effective_start.to_string();
    // 首批:effective_start 来自 prefix 时 inclusive;来自 start_after 时 exclusive。
    let mut inclusive_first = !use_start_after && !prefix.is_empty();
    let mut has_more = false;
    'outer: loop {
        let batch = if inclusive_first {
            state
                .meta_store
                .scan_bucket_page_inclusive(bucket, &cursor, limit + 1)
                .unwrap_or_default()
        } else {
            state
                .meta_store
                .scan_bucket_page(bucket, &cursor, limit + 1)
                .unwrap_or_default()
        };
        inclusive_first = false; // 后续批次以上一批末尾 key 为 exclusive continuation。
        if batch.is_empty() {
            break;
        }
        let batch_len = batch.len();
        for meta in batch {
            cursor = meta.key.clone();
            // 超出 prefix 范围(有序 → 之后都不匹配),结束。
            if !prefix.is_empty() && !meta.key.starts_with(prefix) {
                break 'outer;
            }
            // 与 start_after 严格大于(continuation 已 exclusive,但 effective_start=prefix 时需再判)。
            if !start_after.is_empty() && meta.key.as_str() <= start_after {
                continue;
            }
            if meta.delete_marker {
                continue;
            }
            if out.len() == limit {
                has_more = true;
                break 'outer;
            }
            out.push(DiskObjectEntry {
                key: meta.key.clone(),
                size: meta.size,
                etag: meta.etag.clone(),
                last_modified: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                storage_class: object_storage_class(&meta).to_string(),
            });
        }
        // 本批不足 limit+1 → 已到末尾。
        if batch_len < limit + 1 {
            break;
        }
    }
    (out, has_more)
}

pub(crate) fn collect_object_payload_files(
    bucket_root: &FsPath,
    dir: &FsPath,
    output: &mut HashMap<String, DiskObjectEntry>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        let rel = path
            .strip_prefix(bucket_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if rel == ".rustio_meta"
            || rel.starts_with(".rustio_meta/")
            || rel == ".rustio_versions"
            || rel.starts_with(".rustio_versions/")
            || rel == ".rustio_ec_meta"
            || rel.starts_with(".rustio_ec_meta/")
            || rel == ".rustio_payload"
            || rel.starts_with(".rustio_payload/")
        {
            continue;
        }

        if metadata.is_dir() {
            collect_object_payload_files(bucket_root, &path, output)?;
            continue;
        }

        if !metadata.is_file() {
            continue;
        }

        let modified = metadata.modified().ok();
        let modified_at: DateTime<Utc> =
            modified.map(DateTime::<Utc>::from).unwrap_or_else(Utc::now);
        let modified_secs = modified
            .and_then(|v| v.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|v| v.as_secs())
            .unwrap_or(0);

        output.insert(
            rel.clone(),
            DiskObjectEntry {
                key: rel,
                size: metadata.len(),
                etag: format!("{:x}{:x}", metadata.len(), modified_secs),
                last_modified: modified_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                storage_class: default_storage_class(),
            },
        );
    }
    Ok(())
}

pub(crate) fn collect_object_meta_entries(
    state: &AppState,
    bucket: &str,
    output: &mut HashMap<String, DiskObjectEntry>,
) {
    // current 对象元数据已下沉 redb,从 scan_bucket 覆盖 payload 枚举得到的默认值。
    for meta in state.meta_store.scan_bucket(bucket).unwrap_or_default() {
        if meta.delete_marker {
            output.remove(&meta.key);
            continue;
        }
        output.insert(
            meta.key.clone(),
            DiskObjectEntry {
                key: meta.key.clone(),
                size: meta.size,
                etag: meta.etag.clone(),
                last_modified: meta.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                storage_class: object_storage_class(&meta).to_string(),
            },
        );
    }
}

pub(crate) fn is_bucket_control_plane_metadata_path(bucket_root: &FsPath, path: &FsPath) -> bool {
    let rel = path
        .strip_prefix(bucket_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    matches!(
        rel.as_str(),
        ".rustio_meta/bucket-policy.json"
            | ".rustio_meta/bucket-lifecycle.json"
            | ".rustio_meta/bucket-notifications.json"
            | ".rustio_meta/bucket-acl.json"
            | ".rustio_meta/bucket-public-access-block.json"
            | ".rustio_meta/bucket-cors.json"
            | ".rustio_meta/bucket-tags.json"
            | ".rustio_meta/bucket-encryption.json"
            | ".rustio_meta/bucket-website.json"
    ) || rel == ".rustio_ec_meta"
        || rel.starts_with(".rustio_ec_meta/")
        || rel == ".rustio_payload"
        || rel.starts_with(".rustio_payload/")
}

pub(crate) fn bucket_has_objects(bucket_root: &FsPath, dir: &FsPath) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if is_bucket_control_plane_metadata_path(bucket_root, &path) {
            continue;
        }
        if metadata.is_file() {
            return Ok(true);
        }
        if metadata.is_dir() && bucket_has_objects(bucket_root, &path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn remove_empty_dirs_until(
    mut current: &FsPath,
    stop_at: &FsPath,
) -> std::io::Result<()> {
    while current.starts_with(stop_at) && current != stop_at {
        if std::fs::read_dir(current)?.next().is_some() {
            break;
        }
        std::fs::remove_dir(current)?;
        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            break;
        }
    }
    Ok(())
}

pub(crate) fn weak_etag(bytes: &[u8]) -> String {
    let result = md5::Md5::digest(bytes);
    format!("{:x}", result)
}

/// encoding-type=url 时对 List 响应中的 key 类字段（Key/Prefix/Delimiter/Marker 等）
/// 做 URL 编码；'/' 不编码，对齐 AWS 行为。
pub(crate) fn s3_encode_key(value: &str, encoding_url: bool) -> String {
    if !encoding_url {
        return value.to_string();
    }
    const KEY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'/')
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    utf8_percent_encode(value, KEY_ENCODE_SET).to_string()
}

pub(crate) fn format_http_date(value: DateTime<Utc>) -> String {
    value.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub(crate) fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
        .or_else(|| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|parsed| parsed.with_timezone(&Utc))
        })
}

/// 补齐 GET 响应中流式非 Range / 全量路径共用的头（Content-Type / accept-ranges / Last-Modified / Content-Length / ETag / x-amz-version-id / lock 等），减少重复代码。
pub(crate) fn apply_common_get_response_headers(
    response: &mut Response,
    meta: &S3ObjectMeta,
    etag_quoted: &str,
    last_modified: chrono::DateTime<chrono::Utc>,
    content_length: usize,
) {
    let resolved_content_type = meta
        .content_type
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_string());
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_str(&resolved_content_type)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("accept-ranges"),
        axum::http::HeaderValue::from_static("bytes"),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&format_http_date(last_modified)) {
        response.headers_mut().insert(axum::http::header::LAST_MODIFIED, value);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&content_length.to_string()) {
        response.headers_mut().insert(axum::http::header::CONTENT_LENGTH, value);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(etag_quoted) {
        response.headers_mut().insert(axum::http::header::ETAG, value);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-amz-version-id"),
            value,
        );
    }
    if let Some(mode) = meta.retention_mode.as_deref() {
        if let Ok(value) = axum::http::HeaderValue::from_str(mode) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-object-lock-mode"),
                value,
            );
        }
    }
    if let Some(retention_until) = meta.retention_until {
        if let Ok(value) = axum::http::HeaderValue::from_str(
            &retention_until.to_rfc3339_opts(SecondsFormat::Secs, true),
        ) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-amz-object-lock-retain-until-date"),
                value,
            );
        }
    }
}

/// 解析 Range 请求头为原始(start, end_or_suffix_len)，不依赖对象大小。
pub(crate) fn parse_range_header_raw(headers: &HeaderMap) -> Option<(u64, u64)> {
    let raw = headers
        .get(axum::http::header::RANGE)
        .and_then(|value| value.to_str().ok())?;
    let spec = raw.strip_prefix("bytes=")?;
    if spec.contains(',') { return None; }
    let mut split = spec.splitn(2, '-');
    let start_raw = split.next().unwrap_or_default().trim();
    let end_raw = split.next()?.trim();
    if start_raw.is_empty() {
        let suffix = end_raw.parse::<u64>().ok()?;
        return if suffix == 0 { None } else { Some((0, suffix)) };
    }
    let start = start_raw.parse::<u64>().ok()?;
    let end = if end_raw.is_empty() { u64::MAX } else { end_raw.parse::<u64>().ok()? };
    Some((start, end))
}

/// 将 parse_range_header_raw 的结果钳制到对象大小，返回闭区间。非法返 Err(())。
pub(crate) fn normalize_range_bounds(raw_start: u64, raw_end: u64, size: u64) -> Result<Option<(u64, u64)>, ()> {
    if size == 0 { return Err(()); }
    let (start, end) = if raw_start == 0 && raw_end < size {
        // suffix 形式: (0, suffix_len)
        let suffix_len = raw_end;
        if suffix_len == 0 { return Err(()); }
        (size.saturating_sub(suffix_len), size - 1)
    } else {
        let start = raw_start;
        if start >= size { return Err(()); }
        let end = raw_end.min(size - 1);
        if start > end { return Err(()); }
        (start, end)
    };
    Ok(Some((start, end)))
}

/// 解析 Range 请求头为闭区间(start, end)，不依赖对象大小。用于流式路径。
pub(crate) fn parse_range_header(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(raw) = headers
        .get(axum::http::header::RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    if size == 0 {
        return Err(());
    }

    let Some(spec) = raw.strip_prefix("bytes=") else {
        return Err(());
    };
    if spec.contains(',') {
        return Err(());
    }

    let mut split = spec.splitn(2, '-');
    let start_raw = split.next().unwrap_or_default().trim();
    let end_raw = split.next().ok_or(())?.trim();
    if start_raw.is_empty() {
        let suffix_len = end_raw.parse::<u64>().map_err(|_| ())?;
        if suffix_len == 0 {
            return Err(());
        }
        let start = size.saturating_sub(suffix_len);
        let end = size - 1;
        return Ok(Some((start, end)));
    }

    let start = start_raw.parse::<u64>().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }

    let end = if end_raw.is_empty() {
        size - 1
    } else {
        end_raw.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if start > end {
        return Err(());
    }
    Ok(Some((start, end)))
}

pub(crate) fn normalize_etag_token(token: &str) -> &str {
    token
        .trim()
        .trim_start_matches("W/")
        .trim_start_matches("w/")
        .trim()
}

pub(crate) fn if_header_matches_etag(value: &str, etag: &str, etag_quoted: &str) -> bool {
    value.split(',').map(str::trim).any(|item| {
        let token = normalize_etag_token(item);
        token == "*" || token == etag_quoted || token.trim_matches('"') == etag
    })
}

pub(crate) fn precondition_response(
    method: &Method,
    status: StatusCode,
    code: &str,
    message: &str,
    key: &str,
) -> Response {
    if *method == Method::HEAD {
        status.into_response()
    } else {
        s3_error(status, code, message, key)
    }
}

pub(crate) fn evaluate_object_preconditions(
    method: &Method,
    headers: &HeaderMap,
    etag: &str,
    etag_quoted: &str,
    last_modified: DateTime<Utc>,
    key: &str,
) -> Option<Response> {
    let if_match = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_match {
        if !if_header_matches_etag(value, etag, etag_quoted) {
            return Some(precondition_response(
                method,
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                key,
            ));
        }
    }

    let if_unmodified_since = headers
        .get(axum::http::header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_match.is_none() {
        if let Some(boundary) = if_unmodified_since {
            if last_modified > boundary {
                return Some(precondition_response(
                    method,
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    key,
                ));
            }
        }
    }

    let if_none_match = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_none_match {
        if if_header_matches_etag(value, etag, etag_quoted) {
            return Some(StatusCode::NOT_MODIFIED.into_response());
        }
    }

    let if_modified_since = headers
        .get(axum::http::header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_none_match.is_none() {
        if let Some(boundary) = if_modified_since {
            if last_modified <= boundary {
                return Some(StatusCode::NOT_MODIFIED.into_response());
            }
        }
    }

    None
}

pub(crate) fn evaluate_copy_source_preconditions(
    headers: &HeaderMap,
    etag: &str,
    last_modified: DateTime<Utc>,
    resource: &str,
) -> Option<Response> {
    let etag_quoted = format!("\"{etag}\"");
    let if_match = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-match",
        ))
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_match {
        if !if_header_matches_etag(value, etag, &etag_quoted) {
            return Some(s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                resource,
            ));
        }
    }

    let if_unmodified_since = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-unmodified-since",
        ))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_match.is_none() {
        if let Some(boundary) = if_unmodified_since {
            if last_modified > boundary {
                return Some(s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    resource,
                ));
            }
        }
    }

    let if_none_match = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-none-match",
        ))
        .and_then(|value| value.to_str().ok());
    if let Some(value) = if_none_match {
        if if_header_matches_etag(value, etag, &etag_quoted) {
            return Some(s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                resource,
            ));
        }
    }

    let if_modified_since = headers
        .get(axum::http::header::HeaderName::from_static(
            "x-amz-copy-source-if-modified-since",
        ))
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date);
    if if_none_match.is_none() {
        if let Some(boundary) = if_modified_since {
            if last_modified <= boundary {
                return Some(s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    resource,
                ));
            }
        }
    }

    None
}

/// 抽取 XML 中 `<tag>...</tag>`(含标签本身)的原始片段,用于 round-trip 保真存储
/// 而不解析其内部结构(如 website RoutingRules)。多个同名标签只取第一段。
pub(crate) fn extract_xml_fragment(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?;
    let end = xml[start..].find(&close)? + start + close.len();
    Some(xml[start..end].to_string())
}

pub(crate) fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn s3_xml_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub(crate) fn bilingual_s3_message(code: &str, message: &str) -> String {
    if message.contains(" / ") {
        return message.to_string();
    }

    let (zh, en_default) = match code {
        "NoSuchBucket" => ("桶不存在", "The specified bucket does not exist"),
        "NoSuchKey" => ("对象不存在", "The specified key does not exist"),
        "NoSuchUpload" => (
            "分片上传不存在",
            "The specified multipart upload does not exist",
        ),
        "NoSuchVersion" => (
            "对象版本不存在",
            "The specified object version does not exist",
        ),
        "NoSuchBucketPolicy" => ("桶策略不存在", "The bucket policy does not exist"),
        "NoSuchCORSConfiguration" => ("CORS 配置不存在", "The CORS configuration does not exist"),
        "NoSuchTagSet" => ("标签配置不存在", "The tag set does not exist"),
        "NoSuchLifecycleConfiguration" => (
            "生命周期配置不存在",
            "The lifecycle configuration does not exist",
        ),
        "BucketAlreadyOwnedByYou" => (
            "桶已存在且归属于当前账号",
            "Your previous request to create the named bucket succeeded",
        ),
        "BucketNotEmpty" => ("桶不为空", "The bucket you tried to delete is not empty"),
        "InvalidBucketName" => ("桶名称无效", "The specified bucket is not valid"),
        "InvalidObjectName" => ("对象名称无效", "The specified object name is not valid"),
        "InvalidVersionId" => ("版本号无效", "The specified version ID is not valid"),
        "InvalidRange" => ("请求范围无效", "The requested range is not satisfiable"),
        "InvalidTag" => ("标签参数无效", "The Tag provided was not a valid tag"),
        "InvalidArgument" => ("参数无效", "Invalid Argument"),
        "InvalidRequest" => ("请求不合法", "Invalid Request"),
        "PreconditionFailed" => (
            "前置条件不满足",
            "At least one of the preconditions you specified did not hold",
        ),
        "MalformedXML" => ("XML 格式错误", "The XML you provided was not well-formed"),
        "MalformedPolicy" => ("策略文档格式错误", "The policy document is malformed"),
        "ObjectLockConfigurationNotFoundError" => (
            "对象锁配置不存在",
            "Object Lock configuration does not exist",
        ),
        "ServerSideEncryptionConfigurationNotFoundError" => (
            "桶加密配置不存在",
            "Server side encryption configuration was not found",
        ),
        "AccessDenied" => ("访问被拒绝", "Access Denied"),
        "SignatureDoesNotMatch" => (
            "签名不匹配",
            "The request signature we calculated does not match the signature you provided",
        ),
        "ExpiredToken" => ("令牌已过期", "The provided token has expired"),
        "InvalidToken" => (
            "令牌无效",
            "The security token included in the request is invalid",
        ),
        "InvalidAccessKeyId" => (
            "AccessKey 不存在或无效",
            "The Access Key Id you provided does not exist in our records.",
        ),
        "AuthorizationHeaderMalformed" => (
            "Authorization 头格式错误",
            "The authorization header is malformed",
        ),
        "AuthorizationQueryParametersError" => (
            "签名查询参数错误",
            "The query string authorization parameters are malformed",
        ),
        "XAmzContentSHA256Mismatch" => (
            "请求体 SHA256 校验不匹配",
            "The provided x-amz-content-sha256 does not match",
        ),
        "InvalidPart" => (
            "分片参数无效",
            "One or more of the specified parts could not be found",
        ),
        "MethodNotAllowed" => (
            "方法不被允许",
            "The specified method is not allowed against this resource",
        ),
        "KMSNotConfigured" => ("KMS 未配置", "KMS is not configured"),
        "KMSUnavailable" => ("KMS 不可用", "KMS service is unavailable"),
        "InternalError" => ("服务器内部错误", "We encountered an internal error"),
        _ => ("S3 请求失败", "S3 request failed"),
    };

    let text = message.trim();
    if text.is_empty() {
        return format!("{zh} / {en_default}");
    }

    if contains_cjk_chars(text) && !contains_ascii_alpha(text) {
        return format!("{text} / {en_default}");
    }

    format!("{zh} / {text}")
}

pub(crate) fn contains_ascii_alpha(text: &str) -> bool {
    text.chars().any(|ch| ch.is_ascii_alphabetic())
}

pub(crate) fn contains_cjk_chars(text: &str) -> bool {
    text.chars().any(|ch| {
        matches!(
            ch as u32,
            0x3400..=0x4DBF
                | 0x4E00..=0x9FFF
                | 0xF900..=0xFAFF
                | 0x20000..=0x2A6DF
                | 0x2A700..=0x2B73F
                | 0x2B740..=0x2B81F
                | 0x2B820..=0x2CEAF
                | 0x2EBF0..=0x2EE5F
        )
    })
}

pub(crate) fn s3_error(status: StatusCode, code: &str, message: &str, resource: &str) -> Response {
    let message = bilingual_s3_message(code, message);
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>"#,
        xml_escape(code),
        xml_escape(&message),
        xml_escape(resource),
        Uuid::new_v4()
    );
    s3_xml_response(status, body)
}

pub(crate) fn ensure_confirm_header(headers: &HeaderMap) -> Result<(), AppError> {
    let confirmed = headers
        .get("x-rustio-confirm")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if confirmed {
        Ok(())
    } else {
        Err(AppError::precondition(
            "dangerous action requires x-rustio-confirm: true",
        ))
    }
}

pub(crate) fn extract_access_token(
    headers: &HeaderMap,
    query_token: Option<String>,
) -> Option<String> {
    if let Some(token) = query_token {
        return Some(token);
    }

    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.to_string())
}

pub(crate) fn wrap<T>(data: T) -> Json<ApiEnvelope<T>> {
    Json(ApiEnvelope {
        data,
        request_id: Uuid::new_v4().to_string(),
    })
}

/// 原子写入：先写同名 `.tmp` 临时文件 + fsync，再原子 rename 到目标路径，确保崩溃安全。
pub(crate) async fn atomic_write(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(
        path.extension()
            .map(|ext| format!("{}.tmp", ext.to_string_lossy()))
            .unwrap_or_else(|| "tmp".to_string()),
    );
    if let Some(parent) = tmp.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&tmp, bytes).await?;
    // flush 到磁盘（macOS fsync 即可，Linux 需 fsync + fsync dir）
    let file = tokio::fs::File::open(&tmp).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&tmp, path).await
}
