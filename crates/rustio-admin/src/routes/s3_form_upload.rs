//! S3 POST Object 表单上传 (browser-based form upload)

use super::*;

use base64::{
    engine::general_purpose::STANDARD as BASE64,
    Engine as _,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

// ── 数据结构 ──────────────────────────────────────────────

/// multipart/form-data 解析后的表单字段
struct FormFields {
    key: String,
    file_name: Option<String>,
    file_data: Vec<u8>,
    content_type: Option<String>,
    policy_b64: Option<String>,
    algorithm: Option<String>,
    signature: Option<String>,
    access_key: Option<String>,
    success_action_status: Option<String>,
    success_action_redirect: Option<String>,
    user_metadata: HashMap<String, String>,
}

/// 解码后的 policy 文档
#[allow(dead_code)]
struct FormPolicy {
    expiration: DateTime<Utc>,
    conditions: Vec<PolicyCondition>,
}

/// 单条 policy condition
enum PolicyCondition {
    ExactMatch { field: String, value: String },
    StartsWith { field: String, prefix: String },
    ContentLengthRange { min: u64, max: u64 },
}

/// 表单字段到 condition 变量名的映射键
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConditionField {
    Bucket,
    Key,
    ContentType,
    SuccessActionRedirect,
    SuccessActionStatus,
    XAmzMeta(String),
    XAmzAcl,
    XAmzSecurityToken,
    XAmzAlgorithm,
    XAmzCredential,
    XAmzDate,
    CacheControl,
    ContentDisposition,
    ContentEncoding,
    Expires,
    Other(String),
}

impl ConditionField {
    fn resolve(name: &str) -> Self {
        match name {
            "bucket" => Self::Bucket,
            "key" => Self::Key,
            "Content-Type" => Self::ContentType,
            "success_action_redirect" => Self::SuccessActionRedirect,
            "success_action_status" => Self::SuccessActionStatus,
            "acl" => Self::XAmzAcl,
            "x-amz-algorithm" => Self::XAmzAlgorithm,
            "x-amz-credential" => Self::XAmzCredential,
            "x-amz-date" => Self::XAmzDate,
            "x-amz-security-token" => Self::XAmzSecurityToken,
            "Cache-Control" => Self::CacheControl,
            "Content-Disposition" => Self::ContentDisposition,
            "Content-Encoding" => Self::ContentEncoding,
            "Expires" => Self::Expires,
            other if other.starts_with("x-amz-meta-") => {
                Self::XAmzMeta(other.strip_prefix("x-amz-meta-").unwrap_or("").to_string())
            }
            other => Self::Other(other.to_string()),
        }
    }

    fn value_from_fields(&self, fields: &FormFields, bucket: &str) -> String {
        match self {
            Self::Bucket => bucket.to_string(),
            Self::Key => fields.key.clone(),
            Self::ContentType => fields.content_type.clone().unwrap_or_default(),
            Self::SuccessActionRedirect => fields.success_action_redirect.clone().unwrap_or_default(),
            Self::SuccessActionStatus => fields.success_action_status.clone().unwrap_or_default(),
            Self::XAmzAlgorithm => fields.algorithm.clone().unwrap_or_default(),
            Self::XAmzCredential => String::new(), // 不使用
            Self::XAmzDate => String::new(),       // 不使用
            Self::XAmzSecurityToken => String::new(),
            Self::XAmzAcl => String::new(),
            Self::XAmzMeta(key) => fields.user_metadata.get(key).cloned().unwrap_or_default(),
            Self::CacheControl => String::new(),
            Self::ContentDisposition => String::new(),
            Self::ContentEncoding => String::new(),
            Self::Expires => String::new(),
            Self::Other(_) => String::new(),
        }
    }
}

// ── 主入口 ────────────────────────────────────────────────

pub(crate) async fn s3_form_upload(
    state: Arc<AppState>,
    bucket: String,
    content_type_header: &str,
    body: Vec<u8>,
) -> Response {
    // 1. 解析 multipart/form-data
    let fields = match parse_multipart_form_data(content_type_header, &body) {
        Ok(f) => f,
        Err(response) => return response,
    };

    // 2. 桶存在性校验
    let _ = match bucket_path(&state, &bucket) {
        Ok(path) => path,
        Err(response) => return response,
    };

    // 3. Policy 校验
    let _policy = match &fields.policy_b64 {
        Some(p) => match decode_and_validate_policy(p) {
            Ok(policy) => policy,
            Err(response) => return response,
        },
        None => {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPolicyDocument",
                "Policy is required",
                &bucket,
            );
        }
    };

    // 4. Policy conditions 校验
    if let Err(response) = check_policy_conditions(&_policy, &fields, &bucket) {
        return response;
    }

    // 5. Signature 校验
    if fields.algorithm.is_none() && fields.signature.is_some() {
        // SigV2 HMAC-SHA1
        if let Err(response) = validate_sigv2_signature(&fields, &state) {
            return response;
        }
    } else if fields.algorithm.is_some() {
        // SigV4 (暂未实现)
        return s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "POST form upload with SigV4 is not yet supported; use SigV2 (no x-amz-algorithm header) or anonymous",
            &bucket,
        );
    }
    // 否则匿名 — 仅依赖 policy 校验，无签名

    // 6. Key 映射
    let key = resolve_object_key(&fields);

    // 7. 写入对象
    let meta = match write_form_upload_object(&state, &bucket, &key, &fields).await {
        Ok(meta) => meta,
        Err(response) => return response,
    };

    // 8. 构建响应
    build_form_upload_response(&meta, &fields, &bucket)
}

// ── multipart/form-data 解析 ──────────────────────────────

fn parse_multipart_form_data(content_type: &str, body: &[u8]) -> Result<FormFields, Response> {
    let boundary = extract_boundary(content_type).ok_or_else(|| {
        s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Missing boundary in Content-Type",
            "",
        )
    })?;

    let mut fields = FormFields {
        key: String::new(),
        file_name: None,
        file_data: Vec::new(),
        content_type: None,
        policy_b64: None,
        algorithm: None,
        signature: None,
        access_key: None,
        success_action_status: None,
        success_action_redirect: None,
        user_metadata: HashMap::new(),
    };

    let delim = format!("--{}", boundary);
    let delim_bytes = delim.as_bytes();
    let end_delim = format!("--{}--", boundary);
    let end_delim_bytes = end_delim.as_bytes();

    let parts = split_by_boundary(body, delim_bytes, end_delim_bytes);

    for part in parts.iter().filter(|p| !p.is_empty()) {
        let (headers_str, data) = split_part_headers_data(part);
        let headers = parse_part_headers(headers_str);

        let disposition = headers.get("content-disposition").cloned().unwrap_or_default();
        let name = extract_disposition_param(&disposition, "name");
        let filename = extract_disposition_param(&disposition, "filename");

        match name.as_deref() {
            Some("file") => {
                fields.file_name = filename;
                fields.file_data = data.to_vec();
            }
            Some(n) => {
                let value = std::str::from_utf8(data)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                assign_form_field(&mut fields, n, &value);
            }
            None => continue,
        }
    }

    // key 默认使用文件名
    if fields.key.is_empty() {
        fields.key = fields.file_name.clone().unwrap_or_else(|| "upload".to_string());
    }

    Ok(fields)
}

fn extract_boundary(content_type: &str) -> Option<String> {
    // Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...
    for segment in content_type.split(';') {
        let trimmed = segment.trim();
        if let Some(value) = trimmed.strip_prefix("boundary=") {
            let value = value.trim_matches('"').trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn split_by_boundary<'a>(
    body: &'a [u8],
    delim: &[u8],
    end_delim: &[u8],
) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let body_len = body.len();

    while start < body_len {
        // 查找下一个 boundary
        if let Some(pos) = find_bytes(&body[start..], delim) {
            let abs_pos = start + pos;
            if start == 0 {
                // 开头的数据（preamble）跳过
            } else {
                parts.push(&body[start..abs_pos]);
            }
            // 跳过 boundary 行（含 \r\n 或 \n）
            let after_delim = abs_pos + delim.len();
            start = after_delim;
            // 检查是否是结束 boundary
            if body[abs_pos..].starts_with(end_delim) {
                break;
            }
            // 跳过 \r\n 或 \n
            if start < body_len && body[start] == b'\r' {
                start += 1;
            }
            if start < body_len && body[start] == b'\n' {
                start += 1;
            }
        } else {
            break;
        }
    }

    parts
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn split_part_headers_data(part: &[u8]) -> (&[u8], &[u8]) {
    // 搜索 \r\n\r\n 或 \n\n
    let raw = if let Some(pos) = find_bytes(part, b"\r\n\r\n") {
        (&part[..pos], &part[pos + 4..])
    } else if let Some(pos) = find_bytes(part, b"\n\n") {
        (&part[..pos], &part[pos + 2..])
    } else {
        let empty: &[u8] = &[];
        (empty, part)
    };
    // 去除尾部 \r\n（RFC: 数据末尾的 \r\n 属于 boundary 分隔符的一部分）
    let data = strip_trailing_crlf(raw.1);
    (raw.0, data)
}

fn strip_trailing_crlf(data: &[u8]) -> &[u8] {
    if data.ends_with(b"\r\n") {
        &data[..data.len() - 2]
    } else if data.ends_with(b"\n") {
        &data[..data.len() - 1]
    } else {
        data
    }
}

fn parse_part_headers(headers_raw: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(headers_raw);
    let mut map = HashMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // 多行续接（折叠头）简化：此处不处理，表单上传头通常不折叠
        if let Some((name, value)) = line.split_once(':') {
            map.insert(name.trim().to_lowercase(), value.trim().to_string());
        } else {
            map.insert(line.trim().to_lowercase(), String::new());
        }
    }
    map
}

fn extract_disposition_param(disposition: &str, param: &str) -> Option<String> {
    let parts: Vec<&str> = disposition.split(';').collect();
    for part in &parts[1..] {
        // 每段形如 name="value" 或 name=value
        let trimmed = part.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            if key.trim().eq_ignore_ascii_case(param) {
                let value = value.trim().trim_matches('"').trim();
                return Some(value.to_string());
            }
        }
    }
    None
}

fn assign_form_field(fields: &mut FormFields, name: &str, value: &str) {
    match name {
        "key" => fields.key = value.to_string(),
        "Content-Type" => fields.content_type = Some(value.to_string()),
        "policy" => fields.policy_b64 = Some(value.to_string()),
        "x-amz-algorithm" => fields.algorithm = Some(value.to_string()),
        "x-amz-signature" | "signature" => fields.signature = Some(value.to_string()),
        "AWSAccessKeyId" => fields.access_key = Some(value.to_string()),
        "success_action_status" => fields.success_action_status = Some(value.to_string()),
        "success_action_redirect" => fields.success_action_redirect = Some(value.to_string()),
        other => {
            if let Some(meta_key) = other.strip_prefix("x-amz-meta-") {
                fields
                    .user_metadata
                    .insert(meta_key.to_string(), value.to_string());
            }
        }
    }
}

// ── Policy 解码与校验 ─────────────────────────────────────

fn decode_and_validate_policy(policy_b64: &str) -> Result<FormPolicy, Response> {
    let json_bytes = BASE64.decode(policy_b64).map_err(|_| {
        s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidPolicyDocument",
            "Policy is not valid base64",
            "",
        )
    })?;

    let json: Value = serde_json::from_slice(&json_bytes).map_err(|err| {
        s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidPolicyDocument",
            &format!("Policy is not valid JSON: {err}"),
            "",
        )
    })?;

    let expiration_str = json
        .get("expiration")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPolicyDocument",
                "Policy missing expiration",
                "",
            )
        })?;

    let expiration = DateTime::parse_from_rfc3339(expiration_str)
        .map_err(|_| {
            s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPolicyDocument",
                "Policy expiration is not valid ISO8601",
                "",
            )
        })?
        .with_timezone(&Utc);

    if Utc::now() >= expiration {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Policy has expired",
            "",
        ));
    }

    let conditions_raw = json
        .get("conditions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPolicyDocument",
                "Policy missing conditions array",
                "",
            )
        })?;

    let mut conditions = Vec::new();
    for cond in conditions_raw {
        match cond {
            Value::Array(arr) => {
                let parsed =
                    parse_policy_condition_array(arr).map_err(|msg| {
                        s3_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidPolicyDocument",
                            &msg,
                            "",
                        )
                    })?;
                conditions.push(parsed);
            }
            Value::Object(obj) => {
                // 简写形式: {"bucket": "mybucket"} / {"key": "prefix"} 等都可以，
                // 实际上 AWS docs 说简写只做 exact match
                for (key, val) in obj {
                    let field = key.trim_start_matches('$').to_string();
                    let value = val.as_str().unwrap_or("").to_string();
                    conditions.push(PolicyCondition::ExactMatch { field, value });
                }
            }
            _ => {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidPolicyDocument",
                    "Each condition must be an array or object",
                    "",
                ));
            }
        }
    }

    Ok(FormPolicy {
        expiration,
        conditions,
    })
}

fn parse_policy_condition_array(arr: &[Value]) -> Result<PolicyCondition, String> {
    if arr.is_empty() {
        return Err("empty condition array".to_string());
    }

    let op = arr[0]
        .as_str()
        .ok_or_else(|| "condition operator must be a string".to_string())?;

    match op {
        "eq" => {
            if arr.len() != 3 {
                return Err("eq requires 3 elements".to_string());
            }
            let field = arr[1].as_str().unwrap_or("").trim_start_matches('$').to_string();
            let value = arr[2].as_str().unwrap_or("").to_string();
            Ok(PolicyCondition::ExactMatch { field, value })
        }
        "starts-with" => {
            if arr.len() != 3 {
                return Err("starts-with requires 3 elements".to_string());
            }
            let field = arr[1].as_str().unwrap_or("").trim_start_matches('$').to_string();
            let prefix = arr[2].as_str().unwrap_or("").to_string();
            Ok(PolicyCondition::StartsWith { field, prefix })
        }
        "content-length-range" => {
            if arr.len() != 3 {
                return Err("content-length-range requires 3 elements".to_string());
            }
            let min = arr[1].as_u64().ok_or("min must be integer")?;
            let max = arr[2].as_u64().ok_or("max must be integer")?;
            Ok(PolicyCondition::ContentLengthRange { min, max })
        }
        other => Err(format!("unknown condition operator: {other}")),
    }
}

fn check_policy_conditions(
    policy: &FormPolicy,
    fields: &FormFields,
    bucket: &str,
) -> Result<(), Response> {
    for condition in &policy.conditions {
        let ok = match condition {
            PolicyCondition::ExactMatch { field, value } => {
                let cond = ConditionField::resolve(field);
                let actual = cond.value_from_fields(fields, bucket);
                actual == *value
            }
            PolicyCondition::StartsWith { field, prefix } => {
                let cond = ConditionField::resolve(field);
                let actual = cond.value_from_fields(fields, bucket);
                actual.starts_with(prefix.as_str())
            }
            PolicyCondition::ContentLengthRange { min, max } => {
                let len = fields.file_data.len() as u64;
                len >= *min && len <= *max
            }
        };

        if !ok {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Request does not match policy conditions",
                bucket,
            ));
        }
    }
    Ok(())
}

// ── Signature 校验 ────────────────────────────────────────

fn validate_sigv2_signature(
    fields: &FormFields,
    state: &AppState,
) -> Result<(), Response> {
    let access_key = fields.access_key.as_deref().unwrap_or("");
    let signature = fields.signature.as_deref().unwrap_or("");
    let policy_b64 = fields.policy_b64.as_deref().unwrap_or("");

    if access_key.is_empty() || signature.is_empty() {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Missing AWSAccessKeyId or signature",
            "",
        ));
    }

    // 从 service_accounts 查找 secret key
    let secret_key = if let Ok(accounts) = state.service_accounts.try_read() {
        accounts
            .iter()
            .find(|a| a.access_key == access_key && a.status == "enabled")
            .map(|a| a.secret_key.clone())
    } else {
        None
    };

    let secret_key = match secret_key {
        Some(k) => k,
        None => {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "InvalidAccessKeyId",
                "The AWS Access Key Id you provided does not exist in our records",
                "",
            ));
        }
    };

    // HMAC-SHA1(secret_key, policy_base64)
    let mut mac =
        <HmacSha1 as hmac::Mac>::new_from_slice(secret_key.as_bytes()).map_err(|_| {
            s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "HMAC initialization failed",
                "",
            )
        })?;
    mac.update(policy_b64.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());

    if !computed.eq_ignore_ascii_case(signature) {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
            "",
        ));
    }

    Ok(())
}

// ── Key 映射 ──────────────────────────────────────────────

fn resolve_object_key(fields: &FormFields) -> String {
    let filename = fields.file_name.as_deref().unwrap_or("");
    let key = fields.key.clone();

    // ${filename} 替换
    let resolved = key.replace("${filename}", filename);

    // S3 规范：key 以 / 结尾表示目录，应拼上文件名
    if resolved.ends_with('/') {
        format!("{}{}", resolved, filename)
    } else {
        resolved
    }
}

// ── 对象写入 ─────────────────────────────────────────────

async fn write_form_upload_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    fields: &FormFields,
) -> Result<S3ObjectMeta, Response> {
    let size = fields.file_data.len() as u64;
    let etag = weak_etag(&fields.file_data);
    let content_type = fields.content_type.clone();

    let mut meta = build_object_meta_for_current_version(
        state,
        bucket,
        key,
        size,
        etag.clone(),
        false,
        content_type.clone(),
    )
    .await;

    meta.user_metadata = fields.user_metadata.clone();
    meta.encryption = S3ObjectEncryptionMeta::default();

    // EC 编码写入
    write_ec_object(state, bucket, key, &fields.file_data, &mut meta, None).await?;

    // 持久化元数据
    persist_current_object_meta(state, meta.clone()).await?;

    // 触发复制
    enqueue_replication_for_object(
        state,
        bucket,
        key,
        "put",
        Some(meta.version_id.clone()),
        Some(&meta),
    )
    .await;

    // 触发事件
    emit_bucket_object_event_best_effort(
        state,
        bucket,
        key,
        "s3:ObjectCreated:Post",
        Some(&meta),
        "s3",
    )
    .await;

    Ok(meta)
}

// ── 响应构建 ──────────────────────────────────────────────

fn build_form_upload_response(
    meta: &S3ObjectMeta,
    fields: &FormFields,
    bucket: &str,
) -> Response {
    // 303 重定向优先
    if let Some(ref redirect_url) = fields.success_action_redirect {
        let sep = if redirect_url.contains('?') { "&" } else { "?" };
        let location = format!(
            "{}{sep}bucket={bucket}&key={}&etag={}",
            redirect_url,
            percent_encoding::utf8_percent_encode(&meta.key, percent_encoding::NON_ALPHANUMERIC),
            &meta.etag,
        );
        return Redirect::to(&location).into_response();
    }

    let status = match fields.success_action_status.as_deref() {
        Some("200") => StatusCode::OK,
        Some("201") => StatusCode::CREATED,
        _ => StatusCode::NO_CONTENT, // 默认 204
    };

    let mut response = if status == StatusCode::NO_CONTENT {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        // 204 无 body，但 AWS 仍返回 ETag
        if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
            resp.headers_mut()
                .insert(axum::http::header::ETAG, value);
        }
        resp
    } else {
        // 200 或 201 返回 XML
        let location = format!(
            "/{}/{}",
            bucket,
            percent_encoding::utf8_percent_encode(&meta.key, percent_encoding::NON_ALPHANUMERIC),
        );
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<PostResponse>
  <Location>{}</Location>
  <Bucket>{}</Bucket>
  <Key>{}</Key>
  <ETag>"{}"</ETag>
</PostResponse>"#,
            xml_escape(&location),
            xml_escape(bucket),
            xml_escape(&meta.key),
            &meta.etag,
        );
        let mut resp = s3_xml_response(status, body);
        if let Ok(value) = axum::http::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
            resp.headers_mut()
                .insert(axum::http::header::ETAG, value);
        }
        resp
    };

    // Location header
    let location_value = format!(
        "/{}/{}",
        bucket,
        percent_encoding::utf8_percent_encode(&meta.key, percent_encoding::NON_ALPHANUMERIC),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&location_value) {
        response
            .headers_mut()
            .insert(axum::http::HeaderName::from_static("location"), value);
    }

    // Content-Type（仅非 204）
    if status != StatusCode::NO_CONTENT {
        if let Some(ref ct) = meta.content_type {
            if let Ok(value) = axum::http::HeaderValue::from_str(ct) {
                response
                    .headers_mut()
                    .insert(axum::http::header::CONTENT_TYPE, value);
            }
        }
    }

    // x-amz-version-id
    if meta.version_id != "null" {
        if let Ok(value) = axum::http::HeaderValue::from_str(&meta.version_id) {
            response.headers_mut().insert(
                axum::http::HeaderName::from_static("x-amz-version-id"),
                value,
            );
        }
    }

    response
}

// ═══════════════════════════════════════════════════════════
// 单元测试
// ═══════════════════════════════════════════════════════════

