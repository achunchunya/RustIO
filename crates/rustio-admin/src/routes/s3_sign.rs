//! S3 SigV4 验签与策略评估

use super::*;

/// 流式 SigV4 签名上下文（aws-chunked 链式验签需要的 seed 签名和密钥信息）。
///
/// 仅当请求头含 `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` 时填充，
/// 供 aws-chunked 解码器逐块验证 chunk-signature（每块签名链式依赖上一块签名，初始为 seed）。
#[derive(Debug, Clone)]
pub(crate) struct StreamingSigV4Context {
    /// seed 签名（请求 Authorization header 验证通过的签名，作为链式验签起点）
    pub(crate) seed_signature: String,
    /// 签名密钥（由 secret_key/date/region/service 推导）
    pub(crate) signing_key: Vec<u8>,
    /// ISO8601 时间戳（YYYYMMDDTHHMMSSZ，用于块签名 string-to-sign）
    pub(crate) amz_date: String,
    /// 凭证作用域（date/region/service/aws4_request，用于 chunk string-to-sign）
    pub(crate) credential_scope: String,
}

/// S3 鉴权结果（向后兼容：非流式请求 streaming_context 为 None，现有调用方 `if let Err` 无需改）。
#[derive(Debug, Clone, Default)]
pub(crate) struct S3AuthOutcome {
    /// 仅当 payload 用 STREAMING-AWS4-HMAC-SHA256-PAYLOAD 时填充，供 aws-chunked 解码器链式验签
    pub(crate) streaming_context: Option<StreamingSigV4Context>,
    /// body 是 aws-chunked 编码且声明带 trailer（STREAMING-*-TRAILER），
    /// 解码器需在 0 块后解析 trailer 行（如 x-amz-checksum-crc32）
    pub(crate) chunked_trailer: bool,
    /// body 是 unsigned aws-chunked（STREAMING-UNSIGNED-PAYLOAD-TRAILER）：
    /// 块头无 chunk-signature，仍需解帧
    pub(crate) unsigned_chunked: bool,
    /// 期望的 body SHA256（小写 64 位 hex）。
    ///
    /// 仅当 SigV4 验签（query/header）且声明的 payload_hash 是 64 位 hex、**且调用方传 body=None**
    /// （流式分叉，无法在验签阶段比对）时填充，供调用方在流式消费 body 后比对防篡改。
    /// body=Some 的旧路径已在 `ensure_s3_auth` 内部比对，此字段保持 None 避免重复。
    pub(crate) expected_payload_sha256: Option<String>,
}

/// 流式分叉判定：仅当调用方传 `body=None`（无法在验签阶段比对）且声明的 payload_hash 是
/// 64 位 hex 时，回传该 hash 供调用方流式消费 body 后校验防篡改。其余情形返回 None
/// （UNSIGNED-PAYLOAD / STREAMING-* / body=Some 已内部比对）。
fn expected_payload_sha256_for_streaming(
    body: Option<&[u8]>,
    payload_hash: &str,
) -> Option<String> {
    if body.is_none()
        && payload_hash != "UNSIGNED-PAYLOAD"
        && !payload_hash.starts_with("STREAMING-AWS4-HMAC-SHA256")
        && payload_hash.len() == 64
        && payload_hash.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        Some(payload_hash.to_string())
    } else {
        None
    }
}

pub(crate) fn is_s3_signed_request(headers: &HeaderMap, raw_query: Option<&str>) -> bool {
    if is_s3_style_request(headers) {
        return true;
    }

    let Some(raw_query) = raw_query else {
        return false;
    };

    let lower = raw_query.to_ascii_lowercase();
    lower.contains("x-amz-algorithm=")
        || lower.contains("x-amz-signature=")
        || lower.contains("x-amz-credential=")
        || lower.contains("awsaccesskeyid=")
        || lower.contains("signature=")
}

pub(crate) fn is_s3_style_request(headers: &HeaderMap) -> bool {
    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };

    auth.starts_with("AWS4-HMAC-SHA256 ") || auth.starts_with("AWS ") || auth.starts_with("Basic ")
}

#[derive(Debug)]
pub(crate) struct AwsSigV4Auth {
    pub(crate) access_key: String,
    pub(crate) date: String,
    pub(crate) region: String,
    pub(crate) service: String,
    pub(crate) credential_scope: String,
    pub(crate) signed_headers: Vec<String>,
    pub(crate) signature: String,
}

#[derive(Debug)]
pub(crate) struct AwsSigV4QueryAuth {
    pub(crate) access_key: String,
    pub(crate) date: String,
    pub(crate) region: String,
    pub(crate) service: String,
    pub(crate) credential_scope: String,
    pub(crate) signed_headers: Vec<String>,
    pub(crate) signature: String,
    pub(crate) amz_date: String,
    pub(crate) expires: u64,
    pub(crate) payload_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum S3IdentityKind {
    Root,
    ServiceAccount,
    StsSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S3AuthType {
    Anonymous,
    Basic,
    AwsSigV4Header,
    AwsSigV4Query,
}

#[derive(Debug, Clone)]
pub(crate) struct S3CredentialIdentity {
    pub(crate) access_key: String,
    pub(crate) secret_key: String,
    pub(crate) session_token: Option<String>,
    pub(crate) principal: Option<String>,
    pub(crate) is_root: bool,
    pub(crate) kind: S3IdentityKind,
    pub(crate) role_arn: Option<String>,
    pub(crate) session_name: Option<String>,
    pub(crate) session_policy: Option<Value>,
}

#[derive(Debug)]
pub(crate) struct S3PolicyRequest<'a> {
    pub(crate) method: &'a Method,
    pub(crate) uri: &'a Uri,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) identity: Option<&'a S3CredentialIdentity>,
    pub(crate) auth_type: S3AuthType,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PolicyDecision {
    pub(crate) allowed: bool,
    pub(crate) explicit_deny: bool,
}

impl PolicyDecision {
    fn record(&mut self, effect: bool) {
        if effect {
            self.allowed = true;
        } else {
            self.explicit_deny = true;
        }
    }

    fn combine(&mut self, other: PolicyDecision) {
        self.allowed |= other.allowed;
        self.explicit_deny |= other.explicit_deny;
    }
}

pub(crate) fn resolve_s3_identity(
    state: &AppState,
    access_key: &str,
) -> Option<S3CredentialIdentity> {
    if access_key == state.s3_access_key {
        return Some(S3CredentialIdentity {
            access_key: access_key.to_string(),
            secret_key: state.s3_secret_key.clone(),
            session_token: None,
            principal: None,
            is_root: true,
            kind: S3IdentityKind::Root,
            role_arn: None,
            session_name: None,
            session_policy: None,
        });
    }

    if let Ok(service_accounts) = state.service_accounts.try_read() {
        if let Some(account) = service_accounts
            .iter()
            .find(|item| item.access_key == access_key && item.status == "enabled")
        {
            return Some(S3CredentialIdentity {
                access_key: account.access_key.clone(),
                secret_key: account.secret_key.clone(),
                session_token: None,
                principal: Some(account.owner.clone()),
                is_root: false,
                kind: S3IdentityKind::ServiceAccount,
                role_arn: None,
                session_name: None,
                session_policy: None,
            });
        }
    }

    if let Ok(sts_sessions) = state.sts_sessions.try_read() {
        if let Some(session) = sts_sessions.iter().find(|item| {
            item.access_key == access_key && item.status == "active" && item.expires_at > Utc::now()
        }) {
            return Some(S3CredentialIdentity {
                access_key: session.access_key.clone(),
                secret_key: session.secret_key.clone(),
                session_token: Some(session.session_token.clone()),
                principal: Some(session.principal.clone()),
                is_root: false,
                kind: S3IdentityKind::StsSession,
                role_arn: session.role_arn.clone(),
                session_name: session.session_name.clone(),
                session_policy: session.session_policy.clone(),
            });
        }
    }

    None
}

pub(crate) fn sts_session_expired_for_access_key(state: &AppState, access_key: &str) -> bool {
    let Ok(sts_sessions) = state.sts_sessions.try_read() else {
        return false;
    };
    sts_sessions.iter().any(|session| {
        session.access_key == access_key
            && session.status == "active"
            && session.expires_at <= Utc::now()
    })
}

pub(crate) fn resolve_s3_identity_or_error(
    state: &AppState,
    access_key: &str,
    resource: &str,
    invalid_code: &str,
    invalid_message: &str,
) -> Result<S3CredentialIdentity, Response> {
    if let Some(identity) = resolve_s3_identity(state, access_key) {
        return Ok(identity);
    }
    if sts_session_expired_for_access_key(state, access_key) {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "ExpiredToken",
            "The provided token has expired",
            resource,
        ));
    }
    Err(s3_error(
        StatusCode::FORBIDDEN,
        invalid_code,
        invalid_message,
        resource,
    ))
}

pub(crate) fn request_security_token(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(query) = query {
        let pairs = parse_query_pairs(query);
        if let Some(token) = query_value_case_insensitive(&pairs, "X-Amz-Security-Token") {
            return Some(token);
        }
    }
    headers
        .get("x-amz-security-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

pub(crate) fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    let mut position = 0usize;
    let starts_with_star = pattern.starts_with('*');
    let ends_with_star = pattern.ends_with('*');

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 && !starts_with_star {
            if !value[position..].starts_with(part) {
                return false;
            }
            position += part.len();
            continue;
        }
        if index == parts.len() - 1 && !ends_with_star {
            if let Some(found) = value[position..].rfind(part) {
                let absolute = position + found;
                return absolute + part.len() == value.len();
            }
            return false;
        }
        match value[position..].find(part) {
            Some(found) => {
                position += found + part.len();
            }
            None => return false,
        }
    }
    true
}

pub(crate) fn value_to_string_vec(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(single)) => vec![single.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn parse_s3_path(path: &str) -> (Option<&str>, Option<&str>) {
    let normalized = path.trim_start_matches('/');
    if normalized.is_empty() {
        return (None, None);
    }
    let mut parts = normalized.splitn(2, '/');
    let bucket = parts.next().filter(|value| !value.is_empty());
    let key = parts.next().filter(|value| !value.is_empty());
    (bucket, key)
}

pub(crate) fn query_has_key_case_insensitive(pairs: &[(String, String)], key: &str) -> bool {
    pairs
        .iter()
        .any(|(current, _)| current.eq_ignore_ascii_case(key))
}

pub(crate) fn infer_s3_action(request: &S3PolicyRequest<'_>) -> String {
    let (bucket, key) = parse_s3_path(request.uri.path());
    let query_pairs = request
        .uri
        .query()
        .map(parse_query_pairs)
        .unwrap_or_default();
    let has_version_id = query_value_case_insensitive(&query_pairs, "versionId")
        .map(|value| !value.is_empty())
        .unwrap_or(false);

    match (bucket, key, request.method) {
        (None, _, &Method::GET) | (None, _, &Method::HEAD) => "s3:ListAllMyBuckets".to_string(),
        (Some(_), None, method) => {
            if query_has_key_case_insensitive(&query_pairs, "location") && *method == Method::GET {
                return "s3:GetBucketLocation".to_string();
            }
            if query_has_key_case_insensitive(&query_pairs, "policy") {
                return match *method {
                    Method::GET => "s3:GetBucketPolicy".to_string(),
                    Method::PUT => "s3:PutBucketPolicy".to_string(),
                    Method::DELETE => "s3:DeleteBucketPolicy".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "acl") {
                return match *method {
                    Method::GET => "s3:GetBucketAcl".to_string(),
                    Method::PUT => "s3:PutBucketAcl".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "cors") {
                return match *method {
                    Method::GET => "s3:GetBucketCORS".to_string(),
                    Method::PUT => "s3:PutBucketCORS".to_string(),
                    Method::DELETE => "s3:DeleteBucketCORS".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "website") {
                return match *method {
                    Method::GET => "s3:GetBucketWebsite".to_string(),
                    Method::PUT => "s3:PutBucketWebsite".to_string(),
                    Method::DELETE => "s3:DeleteBucketWebsite".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "replication") {
                return match *method {
                    Method::GET => "s3:GetReplicationConfiguration".to_string(),
                    Method::PUT => "s3:PutReplicationConfiguration".to_string(),
                    Method::DELETE => "s3:DeleteReplicationConfiguration".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "tagging") {
                return match *method {
                    Method::GET => "s3:GetBucketTagging".to_string(),
                    Method::PUT => "s3:PutBucketTagging".to_string(),
                    Method::DELETE => "s3:DeleteBucketTagging".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "encryption") {
                return match *method {
                    Method::GET => "s3:GetEncryptionConfiguration".to_string(),
                    Method::PUT => "s3:PutEncryptionConfiguration".to_string(),
                    Method::DELETE => "s3:DeleteEncryptionConfiguration".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "lifecycle") {
                return match *method {
                    Method::GET => "s3:GetLifecycleConfiguration".to_string(),
                    Method::PUT => "s3:PutLifecycleConfiguration".to_string(),
                    Method::DELETE => "s3:DeleteLifecycleConfiguration".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "object-lock") {
                return match *method {
                    Method::GET => "s3:GetBucketObjectLockConfiguration".to_string(),
                    Method::PUT => "s3:PutBucketObjectLockConfiguration".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "notification") {
                return match *method {
                    Method::GET => "s3:GetBucketNotification".to_string(),
                    Method::PUT => "s3:PutBucketNotification".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "publicAccessBlock")
                || query_has_key_case_insensitive(&query_pairs, "public-access-block")
            {
                return match *method {
                    Method::GET => "s3:GetBucketPublicAccessBlock".to_string(),
                    Method::PUT => "s3:PutBucketPublicAccessBlock".to_string(),
                    Method::DELETE => "s3:DeleteBucketPublicAccessBlock".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "versioning") {
                return match *method {
                    Method::GET => "s3:GetBucketVersioning".to_string(),
                    Method::PUT => "s3:PutBucketVersioning".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "uploads") && *method == Method::GET {
                return "s3:ListBucketMultipartUploads".to_string();
            }
            if query_has_key_case_insensitive(&query_pairs, "versions") && *method == Method::GET {
                return "s3:ListBucketVersions".to_string();
            }
            if query_has_key_case_insensitive(&query_pairs, "delete") && *method == Method::POST {
                return "s3:DeleteObject".to_string();
            }
            match *method {
                Method::GET | Method::HEAD => "s3:ListBucket".to_string(),
                Method::PUT => "s3:CreateBucket".to_string(),
                Method::DELETE => "s3:DeleteBucket".to_string(),
                _ => "s3:*".to_string(),
            }
        }
        (Some(_), Some(_), method) => {
            if query_has_key_case_insensitive(&query_pairs, "legal-hold") {
                return match *method {
                    Method::GET if has_version_id => "s3:GetObjectVersionLegalHold".to_string(),
                    Method::GET => "s3:GetObjectLegalHold".to_string(),
                    Method::PUT if has_version_id => "s3:PutObjectVersionLegalHold".to_string(),
                    Method::PUT => "s3:PutObjectLegalHold".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "retention") {
                return match *method {
                    Method::GET if has_version_id => "s3:GetObjectVersionRetention".to_string(),
                    Method::GET => "s3:GetObjectRetention".to_string(),
                    Method::PUT if has_version_id => "s3:PutObjectVersionRetention".to_string(),
                    Method::PUT => "s3:PutObjectRetention".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "tagging") {
                return match *method {
                    Method::GET if has_version_id => "s3:GetObjectVersionTagging".to_string(),
                    Method::GET => "s3:GetObjectTagging".to_string(),
                    Method::PUT if has_version_id => "s3:PutObjectVersionTagging".to_string(),
                    Method::PUT => "s3:PutObjectTagging".to_string(),
                    Method::DELETE if has_version_id => "s3:DeleteObjectVersionTagging".to_string(),
                    Method::DELETE => "s3:DeleteObjectTagging".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "uploads") && *method == Method::POST {
                return "s3:PutObject".to_string();
            }
            if query_has_key_case_insensitive(&query_pairs, "restore") && *method == Method::POST {
                return "s3:RestoreObject".to_string();
            }
            if query_has_key_case_insensitive(&query_pairs, "select")
                || query_has_key_case_insensitive(&query_pairs, "select-type")
            {
                return match *method {
                    Method::POST if has_version_id => "s3:GetObjectVersion".to_string(),
                    Method::POST => "s3:GetObject".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            if query_has_key_case_insensitive(&query_pairs, "uploadId") {
                return match *method {
                    Method::DELETE => "s3:AbortMultipartUpload".to_string(),
                    Method::GET => "s3:ListMultipartUploadParts".to_string(),
                    Method::POST => "s3:PutObject".to_string(),
                    Method::PUT => "s3:PutObject".to_string(),
                    _ => "s3:*".to_string(),
                };
            }
            match *method {
                Method::GET | Method::HEAD if has_version_id => "s3:GetObjectVersion".to_string(),
                Method::GET | Method::HEAD => "s3:GetObject".to_string(),
                Method::PUT => "s3:PutObject".to_string(),
                Method::POST => "s3:PutObject".to_string(),
                Method::DELETE if has_version_id => "s3:DeleteObjectVersion".to_string(),
                Method::DELETE => "s3:DeleteObject".to_string(),
                _ => "s3:*".to_string(),
            }
        }
        _ => "s3:*".to_string(),
    }
}

pub(crate) fn s3_resource_candidates(path: &str) -> Vec<String> {
    let (bucket, key) = parse_s3_path(path);
    match (bucket, key) {
        (None, _) => vec![
            "arn:aws:s3:::*".to_string(),
            "/".to_string(),
            "*".to_string(),
        ],
        (Some(bucket), None) => vec![
            format!("arn:aws:s3:::{bucket}"),
            format!("/{bucket}"),
            "*".to_string(),
        ],
        (Some(bucket), Some(key)) => vec![
            format!("arn:aws:s3:::{bucket}/{key}"),
            format!("arn:aws:s3:::{bucket}"),
            format!("/{bucket}/{key}"),
            format!("/{bucket}"),
            "*".to_string(),
        ],
    }
}

pub(crate) fn principal_aliases(state: &AppState, principal: &str) -> HashSet<String> {
    let mut aliases = HashSet::from([principal.to_string()]);
    if let Ok(groups) = state.groups.try_read() {
        for group in groups.iter() {
            if group.members.iter().any(|member| member == principal) {
                aliases.insert(group.name.clone());
            }
        }
    }
    aliases
}

pub(crate) fn principal_patterns_from_value(value: &Value) -> Vec<String> {
    match value {
        Value::String(single) => vec![single.clone()],
        Value::Array(items) => items
            .iter()
            .flat_map(principal_patterns_from_value)
            .collect(),
        Value::Object(map) => map
            .values()
            .flat_map(principal_patterns_from_value)
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn request_principal_patterns(request: &S3PolicyRequest<'_>) -> HashSet<String> {
    match request.identity {
        None => HashSet::from([
            "*".to_string(),
            "anonymous".to_string(),
            "arn:aws:iam::rustio:anonymous".to_string(),
        ]),
        Some(identity) if identity.is_root => HashSet::from([
            "*".to_string(),
            "root".to_string(),
            "arn:aws:iam::rustio:root".to_string(),
        ]),
        Some(identity) => {
            let mut patterns = HashSet::new();
            let principal = identity.principal.clone().unwrap_or_default();
            if !principal.is_empty() {
                patterns.insert(principal.clone());
                patterns.insert(format!("arn:aws:iam::rustio:user/{principal}"));
                patterns.insert(format!("user/{principal}"));
            }
            match identity.kind {
                S3IdentityKind::Root => {
                    patterns.insert("root".to_string());
                    patterns.insert("arn:aws:iam::rustio:root".to_string());
                }
                S3IdentityKind::ServiceAccount => {
                    patterns.insert(format!(
                        "arn:aws:iam::rustio:service-account/{}",
                        identity.access_key
                    ));
                    patterns.insert(format!("service-account/{}", identity.access_key));
                }
                S3IdentityKind::StsSession => {
                    if let Some(arn) = sts_identity_assumed_role_arn(identity) {
                        patterns.insert(arn);
                    }
                    patterns.insert(format!("sts/{}", identity.access_key));
                }
            }
            patterns
        }
    }
}

pub(crate) fn statement_matches_principal(
    statement: &Value,
    request: &S3PolicyRequest<'_>,
    principal_required: bool,
) -> bool {
    let request_patterns = request_principal_patterns(request);
    if let Some(principal) = statement.get("Principal") {
        let patterns = principal_patterns_from_value(principal);
        return !patterns.is_empty()
            && patterns.iter().any(|pattern| {
                request_patterns
                    .iter()
                    .any(|candidate| wildcard_match(pattern, candidate))
            });
    }
    if let Some(principal) = statement.get("NotPrincipal") {
        let patterns = principal_patterns_from_value(principal);
        return !patterns.is_empty()
            && request_patterns.iter().all(|candidate| {
                patterns
                    .iter()
                    .all(|pattern| !wildcard_match(pattern, candidate))
            });
    }
    !principal_required
}

pub(crate) fn statement_matches_action(statement: &Value, action: &str) -> bool {
    let actions = value_to_string_vec(statement.get("Action"));
    if !actions.is_empty() {
        return actions
            .iter()
            .any(|candidate| wildcard_match(candidate, action));
    }
    let not_actions = value_to_string_vec(statement.get("NotAction"));
    if !not_actions.is_empty() {
        return not_actions
            .iter()
            .all(|candidate| !wildcard_match(candidate, action));
    }
    false
}

pub(crate) fn statement_matches_resources(statement: &Value, resources: &[String]) -> bool {
    let statement_resources = value_to_string_vec(statement.get("Resource"));
    if !statement_resources.is_empty() {
        return statement_resources.iter().any(|resource_rule| {
            resources
                .iter()
                .any(|resource| wildcard_match(resource_rule, resource))
        });
    }
    let not_resources = value_to_string_vec(statement.get("NotResource"));
    if !not_resources.is_empty() {
        return resources.iter().all(|resource| {
            not_resources
                .iter()
                .all(|resource_rule| !wildcard_match(resource_rule, resource))
        });
    }
    false
}

pub(crate) fn header_value_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

pub(crate) fn forwarded_proto(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = header_value_string(headers, "x-forwarded-proto") {
        return Some(value);
    }
    if let Some(value) = header_value_string(headers, "forwarded") {
        for segment in value.split(';') {
            let trimmed = segment.trim();
            if let Some(proto) = trimmed.strip_prefix("proto=") {
                return Some(proto.trim_matches('"').to_string());
            }
        }
    }
    if let Some(value) = header_value_string(headers, "x-forwarded-ssl") {
        return Some(if value.eq_ignore_ascii_case("on") {
            "https".to_string()
        } else {
            "http".to_string()
        });
    }
    None
}

pub(crate) fn request_uses_secure_transport(headers: &HeaderMap) -> bool {
    forwarded_proto(headers)
        .map(|proto| proto.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

pub(crate) fn request_auth_type_label(auth_type: S3AuthType) -> &'static str {
    match auth_type {
        S3AuthType::Anonymous => "REST-ANONYMOUS",
        S3AuthType::Basic => "REST-BASIC",
        S3AuthType::AwsSigV4Header => "REST-HEADER",
        S3AuthType::AwsSigV4Query => "REST-QUERY-STRING",
    }
}

pub(crate) fn request_signature_version_label(auth_type: S3AuthType) -> &'static str {
    match auth_type {
        S3AuthType::Anonymous => "ANONYMOUS",
        S3AuthType::Basic => "AWS",
        S3AuthType::AwsSigV4Header | S3AuthType::AwsSigV4Query => "AWS4-HMAC-SHA256",
    }
}

pub(crate) fn request_condition_values(
    request: &S3PolicyRequest<'_>,
) -> HashMap<String, Vec<String>> {
    let mut values = HashMap::<String, Vec<String>>::new();
    let query_pairs = request
        .uri
        .query()
        .map(parse_query_pairs)
        .unwrap_or_default();
    let now = Utc::now();

    values.insert(
        "aws:currenttime".to_string(),
        vec![now.to_rfc3339_opts(SecondsFormat::Secs, true)],
    );
    values.insert(
        "aws:epochtime".to_string(),
        vec![now.timestamp().to_string()],
    );
    values.insert(
        "aws:securetransport".to_string(),
        vec![request_uses_secure_transport(request.headers).to_string()],
    );
    values.insert(
        "s3:authtype".to_string(),
        vec![request_auth_type_label(request.auth_type).to_string()],
    );
    values.insert(
        "s3:signatureversion".to_string(),
        vec![request_signature_version_label(request.auth_type).to_string()],
    );

    if let Some(identity) = request.identity {
        let principal = identity.principal.clone().unwrap_or_default();
        values.insert("aws:userid".to_string(), vec![identity.access_key.clone()]);
        if identity.is_root {
            values.insert("aws:principaltype".to_string(), vec!["Account".to_string()]);
            values.insert(
                "aws:principalarn".to_string(),
                vec!["arn:aws:iam::rustio:root".to_string()],
            );
        } else {
            let principal_type = match identity.kind {
                S3IdentityKind::Root => "Account",
                S3IdentityKind::ServiceAccount => "User",
                S3IdentityKind::StsSession => "AssumedRole",
            };
            values.insert(
                "aws:principaltype".to_string(),
                vec![principal_type.to_string()],
            );
            if !principal.is_empty() {
                values.insert("aws:username".to_string(), vec![principal.clone()]);
                values.insert(
                    "aws:principalarn".to_string(),
                    match identity.kind {
                        S3IdentityKind::Root => vec!["arn:aws:iam::rustio:root".to_string()],
                        S3IdentityKind::ServiceAccount => vec![
                            format!("arn:aws:iam::rustio:user/{principal}"),
                            format!(
                                "arn:aws:iam::rustio:service-account/{}",
                                identity.access_key
                            ),
                        ],
                        S3IdentityKind::StsSession => {
                            let mut values = vec![format!("arn:aws:iam::rustio:user/{principal}")];
                            if let Some(arn) = sts_identity_assumed_role_arn(identity) {
                                values.insert(0, arn);
                            }
                            values
                        }
                    },
                );
            }
        }
    } else {
        values.insert(
            "aws:principaltype".to_string(),
            vec!["Anonymous".to_string()],
        );
    }

    for (key, value) in [
        (
            "s3:prefix",
            query_value_case_insensitive(&query_pairs, "prefix"),
        ),
        (
            "s3:max-keys",
            query_value_case_insensitive(&query_pairs, "max-keys"),
        ),
        (
            "s3:delimiter",
            query_value_case_insensitive(&query_pairs, "delimiter"),
        ),
        (
            "s3:versionid",
            query_value_case_insensitive(&query_pairs, "versionId"),
        ),
        (
            "s3:x-amz-copy-source",
            header_value_string(request.headers, "x-amz-copy-source"),
        ),
        (
            "s3:x-amz-server-side-encryption",
            header_value_string(request.headers, "x-amz-server-side-encryption"),
        ),
        (
            "s3:x-amz-server-side-encryption-aws-kms-key-id",
            header_value_string(
                request.headers,
                "x-amz-server-side-encryption-aws-kms-key-id",
            ),
        ),
        (
            "s3:x-amz-metadata-directive",
            header_value_string(request.headers, "x-amz-metadata-directive"),
        ),
        (
            "s3:x-amz-tagging-directive",
            header_value_string(request.headers, "x-amz-tagging-directive"),
        ),
        (
            "s3:object-lock-mode",
            header_value_string(request.headers, "x-amz-object-lock-mode"),
        ),
        (
            "s3:object-lock-legal-hold",
            header_value_string(request.headers, "x-amz-object-lock-legal-hold"),
        ),
        (
            "s3:object-lock-retain-until-date",
            header_value_string(request.headers, "x-amz-object-lock-retain-until-date"),
        ),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            values.insert(key.to_string(), vec![value]);
        }
    }

    values
}

pub(crate) fn condition_value_strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(single) => vec![single.clone()],
        Value::Number(number) => vec![number.to_string()],
        Value::Bool(flag) => vec![flag.to_string()],
        Value::Array(items) => items.iter().flat_map(condition_value_strings).collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn parse_condition_operator(raw: &str) -> (Option<&str>, &str, bool) {
    let (quantifier, rest) = if let Some(rest) = raw.strip_prefix("ForAnyValue:") {
        (Some("ForAnyValue"), rest)
    } else if let Some(rest) = raw.strip_prefix("ForAllValues:") {
        (Some("ForAllValues"), rest)
    } else {
        (None, raw)
    };
    if let Some(rest) = rest.strip_suffix("IfExists") {
        (quantifier, rest, true)
    } else {
        (quantifier, rest, false)
    }
}

pub(crate) fn parse_condition_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub(crate) fn parse_condition_number(value: &str) -> Option<f64> {
    value.trim().parse::<f64>().ok()
}

pub(crate) fn parse_condition_datetime(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            value
                .trim()
                .parse::<i64>()
                .ok()
                .and_then(|epoch| DateTime::<Utc>::from_timestamp(epoch, 0))
        })
}

pub(crate) fn evaluate_condition_value(
    operator: &str,
    actual: &str,
    expected_values: &[String],
) -> bool {
    match operator {
        "StringEquals" | "ArnEquals" => expected_values.iter().any(|expected| actual == expected),
        "StringNotEquals" | "ArnNotEquals" => {
            expected_values.iter().all(|expected| actual != expected)
        }
        "StringLike" | "ArnLike" => expected_values
            .iter()
            .any(|expected| wildcard_match(expected, actual)),
        "StringNotLike" | "ArnNotLike" => expected_values
            .iter()
            .all(|expected| !wildcard_match(expected, actual)),
        "Bool" => {
            let Some(actual) = parse_condition_bool(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_bool(expected)
                    .map(|expected| actual == expected)
                    .unwrap_or(false)
            })
        }
        "NumericEquals" => {
            let Some(actual) = parse_condition_number(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_number(expected)
                    .map(|expected| (actual - expected).abs() < f64::EPSILON)
                    .unwrap_or(false)
            })
        }
        "NumericNotEquals" => {
            let Some(actual) = parse_condition_number(actual) else {
                return false;
            };
            expected_values.iter().all(|expected| {
                parse_condition_number(expected)
                    .map(|expected| (actual - expected).abs() >= f64::EPSILON)
                    .unwrap_or(false)
            })
        }
        "NumericLessThan" => {
            let Some(actual) = parse_condition_number(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_number(expected)
                    .map(|expected| actual < expected)
                    .unwrap_or(false)
            })
        }
        "NumericLessThanEquals" => {
            let Some(actual) = parse_condition_number(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_number(expected)
                    .map(|expected| actual <= expected)
                    .unwrap_or(false)
            })
        }
        "NumericGreaterThan" => {
            let Some(actual) = parse_condition_number(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_number(expected)
                    .map(|expected| actual > expected)
                    .unwrap_or(false)
            })
        }
        "NumericGreaterThanEquals" => {
            let Some(actual) = parse_condition_number(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_number(expected)
                    .map(|expected| actual >= expected)
                    .unwrap_or(false)
            })
        }
        "DateEquals" => {
            let Some(actual) = parse_condition_datetime(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_datetime(expected)
                    .map(|expected| actual == expected)
                    .unwrap_or(false)
            })
        }
        "DateNotEquals" => {
            let Some(actual) = parse_condition_datetime(actual) else {
                return false;
            };
            expected_values.iter().all(|expected| {
                parse_condition_datetime(expected)
                    .map(|expected| actual != expected)
                    .unwrap_or(false)
            })
        }
        "DateLessThan" => {
            let Some(actual) = parse_condition_datetime(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_datetime(expected)
                    .map(|expected| actual < expected)
                    .unwrap_or(false)
            })
        }
        "DateLessThanEquals" => {
            let Some(actual) = parse_condition_datetime(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_datetime(expected)
                    .map(|expected| actual <= expected)
                    .unwrap_or(false)
            })
        }
        "DateGreaterThan" => {
            let Some(actual) = parse_condition_datetime(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_datetime(expected)
                    .map(|expected| actual > expected)
                    .unwrap_or(false)
            })
        }
        "DateGreaterThanEquals" => {
            let Some(actual) = parse_condition_datetime(actual) else {
                return false;
            };
            expected_values.iter().any(|expected| {
                parse_condition_datetime(expected)
                    .map(|expected| actual >= expected)
                    .unwrap_or(false)
            })
        }
        _ => false,
    }
}

pub(crate) fn evaluate_policy_conditions(statement: &Value, request: &S3PolicyRequest<'_>) -> bool {
    let Some(conditions) = statement.get("Condition") else {
        return true;
    };
    let Some(condition_map) = conditions.as_object() else {
        return false;
    };
    let context = request_condition_values(request);

    for (raw_operator, clauses) in condition_map {
        let Some(clause_map) = clauses.as_object() else {
            return false;
        };
        let (quantifier, operator, if_exists) = parse_condition_operator(raw_operator);
        for (raw_key, expected_value) in clause_map {
            let key = raw_key.to_ascii_lowercase();
            let expected_values = condition_value_strings(expected_value);
            if expected_values.is_empty() && operator != "Null" {
                return false;
            }
            let actual_values = context.get(&key).cloned().unwrap_or_default();
            if operator == "Null" {
                let expected = expected_values
                    .first()
                    .and_then(|value| parse_condition_bool(value))
                    .unwrap_or(false);
                if expected != actual_values.is_empty() {
                    return false;
                }
                continue;
            }
            if actual_values.is_empty() {
                if if_exists {
                    continue;
                }
                return false;
            }

            let matches = match quantifier {
                Some("ForAllValues") => actual_values
                    .iter()
                    .all(|actual| evaluate_condition_value(operator, actual, &expected_values)),
                Some("ForAnyValue") => actual_values
                    .iter()
                    .any(|actual| evaluate_condition_value(operator, actual, &expected_values)),
                _ => actual_values
                    .iter()
                    .any(|actual| evaluate_condition_value(operator, actual, &expected_values)),
            };
            if !matches {
                return false;
            }
        }
    }
    true
}

pub(crate) fn evaluate_policy_statement(
    statement: &Value,
    request: &S3PolicyRequest<'_>,
    action: &str,
    resources: &[String],
    principal_required: bool,
) -> Option<bool> {
    let effect = statement
        .get("Effect")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if !statement_matches_principal(statement, request, principal_required) {
        return None;
    }
    if !statement_matches_action(statement, action) {
        return None;
    }
    if !statement_matches_resources(statement, resources) {
        return None;
    }
    if !evaluate_policy_conditions(statement, request) {
        return None;
    }
    if effect == "deny" {
        return Some(false);
    }
    if effect == "allow" {
        return Some(true);
    }
    None
}

pub(crate) fn bucket_policy_statement_is_public(statement: &Value) -> bool {
    statement
        .get("Principal")
        .map(principal_patterns_from_value)
        .unwrap_or_default()
        .iter()
        .any(|value| value == "*")
}

pub(crate) fn collect_policy_statements(document: &Value) -> Vec<Value> {
    match document.get("Statement") {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Object(_)) => vec![document["Statement"].clone()],
        _ => Vec::new(),
    }
}

pub(crate) fn evaluate_policy_document(
    document: &Value,
    request: &S3PolicyRequest<'_>,
    action: &str,
    resources: &[String],
    principal_required: bool,
) -> PolicyDecision {
    let mut decision = PolicyDecision::default();
    for statement in collect_policy_statements(document) {
        match evaluate_policy_statement(&statement, request, action, resources, principal_required)
        {
            Some(false) => decision.record(false),
            Some(true) => decision.record(true),
            None => {}
        }
    }
    decision
}

pub(crate) fn evaluate_identity_policies(
    state: &AppState,
    request: &S3PolicyRequest<'_>,
    action: &str,
    resources: &[String],
) -> PolicyDecision {
    let mut decision = PolicyDecision::default();
    let Some(identity) = request.identity else {
        return decision;
    };
    let Some(principal) = identity.principal.as_deref() else {
        return decision;
    };
    let Ok(policies) = state.policies.try_read() else {
        return decision;
    };
    let aliases = principal_aliases(state, principal);
    for policy in policies.iter() {
        if !policy
            .attached_to
            .iter()
            .any(|attached| aliases.contains(attached))
        {
            continue;
        }
        decision.combine(evaluate_policy_document(
            &policy.document,
            request,
            action,
            resources,
            false,
        ));
    }
    if let Some(role_name) = identity
        .role_arn
        .as_deref()
        .and_then(sts_policy_name_from_role_arn)
    {
        if let Some(policy) = policies.iter().find(|policy| policy.name == role_name) {
            decision.combine(evaluate_policy_document(
                &policy.document,
                request,
                action,
                resources,
                false,
            ));
        }
    }
    decision
}

pub(crate) fn evaluate_sts_session_scope(
    state: &AppState,
    request: &S3PolicyRequest<'_>,
    action: &str,
    resources: &[String],
) -> Option<PolicyDecision> {
    let identity = request.identity?;
    if !matches!(identity.kind, S3IdentityKind::StsSession) {
        return None;
    }
    let mut scope = None::<PolicyDecision>;
    if let Some(role_name) = identity
        .role_arn
        .as_deref()
        .and_then(sts_policy_name_from_role_arn)
    {
        if let Ok(policies) = state.policies.try_read() {
            if let Some(policy) = policies.iter().find(|policy| policy.name == role_name) {
                let decision =
                    evaluate_policy_document(&policy.document, request, action, resources, false);
                scope = Some(match scope {
                    Some(current) => PolicyDecision {
                        allowed: current.allowed && decision.allowed,
                        explicit_deny: current.explicit_deny || decision.explicit_deny,
                    },
                    None => decision,
                });
            }
        }
    }
    if let Some(session_policy) = identity.session_policy.as_ref() {
        let decision = evaluate_policy_document(session_policy, request, action, resources, false);
        scope = Some(match scope {
            Some(current) => PolicyDecision {
                allowed: current.allowed && decision.allowed,
                explicit_deny: current.explicit_deny || decision.explicit_deny,
            },
            None => decision,
        });
    }
    scope
}

pub(crate) fn evaluate_bucket_policy(
    state: &AppState,
    request: &S3PolicyRequest<'_>,
    action: &str,
    resources: &[String],
) -> PolicyDecision {
    let mut decision = PolicyDecision::default();
    let (bucket, _) = parse_s3_path(request.uri.path());
    let Some(bucket) = bucket else {
        return decision;
    };
    let Ok(bucket_policies) = state.bucket_policies.try_read() else {
        return decision;
    };
    let Some(policy) = bucket_policies.get(bucket) else {
        return decision;
    };
    let public_access_block = state
        .bucket_public_access_blocks
        .try_read()
        .ok()
        .and_then(|blocks| blocks.get(bucket).cloned())
        .unwrap_or_else(default_bucket_public_access_block_config);

    for statement in collect_policy_statements(policy) {
        if request.identity.is_none()
            && bucket_policy_statement_is_public(&statement)
            && (public_access_block.block_public_policy
                || public_access_block.restrict_public_buckets)
        {
            continue;
        }
        match evaluate_policy_statement(&statement, request, action, resources, true) {
            Some(false) => decision.record(false),
            Some(true) => decision.record(true),
            None => {}
        }
    }
    decision
}

pub(crate) fn ensure_s3_policy_allowed(
    state: &AppState,
    request: &S3PolicyRequest<'_>,
) -> Result<(), Response> {
    if request.identity.is_some_and(|identity| identity.is_root) {
        return Ok(());
    }

    let action = infer_s3_action(request);
    let resource_candidates = s3_resource_candidates(request.uri.path());
    let identity_decision =
        evaluate_identity_policies(state, request, &action, &resource_candidates);
    let bucket_decision = evaluate_bucket_policy(state, request, &action, &resource_candidates);
    let sts_scope_decision =
        evaluate_sts_session_scope(state, request, &action, &resource_candidates);

    if identity_decision.explicit_deny
        || bucket_decision.explicit_deny
        || sts_scope_decision
            .as_ref()
            .map(|decision| decision.explicit_deny)
            .unwrap_or(false)
    {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Access denied by IAM policy",
            request.uri.path(),
        ));
    }
    let mut allowed = identity_decision.allowed || bucket_decision.allowed;
    if let Some(scope) = sts_scope_decision {
        allowed = allowed && scope.allowed;
    }
    if allowed {
        return Ok(());
    }
    Err(s3_error(
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "Access denied by IAM policy",
        request.uri.path(),
    ))
}

pub(crate) fn ensure_session_token(
    identity: &S3CredentialIdentity,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<(), Response> {
    let Some(expected) = identity.session_token.as_ref() else {
        return Ok(());
    };
    let token = request_security_token(headers, uri.query());
    match token {
        Some(token) if token == *expected => Ok(()),
        Some(_) => Err(s3_error(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            "The security token included in the request is invalid",
            uri.path(),
        )),
        None => Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Missing required session token",
            uri.path(),
        )),
    }
}

pub(crate) fn ensure_s3_auth(
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: Option<&[u8]>,
    state: &AppState,
) -> Result<S3AuthOutcome, Response> {
    let query_sig = parse_aws_v4_query_auth(uri.query()).map_err(|message| {
        s3_error(
            StatusCode::FORBIDDEN,
            "AuthorizationQueryParametersError",
            &message,
            uri.path(),
        )
    })?;
    if let Some(sig) = query_sig {
        let identity = resolve_s3_identity_or_error(
            state,
            &sig.access_key,
            uri.path(),
            "InvalidAccessKeyId",
            "The Access Key Id you provided does not exist in our records.",
        )?;
        ensure_session_token(&identity, headers, uri)?;

        if sig.service != "s3" {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "AuthorizationQueryParametersError",
                "Credential should be scoped to s3 service",
                uri.path(),
            ));
        }

        if !sig.amz_date.starts_with(&sig.date) {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "AuthorizationQueryParametersError",
                "X-Amz-Date does not match credential scope date",
                uri.path(),
            ));
        }

        let signed_at = chrono::NaiveDateTime::parse_from_str(&sig.amz_date, "%Y%m%dT%H%M%SZ")
            .map(|value| value.and_utc())
            .map_err(|_| {
                s3_error(
                    StatusCode::FORBIDDEN,
                    "AuthorizationQueryParametersError",
                    "X-Amz-Date must be in YYYYMMDD'T'HHMMSS'Z' format",
                    uri.path(),
                )
            })?;
        if Utc::now() > signed_at + Duration::seconds(sig.expires as i64) {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Request has expired",
                uri.path(),
            ));
        }
        // 拒绝签名时间明显在未来(超过时钟偏移容差),防止伪造未来时间变相延长有效期。
        if signed_at > Utc::now() + Duration::seconds(SIGV4_CLOCK_SKEW_SECS) {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Request signature date is too far in the future",
                uri.path(),
            ));
        }

        let payload_hash = sig
            .payload_hash
            .unwrap_or_else(|| "UNSIGNED-PAYLOAD".to_string());
        if payload_hash != "UNSIGNED-PAYLOAD"
            && !payload_hash.starts_with("STREAMING-AWS4-HMAC-SHA256")
            && payload_hash.len() == 64
            && payload_hash.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            if let Some(bytes) = body {
                let computed = sha256_hex(bytes);
                if !computed.eq_ignore_ascii_case(&payload_hash) {
                    return Err(s3_error(
                        StatusCode::BAD_REQUEST,
                        "XAmzContentSHA256Mismatch",
                        "x-amz-content-sha256 does not match request body",
                        uri.path(),
                    ));
                }
            }
        }

        let canonical_request =
            canonical_request_presigned(method, uri, headers, &sig.signed_headers, &payload_hash)
                .map_err(|message| {
                s3_error(
                    StatusCode::FORBIDDEN,
                    "AuthorizationQueryParametersError",
                    &message,
                    uri.path(),
                )
            })?;
        let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            sig.amz_date, sig.credential_scope, canonical_request_hash
        );
        let signing_key =
            build_aws_v4_signing_key(&identity.secret_key, &sig.date, &sig.region, &sig.service);
        let expected = hmac_sha256_hex(&signing_key, &string_to_sign);
        if !expected.eq_ignore_ascii_case(&sig.signature) {
            return Err(s3_error(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "The request signature we calculated does not match the signature you provided.",
                uri.path(),
            ));
        }
        ensure_s3_policy_allowed(
            state,
            &S3PolicyRequest {
                method,
                uri,
                headers,
                identity: Some(&identity),
                auth_type: S3AuthType::AwsSigV4Query,
            },
        )?;
        // 流式分叉（body=None）：presigned 声明的 payload_hash 是 64 位 hex 时回传供流式校验
        let expected_payload_sha256 = expected_payload_sha256_for_streaming(body, &payload_hash);
        return Ok(S3AuthOutcome {
            streaming_context: None,
            chunked_trailer: false,
            unsigned_chunked: false,
            expected_payload_sha256,
        });
    }

    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        ensure_s3_policy_allowed(
            state,
            &S3PolicyRequest {
                method,
                uri,
                headers,
                identity: None,
                auth_type: S3AuthType::Anonymous,
            },
        )?;
        return Ok(S3AuthOutcome::default());
    };

    if let Some(token) = auth.strip_prefix("Basic ") {
        let decoded = BASE64.decode(token).map_err(|_| {
            s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Invalid basic auth",
                "/",
            )
        })?;
        let pair = String::from_utf8(decoded).map_err(|_| {
            s3_error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "Invalid basic auth",
                "/",
            )
        })?;
        let mut split = pair.splitn(2, ':');
        let user = split.next().unwrap_or_default();
        let pass = split.next().unwrap_or_default();
        let identity = resolve_s3_identity_or_error(
            state,
            user,
            "/",
            "AccessDenied",
            "Invalid access key or secret key",
        )?;
        if crate::state::password::constant_time_eq(pass.as_bytes(), identity.secret_key.as_bytes()) {
            ensure_session_token(&identity, headers, uri)?;
            ensure_s3_policy_allowed(
                state,
                &S3PolicyRequest {
                    method,
                    uri,
                    headers,
                    identity: Some(&identity),
                    auth_type: S3AuthType::Basic,
                },
            )?;
            return Ok(S3AuthOutcome::default());
        }
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Invalid access key or secret key",
            "/",
        ));
    }

    if auth.starts_with("AWS ") {
        // SigV2(`Authorization: AWS <key>:<sig>`)不再受支持:历史实现仅解析 access key
        // 而从不校验签名,构成认证绕过。现代 SDK 默认使用 SigV4,直接拒绝该认证方式。
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "InvalidRequest",
            "AWS Signature Version 2 is not supported; use Signature Version 4",
            "/",
        ));
    }

    let sig = parse_aws_v4_authorization(auth).map_err(|message| {
        s3_error(
            StatusCode::FORBIDDEN,
            "AuthorizationHeaderMalformed",
            &message,
            uri.path(),
        )
    })?;

    let identity = resolve_s3_identity_or_error(
        state,
        &sig.access_key,
        uri.path(),
        "InvalidAccessKeyId",
        "The Access Key Id you provided does not exist in our records.",
    )?;
    ensure_session_token(&identity, headers, uri)?;

    if sig.service != "s3" {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AuthorizationHeaderMalformed",
            "Credential should be scoped to s3 service",
            uri.path(),
        ));
    }

    let Some(amz_date) = headers
        .get("x-amz-date")
        .and_then(|value| value.to_str().ok())
    else {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Missing x-amz-date header",
            uri.path(),
        ));
    };
    if !amz_date.starts_with(&sig.date) {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "AuthorizationHeaderMalformed",
            "x-amz-date does not match credential scope date",
            uri.path(),
        ));
    }
    // 请求时效窗口校验:x-amz-date 须在当前时间 ±SIGV4_CLOCK_SKEW_SECS 内,
    // 防止已签名请求在当天被无限重放(header 路径原无任何过期校验)。
    let signed_at = chrono::NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
        .map(|value| value.and_utc())
        .map_err(|_| {
            s3_error(
                StatusCode::FORBIDDEN,
                "AuthorizationHeaderMalformed",
                "x-amz-date must be in YYYYMMDD'T'HHMMSS'Z' format",
                uri.path(),
            )
        })?;
    let skew = Duration::seconds(SIGV4_CLOCK_SKEW_SECS);
    let now = Utc::now();
    if signed_at < now - skew || signed_at > now + skew {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "The difference between the request time and the server's time is too large",
            uri.path(),
        ));
    }

    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| match body {
            Some(bytes) => sha256_hex(bytes),
            None => EMPTY_SHA256.to_string(),
        });

    if payload_hash != "UNSIGNED-PAYLOAD"
        && !payload_hash.starts_with("STREAMING-AWS4-HMAC-SHA256")
        && payload_hash.len() == 64
        && payload_hash.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        if let Some(bytes) = body {
            let computed = sha256_hex(bytes);
            if !computed.eq_ignore_ascii_case(&payload_hash) {
                return Err(s3_error(
                    StatusCode::BAD_REQUEST,
                    "XAmzContentSHA256Mismatch",
                    "x-amz-content-sha256 does not match request body",
                    uri.path(),
                ));
            }
        }
    }

    let canonical_request =
        canonical_request(method, uri, headers, &sig.signed_headers, &payload_hash).map_err(
            |message| {
                s3_error(
                    StatusCode::FORBIDDEN,
                    "AuthorizationHeaderMalformed",
                    &message,
                    uri.path(),
                )
            },
        )?;
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, sig.credential_scope, canonical_request_hash
    );

    let signing_key =
        build_aws_v4_signing_key(&identity.secret_key, &sig.date, &sig.region, &sig.service);
    let expected = hmac_sha256_hex(&signing_key, &string_to_sign);
    if !expected.eq_ignore_ascii_case(&sig.signature) {
        return Err(s3_error(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
            uri.path(),
        ));
    }

    ensure_s3_policy_allowed(
        state,
        &S3PolicyRequest {
            method,
            uri,
            headers,
            identity: Some(&identity),
            auth_type: S3AuthType::AwsSigV4Header,
        },
    )?;

    // 若请求用 STREAMING-AWS4-HMAC-SHA256-PAYLOAD，回传 seed 签名上下文供 aws-chunked 解码器链式验签
    let streaming_context = if payload_hash.starts_with("STREAMING-AWS4-HMAC-SHA256") {
        Some(StreamingSigV4Context {
            seed_signature: expected,
            signing_key,
            amz_date: amz_date.to_string(),
            credential_scope: sig.credential_scope.clone(),
        })
    } else {
        None
    };

    // 流式分叉（body=None）：声明的 payload_hash 是 64 位 hex 时无法在此比对，回传供调用方流式消费后校验
    let expected_payload_sha256 = expected_payload_sha256_for_streaming(body, &payload_hash);

    Ok(S3AuthOutcome {
        streaming_context,
        chunked_trailer: payload_hash.ends_with("-TRAILER"),
        unsigned_chunked: payload_hash == "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        expected_payload_sha256,
    })
}

pub(crate) fn parse_aws_v4_authorization(value: &str) -> Result<AwsSigV4Auth, String> {
    let Some(rest) = value.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return Err("Authorization scheme must be AWS4-HMAC-SHA256".to_string());
    };

    let mut credential = None::<String>;
    let mut signed_headers = None::<String>;
    let mut signature = None::<String>;

    for pair in rest.split(',') {
        let trimmed = pair.trim();
        let mut split = trimmed.splitn(2, '=');
        let Some(key) = split.next() else {
            continue;
        };
        let Some(raw_value) = split.next() else {
            continue;
        };
        match key {
            "Credential" => credential = Some(raw_value.to_string()),
            "SignedHeaders" => signed_headers = Some(raw_value.to_string()),
            "Signature" => signature = Some(raw_value.to_string()),
            _ => {}
        }
    }

    let credential =
        credential.ok_or_else(|| "Missing Credential in authorization header".to_string())?;
    let signed_headers = signed_headers
        .ok_or_else(|| "Missing SignedHeaders in authorization header".to_string())?;
    let signature =
        signature.ok_or_else(|| "Missing Signature in authorization header".to_string())?;

    let scope = credential.split('/').collect::<Vec<_>>();
    if scope.len() != 5 || scope[4] != "aws4_request" {
        return Err("Credential scope must be access/date/region/service/aws4_request".to_string());
    }

    let signed_headers_vec = signed_headers
        .split(';')
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if signed_headers_vec.is_empty() {
        return Err("SignedHeaders cannot be empty".to_string());
    }

    Ok(AwsSigV4Auth {
        access_key: scope[0].to_string(),
        date: scope[1].to_string(),
        region: scope[2].to_string(),
        service: scope[3].to_string(),
        credential_scope: format!("{}/{}/{}/aws4_request", scope[1], scope[2], scope[3]),
        signed_headers: signed_headers_vec,
        signature,
    })
}

pub(crate) fn parse_aws_v4_query_auth(
    raw_query: Option<&str>,
) -> Result<Option<AwsSigV4QueryAuth>, String> {
    let Some(raw_query) = raw_query else {
        return Ok(None);
    };
    let pairs = parse_query_pairs(raw_query);
    let has_query_sig = pairs.iter().any(|(key, _)| {
        key.eq_ignore_ascii_case("X-Amz-Algorithm") || key.eq_ignore_ascii_case("X-Amz-Signature")
    });
    if !has_query_sig {
        return Ok(None);
    }

    let algorithm = query_value_case_insensitive(&pairs, "X-Amz-Algorithm")
        .ok_or_else(|| "Missing X-Amz-Algorithm query parameter".to_string())?;
    if !algorithm.eq_ignore_ascii_case("AWS4-HMAC-SHA256") {
        return Err("X-Amz-Algorithm must be AWS4-HMAC-SHA256".to_string());
    }

    let credential = query_value_case_insensitive(&pairs, "X-Amz-Credential")
        .ok_or_else(|| "Missing X-Amz-Credential query parameter".to_string())?;
    let amz_date = query_value_case_insensitive(&pairs, "X-Amz-Date")
        .ok_or_else(|| "Missing X-Amz-Date query parameter".to_string())?;
    let expires = query_value_case_insensitive(&pairs, "X-Amz-Expires")
        .ok_or_else(|| "Missing X-Amz-Expires query parameter".to_string())?
        .parse::<u64>()
        .map_err(|_| "X-Amz-Expires must be an integer".to_string())?;
    if expires > 604_800 {
        return Err("X-Amz-Expires must be less than or equal to 604800".to_string());
    }
    let signed_headers = query_value_case_insensitive(&pairs, "X-Amz-SignedHeaders")
        .ok_or_else(|| "Missing X-Amz-SignedHeaders query parameter".to_string())?;
    let signature = query_value_case_insensitive(&pairs, "X-Amz-Signature")
        .ok_or_else(|| "Missing X-Amz-Signature query parameter".to_string())?;
    let payload_hash = query_value_case_insensitive(&pairs, "X-Amz-Content-Sha256");

    let scope = credential.split('/').collect::<Vec<_>>();
    if scope.len() != 5 || scope[4] != "aws4_request" {
        return Err("X-Amz-Credential must be access/date/region/service/aws4_request".to_string());
    }

    let signed_headers_vec = signed_headers
        .split(';')
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if signed_headers_vec.is_empty() {
        return Err("X-Amz-SignedHeaders cannot be empty".to_string());
    }

    Ok(Some(AwsSigV4QueryAuth {
        access_key: scope[0].to_string(),
        date: scope[1].to_string(),
        region: scope[2].to_string(),
        service: scope[3].to_string(),
        credential_scope: format!("{}/{}/{}/aws4_request", scope[1], scope[2], scope[3]),
        signed_headers: signed_headers_vec,
        signature,
        amz_date,
        expires,
        payload_hash,
    }))
}

pub(crate) fn canonical_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    signed_headers: &[String],
    payload_hash: &str,
) -> Result<String, String> {
    let canonical_uri = canonical_uri(uri.path());
    let canonical_query = canonical_query(uri.query());

    let mut canonical_headers = String::new();
    for header_name in signed_headers {
        let values = headers
            .get_all(header_name.as_str())
            .iter()
            .map(|value| value.to_str().map(normalize_header_value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| format!("Invalid header value for {header_name}"))?;
        if values.is_empty() {
            return Err(format!("Missing signed header {header_name}"));
        }
        canonical_headers.push_str(header_name);
        canonical_headers.push(':');
        canonical_headers.push_str(&values.join(","));
        canonical_headers.push('\n');
    }

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers.join(";"),
        payload_hash
    ))
}

pub(crate) fn canonical_request_presigned(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    signed_headers: &[String],
    payload_hash: &str,
) -> Result<String, String> {
    let canonical_uri = canonical_uri(uri.path());
    let canonical_query = canonical_query_presigned(uri.query());
    let canonical_headers = canonical_headers(headers, signed_headers)?;

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers.join(";"),
        payload_hash
    ))
}

pub(crate) fn canonical_headers(
    headers: &HeaderMap,
    signed_headers: &[String],
) -> Result<String, String> {
    let mut canonical_headers = String::new();
    for header_name in signed_headers {
        let values = headers
            .get_all(header_name.as_str())
            .iter()
            .map(|value| value.to_str().map(normalize_header_value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| format!("Invalid header value for {header_name}"))?;
        if values.is_empty() {
            return Err(format!("Missing signed header {header_name}"));
        }
        canonical_headers.push_str(header_name);
        canonical_headers.push(':');
        canonical_headers.push_str(&values.join(","));
        canonical_headers.push('\n');
    }
    Ok(canonical_headers)
}

pub(crate) fn canonical_uri(path: &str) -> String {
    // canonical URI 必须逐字使用请求行中的原始路径：客户端（aws-sdk / minio-go 等）
    // 签名时签的就是它发到线上的那串已编码字节（如 `(` → `%28`）。若在此再做一次
    // 百分号编码，会把 `%` 二次编码成 `%25`（`%28` → `%2528`），导致任何含特殊字符
    // key 的请求签名不匹配。故直接用原始 path，仅处理空路径。
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

pub(crate) fn canonical_query(raw_query: Option<&str>) -> String {
    let Some(raw_query) = raw_query else {
        return String::new();
    };
    let mut pairs = parse_query_pairs(raw_query)
        .into_iter()
        .map(|(key, value)| {
            (
                aws_encode_query_component(&key),
                aws_encode_query_component(&value),
            )
        })
        .collect::<Vec<_>>();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut output = String::new();
    for (idx, (key, value)) in pairs.into_iter().enumerate() {
        if idx > 0 {
            output.push('&');
        }
        output.push_str(&key);
        output.push('=');
        output.push_str(&value);
    }
    output
}

pub(crate) fn canonical_query_presigned(raw_query: Option<&str>) -> String {
    let Some(raw_query) = raw_query else {
        return String::new();
    };
    let mut pairs = parse_query_pairs(raw_query)
        .into_iter()
        .filter(|(key, _)| !key.eq_ignore_ascii_case("X-Amz-Signature"))
        .map(|(key, value)| {
            (
                aws_encode_query_component(&key),
                aws_encode_query_component(&value),
            )
        })
        .collect::<Vec<_>>();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut output = String::new();
    for (idx, (key, value)) in pairs.into_iter().enumerate() {
        if idx > 0 {
            output.push('&');
        }
        output.push_str(&key);
        output.push('=');
        output.push_str(&value);
    }
    output
}

pub(crate) fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn build_aws_v4_signing_key(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date);
    let k_region = hmac_sha256(&k_date, region);
    let k_service = hmac_sha256(&k_region, service);
    hmac_sha256(&k_service, "aws4_request")
}

pub(crate) fn hmac_sha256(key: &[u8], message: &str) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC supports arbitrary key size");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn hmac_sha256_hex(key: &[u8], message: &str) -> String {
    hex::encode(hmac_sha256(key, message))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn query_has_key(raw_query: Option<&str>, key: &str) -> bool {
    raw_query
        .map(parse_query_pairs)
        .unwrap_or_default()
        .into_iter()
        .any(|(k, _)| k == key)
}

pub(crate) fn query_value(raw_query: Option<&str>, key: &str) -> Option<String> {
    raw_query
        .map(parse_query_pairs)
        .unwrap_or_default()
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
}

pub(crate) fn parse_query_pairs(raw_query: &str) -> Vec<(String, String)> {
    if raw_query.is_empty() {
        return Vec::new();
    }

    raw_query
        .split('&')
        .filter(|item| !item.is_empty())
        .map(|part| {
            let mut split = part.splitn(2, '=');
            let key_raw = split.next().unwrap_or_default();
            let value_raw = split.next().unwrap_or_default();
            let key = percent_decode_str(key_raw).decode_utf8_lossy().to_string();
            let value = percent_decode_str(value_raw)
                .decode_utf8_lossy()
                .to_string();
            (key, value)
        })
        .collect()
}

pub(crate) fn query_value_case_insensitive(
    pairs: &[(String, String)],
    key: &str,
) -> Option<String> {
    pairs
        .iter()
        .find(|(current, _)| current.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
}

pub(crate) fn parse_copy_source_header(
    value: &str,
) -> Result<(String, String, Option<String>), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("x-amz-copy-source cannot be empty".to_string());
    }

    let mut split = trimmed.splitn(2, '?');
    let raw_path = split.next().unwrap_or_default();
    let raw_query = split.next();

    let decoded_path = percent_decode_str(raw_path).decode_utf8_lossy().to_string();
    let normalized = decoded_path.trim_start_matches('/');
    let mut parts = normalized.splitn(2, '/');
    let bucket = parts.next().unwrap_or_default().trim().to_string();
    let key = parts.next().unwrap_or_default().to_string();
    if bucket.is_empty() || key.is_empty() {
        return Err(
            "x-amz-copy-source must be '/source-bucket/source-key' or 'source-bucket/source-key'"
                .to_string(),
        );
    }

    let version_id = raw_query.and_then(|query| query_value(Some(query), "versionId"));
    Ok((bucket, key, version_id))
}

pub(crate) const EMPTY_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// SigV4 请求时效容差(秒)。请求签名时间须在服务器当前时间 ±此值内,与 AWS 默认 15 分钟一致。
/// 用于 header 路径防重放与 presigned 未来时间下界。
pub(crate) const SIGV4_CLOCK_SKEW_SECS: i64 = 900;

pub(crate) const AWS_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub(crate) fn aws_encode_query_component(value: &str) -> String {
    utf8_percent_encode(value, &AWS_QUERY_ENCODE_SET).to_string()
}

pub(crate) fn multipart_upload_dir(state: &AppState, upload_id: &str) -> PathBuf {
    state.data_dir.join(".multipart").join(upload_id)
}

#[derive(Debug)]
pub(crate) enum S3ListEntry {
    Object(DiskObjectEntry),
    CommonPrefix(String),
}

#[derive(Debug)]
pub(crate) struct S3ListPage {
    pub(crate) objects: Vec<DiskObjectEntry>,
    pub(crate) common_prefixes: Vec<String>,
    pub(crate) result_count: usize,
    pub(crate) truncated: bool,
    pub(crate) next_token: Option<String>,
}

pub(crate) fn build_s3_list_page(
    objects: Vec<DiskObjectEntry>,
    prefix: &str,
    delimiter: &str,
    start_after: Option<&str>,
    max_keys: usize,
) -> S3ListPage {
    // AWS 语义：max-keys=0 返回空结果且 IsTruncated=false
    if max_keys == 0 {
        return S3ListPage {
            objects: Vec::new(),
            common_prefixes: Vec::new(),
            result_count: 0,
            truncated: false,
            next_token: None,
        };
    }
    let mut page_objects = Vec::new();
    let mut page_common_prefixes = Vec::new();
    let mut emitted_common_prefixes = HashSet::new();
    let mut result_count = 0usize;
    let mut truncated = false;
    let mut last_token = None::<String>;

    for object in objects {
        let key = object.key.clone();
        let entry = if delimiter.is_empty() {
            S3ListEntry::Object(object)
        } else {
            let rest = key.strip_prefix(prefix).unwrap_or(key.as_str());
            if let Some(idx) = rest.find(delimiter) {
                let common_prefix = format!("{prefix}{}", &rest[..idx + delimiter.len()]);
                S3ListEntry::CommonPrefix(common_prefix)
            } else {
                S3ListEntry::Object(object)
            }
        };

        let token = match &entry {
            S3ListEntry::Object(item) => item.key.clone(),
            S3ListEntry::CommonPrefix(value) => value.clone(),
        };
        if start_after
            .map(|boundary| token.as_str() <= boundary)
            .unwrap_or(false)
        {
            continue;
        }

        if let S3ListEntry::CommonPrefix(value) = &entry {
            if !emitted_common_prefixes.insert(value.clone()) {
                continue;
            }
        }

        if result_count < max_keys {
            match entry {
                S3ListEntry::Object(item) => page_objects.push(item),
                S3ListEntry::CommonPrefix(value) => page_common_prefixes.push(value),
            }
            result_count += 1;
            last_token = Some(token);
        } else {
            truncated = true;
            break;
        }
    }

    S3ListPage {
        objects: page_objects,
        common_prefixes: page_common_prefixes,
        result_count,
        truncated,
        next_token: if truncated { last_token } else { None },
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_list_objects_v2_xml(
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    key_count: usize,
    truncated: bool,
    continuation_token: Option<&str>,
    start_after: Option<&str>,
    next_continuation_token: Option<&str>,
    objects: &[DiskObjectEntry],
    common_prefixes: &[String],
    encoding_url: bool,
) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str("<Name>");
    xml.push_str(&xml_escape(bucket));
    xml.push_str("</Name><Prefix>");
    xml.push_str(&xml_escape(&s3_encode_key(prefix, encoding_url)));
    xml.push_str("</Prefix>");
    if encoding_url {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    if let Some(value) = continuation_token {
        xml.push_str("<ContinuationToken>");
        xml.push_str(&xml_escape(value));
        xml.push_str("</ContinuationToken>");
    }
    if let Some(value) = start_after {
        xml.push_str("<StartAfter>");
        xml.push_str(&xml_escape(&s3_encode_key(value, encoding_url)));
        xml.push_str("</StartAfter>");
    }
    xml.push_str("<KeyCount>");
    xml.push_str(&key_count.to_string());
    xml.push_str("</KeyCount><MaxKeys>");
    xml.push_str(&max_keys.to_string());
    xml.push_str("</MaxKeys><Delimiter>");
    xml.push_str(&xml_escape(&s3_encode_key(delimiter, encoding_url)));
    xml.push_str("</Delimiter><IsTruncated>");
    xml.push_str(if truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated>");
    if truncated {
        if let Some(value) = next_continuation_token {
            xml.push_str("<NextContinuationToken>");
            xml.push_str(&xml_escape(value));
            xml.push_str("</NextContinuationToken>");
        }
    }

    for value in common_prefixes {
        xml.push_str("<CommonPrefixes><Prefix>");
        xml.push_str(&xml_escape(&s3_encode_key(value, encoding_url)));
        xml.push_str("</Prefix></CommonPrefixes>");
    }

    for item in objects {
        xml.push_str("<Contents><Key>");
        xml.push_str(&xml_escape(&s3_encode_key(&item.key, encoding_url)));
        xml.push_str("</Key><LastModified>");
        xml.push_str(&item.last_modified);
        xml.push_str("</LastModified><ETag>\"");
        xml.push_str(&xml_escape(&item.etag));
        xml.push_str("\"</ETag><Size>");
        xml.push_str(&item.size.to_string());
        xml.push_str("</Size><StorageClass>");
        xml.push_str(&xml_escape(&item.storage_class));
        xml.push_str("</StorageClass></Contents>");
    }

    xml.push_str("</ListBucketResult>");
    xml
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_list_objects_v1_xml(
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    marker: &str,
    max_keys: usize,
    truncated: bool,
    next_marker: Option<&str>,
    objects: &[DiskObjectEntry],
    common_prefixes: &[String],
    encoding_url: bool,
) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str("<Name>");
    xml.push_str(&xml_escape(bucket));
    xml.push_str("</Name><Prefix>");
    xml.push_str(&xml_escape(&s3_encode_key(prefix, encoding_url)));
    xml.push_str("</Prefix><Marker>");
    xml.push_str(&xml_escape(&s3_encode_key(marker, encoding_url)));
    xml.push_str("</Marker><MaxKeys>");
    xml.push_str(&max_keys.to_string());
    xml.push_str("</MaxKeys><IsTruncated>");
    xml.push_str(if truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated><Delimiter>");
    xml.push_str(&xml_escape(&s3_encode_key(delimiter, encoding_url)));
    xml.push_str("</Delimiter>");
    if encoding_url {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    // AWS V1 语义：NextMarker 仅在指定 delimiter 时返回（无 delimiter 时客户端用最后一个 Key 翻页）
    if !delimiter.is_empty() {
        if let Some(next_marker) = next_marker {
            xml.push_str("<NextMarker>");
            xml.push_str(&xml_escape(&s3_encode_key(next_marker, encoding_url)));
            xml.push_str("</NextMarker>");
        }
    }

    for value in common_prefixes {
        xml.push_str("<CommonPrefixes><Prefix>");
        xml.push_str(&xml_escape(&s3_encode_key(value, encoding_url)));
        xml.push_str("</Prefix></CommonPrefixes>");
    }

    for item in objects {
        xml.push_str("<Contents><Key>");
        xml.push_str(&xml_escape(&s3_encode_key(&item.key, encoding_url)));
        xml.push_str("</Key><LastModified>");
        xml.push_str(&item.last_modified);
        xml.push_str("</LastModified><ETag>\"");
        xml.push_str(&xml_escape(&item.etag));
        xml.push_str("\"</ETag><Size>");
        xml.push_str(&item.size.to_string());
        xml.push_str("</Size><StorageClass>");
        xml.push_str(&xml_escape(&item.storage_class));
        xml.push_str("</StorageClass></Contents>");
    }

    xml.push_str("</ListBucketResult>");
    xml
}

pub(crate) fn build_bucket_cors_xml(rules: &[BucketCorsRule]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for rule in rules {
        xml.push_str("<CORSRule>");
        xml.push_str("<ID>");
        xml.push_str(&xml_escape(&rule.id));
        xml.push_str("</ID>");
        for origin in &rule.allowed_origins {
            xml.push_str("<AllowedOrigin>");
            xml.push_str(&xml_escape(origin));
            xml.push_str("</AllowedOrigin>");
        }
        for method in &rule.allowed_methods {
            xml.push_str("<AllowedMethod>");
            xml.push_str(&xml_escape(method));
            xml.push_str("</AllowedMethod>");
        }
        for header in &rule.allowed_headers {
            xml.push_str("<AllowedHeader>");
            xml.push_str(&xml_escape(header));
            xml.push_str("</AllowedHeader>");
        }
        for header in &rule.expose_headers {
            xml.push_str("<ExposeHeader>");
            xml.push_str(&xml_escape(header));
            xml.push_str("</ExposeHeader>");
        }
        if let Some(max_age_seconds) = rule.max_age_seconds {
            xml.push_str("<MaxAgeSeconds>");
            xml.push_str(&max_age_seconds.to_string());
            xml.push_str("</MaxAgeSeconds>");
        }
        xml.push_str("</CORSRule>");
    }
    xml.push_str("</CORSConfiguration>");
    xml
}

pub(crate) fn build_bucket_website_xml(config: &rustio_core::BucketWebsiteConfig) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    if let (Some(host), proto) = (&config.redirect_all_to_host, &config.redirect_all_protocol) {
        xml.push_str("<RedirectAllRequestsTo><HostName>");
        xml.push_str(&xml_escape(host));
        xml.push_str("</HostName>");
        if let Some(proto) = proto {
            xml.push_str("<Protocol>");
            xml.push_str(&xml_escape(proto));
            xml.push_str("</Protocol>");
        }
        xml.push_str("</RedirectAllRequestsTo>");
    }
    if let Some(suffix) = &config.index_document {
        xml.push_str("<IndexDocument><Suffix>");
        xml.push_str(&xml_escape(suffix));
        xml.push_str("</Suffix></IndexDocument>");
    }
    if let Some(key) = &config.error_document {
        xml.push_str("<ErrorDocument><Key>");
        xml.push_str(&xml_escape(key));
        xml.push_str("</Key></ErrorDocument>");
    }
    // RoutingRules 原样回显(存储时已抽取原始片段,serving 不执行)。
    if let Some(routing) = &config.routing_rules_xml {
        xml.push_str(routing);
    }
    xml.push_str("</WebsiteConfiguration>");
    xml
}

pub(crate) fn build_bucket_replication_xml(rules: &[rustio_core::ReplicationStatus]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Role></Role>"#,
    );
    for rule in rules {
        xml.push_str("<Rule><ID>");
        xml.push_str(&xml_escape(&rule.rule_id));
        xml.push_str("</ID><Status>");
        xml.push_str(if rule.status == "paused" {
            "Disabled"
        } else {
            "Enabled"
        });
        xml.push_str("</Status><Priority>");
        xml.push_str(&rule.priority.to_string());
        xml.push_str("</Priority>");
        // Filter:多标签或带前缀用 And 包裹;单一前缀直接 Prefix;均空则空 Filter。
        let has_prefix = rule.prefix.as_deref().is_some_and(|p| !p.is_empty());
        if !rule.tags.is_empty() || (has_prefix && rule.tags.len() > 1) {
            xml.push_str("<Filter><And>");
            if let Some(prefix) = rule.prefix.as_deref().filter(|p| !p.is_empty()) {
                xml.push_str("<Prefix>");
                xml.push_str(&xml_escape(prefix));
                xml.push_str("</Prefix>");
            }
            for tag in &rule.tags {
                xml.push_str("<Tag><Key>");
                xml.push_str(&xml_escape(&tag.key));
                xml.push_str("</Key><Value>");
                xml.push_str(&xml_escape(&tag.value));
                xml.push_str("</Value></Tag>");
            }
            xml.push_str("</And></Filter>");
        } else if let Some(prefix) = rule.prefix.as_deref().filter(|p| !p.is_empty()) {
            xml.push_str("<Filter><Prefix>");
            xml.push_str(&xml_escape(prefix));
            xml.push_str("</Prefix></Filter>");
        } else {
            xml.push_str("<Filter></Filter>");
        }
        xml.push_str("<DeleteMarkerReplication><Status>");
        xml.push_str(if rule.sync_deletes {
            "Enabled"
        } else {
            "Disabled"
        });
        xml.push_str("</Status></DeleteMarkerReplication>");
        xml.push_str("<Destination><Bucket>");
        xml.push_str(&xml_escape(&format!("arn:aws:s3:::{}", rule.target_site)));
        xml.push_str("</Bucket></Destination></Rule>");
    }
    xml.push_str("</ReplicationConfiguration>");
    xml
}

pub(crate) fn build_bucket_tagging_xml(tags: &[BucketTag]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>"#,
    );
    for tag in tags {
        xml.push_str("<Tag><Key>");
        xml.push_str(&xml_escape(&tag.key));
        xml.push_str("</Key><Value>");
        xml.push_str(&xml_escape(&tag.value));
        xml.push_str("</Value></Tag>");
    }
    xml.push_str("</TagSet></Tagging>");
    xml
}

pub(crate) fn build_object_tagging_xml(tags: &[BucketTag]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>"#,
    );
    for tag in tags {
        xml.push_str("<Tag><Key>");
        xml.push_str(&xml_escape(&tag.key));
        xml.push_str("</Key><Value>");
        xml.push_str(&xml_escape(&tag.value));
        xml.push_str("</Value></Tag>");
    }
    xml.push_str("</TagSet></Tagging>");
    xml
}

pub(crate) fn build_bucket_encryption_xml(config: &BucketEncryptionConfig) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>"#,
    );
    xml.push_str(&xml_escape(&config.algorithm));
    xml.push_str("</SSEAlgorithm>");
    if let Some(kms_key_id) = config.kms_key_id.as_deref() {
        if !kms_key_id.is_empty() {
            xml.push_str("<KMSMasterKeyID>");
            xml.push_str(&xml_escape(kms_key_id));
            xml.push_str("</KMSMasterKeyID>");
        }
    }
    xml.push_str(
        "</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
    );
    xml
}

pub(crate) fn build_bucket_object_lock_xml(config: &BucketObjectLockConfig) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>"#,
    );
    xml.push_str(&xml_escape(&config.mode));
    xml.push_str("</Mode><Days>");
    xml.push_str(&config.default_retention_days.to_string());
    xml.push_str("</Days></DefaultRetention></Rule></ObjectLockConfiguration>");
    xml
}

pub(crate) fn build_bucket_lifecycle_xml(rules: &[BucketLifecycleRule]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for rule in rules {
        xml.push_str("<Rule><ID>");
        xml.push_str(&xml_escape(&rule.id));
        xml.push_str("</ID><Status>");
        xml.push_str(&xml_escape(&rule.status));
        xml.push_str("</Status>");
        if let Some(prefix) = rule.prefix.as_deref() {
            xml.push_str("<Filter><Prefix>");
            xml.push_str(&xml_escape(prefix));
            xml.push_str("</Prefix></Filter>");
        }
        if let Some(days) = rule.expiration_days {
            xml.push_str("<Expiration><Days>");
            xml.push_str(&days.to_string());
            xml.push_str("</Days></Expiration>");
        }
        if let (Some(days), Some(tier)) = (rule.transition_days, rule.transition_tier.as_deref()) {
            xml.push_str("<Transition><Days>");
            xml.push_str(&days.to_string());
            xml.push_str("</Days><StorageClass>");
            xml.push_str(&xml_escape(tier));
            xml.push_str("</StorageClass></Transition>");
        }
        if let Some(days) = rule.noncurrent_expiration_days {
            xml.push_str("<NoncurrentVersionExpiration><NoncurrentDays>");
            xml.push_str(&days.to_string());
            xml.push_str("</NoncurrentDays></NoncurrentVersionExpiration>");
        }
        if let (Some(days), Some(tier)) = (
            rule.noncurrent_transition_days,
            rule.noncurrent_transition_tier.as_deref(),
        ) {
            xml.push_str("<NoncurrentVersionTransition><NoncurrentDays>");
            xml.push_str(&days.to_string());
            xml.push_str("</NoncurrentDays><StorageClass>");
            xml.push_str(&xml_escape(tier));
            xml.push_str("</StorageClass></NoncurrentVersionTransition>");
        }
        xml.push_str("</Rule>");
    }
    xml.push_str("</LifecycleConfiguration>");
    xml
}

pub(crate) fn build_bucket_notification_xml(rules: &[BucketNotificationRule]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for rule in rules.iter().filter(|rule| rule.enabled) {
        let (open_tag, target_tag, close_tag) = if rule.target.contains(":sns:") {
            ("TopicConfiguration", "Topic", "TopicConfiguration")
        } else if rule.target.contains(":lambda:") {
            (
                "CloudFunctionConfiguration",
                "CloudFunction",
                "CloudFunctionConfiguration",
            )
        } else {
            ("QueueConfiguration", "Queue", "QueueConfiguration")
        };
        xml.push('<');
        xml.push_str(open_tag);
        xml.push('>');
        xml.push_str("<Id>");
        xml.push_str(&xml_escape(&rule.id));
        xml.push_str("</Id>");
        xml.push('<');
        xml.push_str(target_tag);
        xml.push('>');
        xml.push_str(&xml_escape(&rule.target));
        xml.push_str("</");
        xml.push_str(target_tag);
        xml.push('>');
        xml.push_str("<Event>");
        xml.push_str(&xml_escape(&rule.event));
        xml.push_str("</Event>");
        if rule.prefix.is_some() || rule.suffix.is_some() {
            xml.push_str("<Filter><S3Key>");
            if let Some(prefix) = rule.prefix.as_deref() {
                xml.push_str("<FilterRule><Name>prefix</Name><Value>");
                xml.push_str(&xml_escape(prefix));
                xml.push_str("</Value></FilterRule>");
            }
            if let Some(suffix) = rule.suffix.as_deref() {
                xml.push_str("<FilterRule><Name>suffix</Name><Value>");
                xml.push_str(&xml_escape(suffix));
                xml.push_str("</Value></FilterRule>");
            }
            xml.push_str("</S3Key></Filter>");
        }
        xml.push_str("</");
        xml.push_str(close_tag);
        xml.push('>');
    }
    xml.push_str("</NotificationConfiguration>");
    xml
}

pub(crate) fn build_bucket_acl_xml(bucket: &str, acl: &str) -> String {
    let (grantee_uri, permission) = match acl {
        "public-read" => (
            Some("http://acs.amazonaws.com/groups/global/AllUsers"),
            Some("READ"),
        ),
        "public-read-write" => (
            Some("http://acs.amazonaws.com/groups/global/AllUsers"),
            Some("FULL_CONTROL"),
        ),
        "authenticated-read" => (
            Some("http://acs.amazonaws.com/groups/global/AuthenticatedUsers"),
            Some("READ"),
        ),
        _ => (None, None),
    };

    let owner_id = sha256_hex(bucket.as_bytes());
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>"#,
    );
    xml.push_str(&xml_escape(&owner_id));
    xml.push_str("</ID><DisplayName>rustio</DisplayName></Owner><AccessControlList>");
    xml.push_str("<Grant><Grantee xsi:type=\"CanonicalUser\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><ID>");
    xml.push_str(&xml_escape(&owner_id));
    xml.push_str("</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>");
    if let (Some(uri), Some(permission)) = (grantee_uri, permission) {
        xml.push_str("<Grant><Grantee xsi:type=\"Group\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><URI>");
        xml.push_str(&xml_escape(uri));
        xml.push_str("</URI></Grantee><Permission>");
        xml.push_str(permission);
        xml.push_str("</Permission></Grant>");
    }
    xml.push_str("</AccessControlList></AccessControlPolicy>");
    xml
}

pub(crate) fn build_bucket_public_access_block_xml(
    config: &BucketPublicAccessBlockConfig,
) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>{}</BlockPublicAcls><IgnorePublicAcls>{}</IgnorePublicAcls><BlockPublicPolicy>{}</BlockPublicPolicy><RestrictPublicBuckets>{}</RestrictPublicBuckets></PublicAccessBlockConfiguration>"#,
        if config.block_public_acls {
            "true"
        } else {
            "false"
        },
        if config.ignore_public_acls {
            "true"
        } else {
            "false"
        },
        if config.block_public_policy {
            "true"
        } else {
            "false"
        },
        if config.restrict_public_buckets {
            "true"
        } else {
            "false"
        },
    )
}

pub(crate) fn build_bucket_accelerate_xml(config: &BucketAccelerateConfig) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><AccelerateConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{}</Status></AccelerateConfiguration>"#,
        if config.enabled { "Enabled" } else { "Suspended" },
    )
}

pub(crate) fn build_bucket_logging_xml(config: &BucketLoggingConfig) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>{}</TargetBucket><TargetPrefix>{}</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"#,
        xml_escape(&config.target_bucket),
        xml_escape(&config.target_prefix),
    )
}

pub(crate) fn build_bucket_request_payment_xml(config: &BucketRequestPaymentConfig) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Payer>{}</Payer></RequestPaymentConfiguration>"#,
        xml_escape(&config.payer),
    )
}

pub(crate) fn build_bucket_analytics_xml(configs: &[BucketAnalyticsConfig]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAnalyticsConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for cfg in configs {
        xml.push_str("<AnalyticsConfiguration><Id>");
        xml.push_str(&xml_escape(&cfg.id));
        xml.push_str("</Id><Filter><Prefix>");
        xml.push_str(&xml_escape(cfg.prefix.as_deref().unwrap_or("")));
        xml.push_str("</Prefix></Filter></AnalyticsConfiguration>");
    }
    xml.push_str("<IsTruncated>false</IsTruncated></ListAnalyticsConfiguration>");
    xml
}

pub(crate) fn build_bucket_metrics_xml(configs: &[BucketMetricsConfig]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListMetricsConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for cfg in configs {
        xml.push_str("<MetricsConfiguration><Id>");
        xml.push_str(&xml_escape(&cfg.id));
        xml.push_str("</Id><Filter><Prefix>");
        xml.push_str(&xml_escape(cfg.prefix.as_deref().unwrap_or("")));
        xml.push_str("</Prefix></Filter></MetricsConfiguration>");
    }
    xml.push_str("<IsTruncated>false</IsTruncated></ListMetricsConfiguration>");
    xml
}

pub(crate) fn build_bucket_inventory_xml(configs: &[BucketInventoryConfig]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListInventoryConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for cfg in configs {
        xml.push_str("<InventoryConfiguration><Id>");
        xml.push_str(&xml_escape(&cfg.id));
        xml.push_str("</Id><Destination><S3BucketDestination><Bucket>arn:aws:s3:::");
        xml.push_str(&xml_escape(&cfg.destination_bucket));
        xml.push_str("</Bucket><Prefix>");
        xml.push_str(&xml_escape(cfg.destination_prefix.as_deref().unwrap_or("")));
        xml.push_str("</Prefix></S3BucketDestination></Destination><IsEnabled>true</IsEnabled><Filter><Prefix>");
        xml.push_str(&xml_escape(cfg.prefix.as_deref().unwrap_or("")));
        xml.push_str("</Prefix></Filter><Schedule><Frequency>");
        xml.push_str(&xml_escape(&cfg.frequency));
        xml.push_str("</Frequency></Schedule><IncludedObjectVersions>");
        xml.push_str(&xml_escape(&cfg.included_object_versions));
        xml.push_str("</IncludedObjectVersions></InventoryConfiguration>");
    }
    xml.push_str("<IsTruncated>false</IsTruncated></ListInventoryConfiguration>");
    xml
}

pub(crate) fn build_torrent_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?><Torrent xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated></Torrent>"#.to_string()
}

pub(crate) fn build_delete_objects_result_xml(
    deleted: &[S3DeleteObjectResultEntry],
    errors: &[S3DeleteObjectErrorEntry],
    quiet: bool,
) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );

    if !quiet {
        for item in deleted {
            xml.push_str("<Deleted><Key>");
            xml.push_str(&xml_escape(&item.key));
            xml.push_str("</Key>");
            if let Some(version_id) = item.version_id.as_deref() {
                xml.push_str("<VersionId>");
                xml.push_str(&xml_escape(version_id));
                xml.push_str("</VersionId>");
            }
            if item.delete_marker {
                xml.push_str("<DeleteMarker>true</DeleteMarker>");
            }
            if let Some(delete_marker_version_id) = item.delete_marker_version_id.as_deref() {
                xml.push_str("<DeleteMarkerVersionId>");
                xml.push_str(&xml_escape(delete_marker_version_id));
                xml.push_str("</DeleteMarkerVersionId>");
            }
            xml.push_str("</Deleted>");
        }
    }

    for item in errors {
        xml.push_str("<Error><Key>");
        xml.push_str(&xml_escape(&item.key));
        xml.push_str("</Key>");
        if let Some(version_id) = item.version_id.as_deref() {
            xml.push_str("<VersionId>");
            xml.push_str(&xml_escape(version_id));
            xml.push_str("</VersionId>");
        }
        xml.push_str("<Code>");
        xml.push_str(&xml_escape(&item.code));
        xml.push_str("</Code><Message>");
        let message = bilingual_s3_message(&item.code, &item.message);
        xml.push_str(&xml_escape(&message));
        xml.push_str("</Message></Error>");
    }

    xml.push_str("</DeleteResult>");
    xml
}

pub(crate) fn collect_json_files(dir: &FsPath, output: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_json_files(&path, output)?;
            continue;
        }
        if metadata.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            output.push(path);
        }
    }
    Ok(())
}

