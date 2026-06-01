//! STS（安全令牌服务）兼容接口：AssumeRole 系列与根路径 STS 分发。

use super::*;

pub(crate) fn bilingual_sts_message(code: &str, message: &str) -> String {
    if message.contains(" / ") {
        return message.to_string();
    }
    let (zh, en_default) = match code {
        "AccessDenied" => ("访问被拒绝", "access denied"),
        "InvalidAction" => ("STS 动作无效", "invalid sts action"),
        "InvalidIdentityToken" => ("身份令牌无效", "invalid identity token"),
        "InvalidParameterValue" => ("参数值无效", "invalid parameter value"),
        "MalformedPolicyDocument" => ("会话策略文档格式错误", "malformed session policy document"),
        "MissingParameter" => ("缺少参数", "missing parameter"),
        _ => ("STS 请求失败", "sts request failed"),
    };
    let text = message.trim();
    if text.is_empty() {
        return format!("{zh} / {en_default}");
    }
    if text.contains(" / ") {
        return text.to_string();
    }
    format!("{zh} / {text}")
}

pub(crate) fn sts_xml_response(status: StatusCode, body: String) -> Response {
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

pub(crate) fn sts_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{}</RequestId></ErrorResponse>"#,
        xml_escape(code),
        xml_escape(&bilingual_sts_message(code, message)),
        Uuid::new_v4()
    );
    sts_xml_response(status, body)
}

pub(crate) fn decode_form_component(raw: &str) -> String {
    percent_decode_str(&raw.replace('+', " "))
        .decode_utf8_lossy()
        .to_string()
}

pub(crate) fn parse_form_encoded_pairs(raw_query: &str) -> Vec<(String, String)> {
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
            (
                decode_form_component(key_raw),
                decode_form_component(value_raw),
            )
        })
        .collect()
}

pub(crate) fn sts_request_pairs(
    uri: &Uri,
    body: Option<&[u8]>,
) -> Result<Vec<(String, String)>, Response> {
    let mut pairs = Vec::new();
    if let Some(body) = body.filter(|bytes| !bytes.is_empty()) {
        let body_text = std::str::from_utf8(body).map_err(|_| {
            sts_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "表单请求体必须是 UTF-8 / sts form body must be utf-8",
            )
        })?;
        pairs.extend(parse_form_encoded_pairs(body_text));
    }
    if let Some(query) = uri.query() {
        pairs.extend(parse_query_pairs(query));
    }
    Ok(pairs)
}

pub(crate) fn sts_action_supported(action: &str) -> bool {
    action.eq_ignore_ascii_case("AssumeRoleWithWebIdentity")
        || action.eq_ignore_ascii_case("AssumeRoleWithCustomToken")
        || action.eq_ignore_ascii_case("AssumeRoleWithLDAPIdentity")
}

pub(crate) fn require_sts_param(
    pairs: &[(String, String)],
    key: &str,
    label: &str,
) -> Result<String, Response> {
    query_value_case_insensitive(pairs, key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            sts_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                &format!("{label} 不能为空 / {key} cannot be empty"),
            )
        })
}

pub(crate) fn validate_sts_version(pairs: &[(String, String)]) -> Result<(), Response> {
    let version = require_sts_param(pairs, "Version", "Version")?;
    if version != "2011-06-15" {
        return Err(sts_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "Version 必须为 2011-06-15 / version must be 2011-06-15",
        ));
    }
    Ok(())
}

pub(crate) fn sts_duration_seconds(pairs: &[(String, String)]) -> Result<i64, Response> {
    let duration = query_value_case_insensitive(pairs, "DurationSeconds")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<i64>().map_err(|_| {
                sts_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "DurationSeconds 必须是整数 / duration seconds must be an integer",
                )
            })
        })
        .transpose()?
        .unwrap_or(3600);
    if !(900..=7 * 24 * 3600).contains(&duration) {
        return Err(sts_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "DurationSeconds 必须在 900 到 604800 之间 / duration seconds must be between 900 and 604800",
        ));
    }
    Ok(duration)
}

pub(crate) fn sts_session_policy_from_pairs(
    pairs: &[(String, String)],
) -> Result<Option<Value>, Response> {
    parse_sts_session_policy_string(
        query_value_case_insensitive(pairs, "Policy").as_deref(),
        "policy",
    )
    .map_err(|err| {
        sts_error(
            StatusCode::BAD_REQUEST,
            "MalformedPolicyDocument",
            &err.message,
        )
    })
}

pub(crate) fn sts_role_name(session: &rustio_core::StsSession) -> String {
    session
        .role_arn
        .as_deref()
        .and_then(sts_policy_name_from_role_arn)
        .unwrap_or_else(|| sanitize_sts_session_component(&session.principal, "session"))
}

pub(crate) fn sts_assumed_role_arn(session: &rustio_core::StsSession) -> String {
    let role_name = sts_role_name(session);
    let session_name = session
        .session_name
        .clone()
        .unwrap_or_else(|| sanitize_sts_session_component(&session.principal, "session"));
    format!("arn:aws:sts::rustio:assumed-role/{role_name}/{session_name}")
}

pub(crate) fn sts_assumed_role_id(session: &rustio_core::StsSession) -> String {
    let role_name = sts_role_name(session);
    let session_name = session
        .session_name
        .clone()
        .unwrap_or_else(|| sanitize_sts_session_component(&session.principal, "session"));
    format!("{role_name}:{session_name}")
}

pub(crate) fn sts_identity_assumed_role_arn(identity: &S3CredentialIdentity) -> Option<String> {
    let principal = identity.principal.as_deref().unwrap_or_default();
    if principal.is_empty() {
        return None;
    }
    let role_name = identity
        .role_arn
        .as_deref()
        .and_then(sts_policy_name_from_role_arn)
        .unwrap_or_else(|| sanitize_sts_session_component(principal, "session"));
    let session_name = identity
        .session_name
        .clone()
        .unwrap_or_else(|| sanitize_sts_session_component(principal, "session"));
    Some(format!(
        "arn:aws:sts::rustio:assumed-role/{role_name}/{session_name}"
    ))
}

pub(crate) fn build_sts_assume_role_response(
    response_name: &str,
    result_name: &str,
    session: &rustio_core::StsSession,
    provider: Option<&str>,
    subject_tag: Option<&str>,
    subject: Option<&str>,
    audience: Option<&str>,
) -> Response {
    let expiration = session
        .expires_at
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut extra = String::new();
    if let Some(provider) = provider.filter(|value| !value.trim().is_empty()) {
        extra.push_str("<Provider>");
        extra.push_str(&xml_escape(provider));
        extra.push_str("</Provider>");
    }
    if let Some(subject) = subject.filter(|value| !value.trim().is_empty()) {
        let subject_tag = subject_tag.unwrap_or("Subject");
        extra.push('<');
        extra.push_str(subject_tag);
        extra.push('>');
        extra.push_str(&xml_escape(subject));
        extra.push_str("</");
        extra.push_str(subject_tag);
        extra.push('>');
    }
    if let Some(audience) = audience.filter(|value| !value.trim().is_empty()) {
        extra.push_str("<Audience>");
        extra.push_str(&xml_escape(audience));
        extra.push_str("</Audience>");
    }
    let packed_policy_size = session
        .session_policy
        .as_ref()
        .and_then(|policy| serde_json::to_string(policy).ok())
        .map(|text| ((text.len() as f32 / 2048.0) * 100.0).ceil() as u32)
        .unwrap_or(0)
        .min(100);
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><{response_name} xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><{result_name}><AssumedRoleUser><Arn>{arn}</Arn><AssumedRoleId>{assumed_role_id}</AssumedRoleId></AssumedRoleUser><Credentials><AccessKeyId>{access_key}</AccessKeyId><SecretAccessKey>{secret_key}</SecretAccessKey><SessionToken>{session_token}</SessionToken><Expiration>{expiration}</Expiration></Credentials><PackedPolicySize>{packed_policy_size}</PackedPolicySize>{extra}</{result_name}><ResponseMetadata><RequestId>{request_id}</RequestId></ResponseMetadata></{response_name}>"#,
        response_name = response_name,
        result_name = result_name,
        arn = xml_escape(&sts_assumed_role_arn(session)),
        assumed_role_id = xml_escape(&sts_assumed_role_id(session)),
        access_key = xml_escape(&session.access_key),
        secret_key = xml_escape(&session.secret_key),
        session_token = xml_escape(&session.session_token),
        expiration = xml_escape(&expiration),
        packed_policy_size = packed_policy_size,
        extra = extra,
        request_id = Uuid::new_v4(),
    );
    sts_xml_response(StatusCode::OK, body)
}

pub(crate) async fn handle_assume_role_with_web_identity(
    state: Arc<AppState>,
    pairs: &[(String, String)],
) -> Response {
    if let Err(response) = validate_sts_version(pairs) {
        return response;
    }
    let duration_seconds = match sts_duration_seconds(pairs) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let web_identity_token = match require_sts_param(pairs, "WebIdentityToken", "WebIdentityToken")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let role_arn =
        normalize_sts_role_arn(query_value_case_insensitive(pairs, "RoleArn").as_deref());
    let session_name = query_value_case_insensitive(pairs, "RoleSessionName");
    let session_policy = match sts_session_policy_from_pairs(pairs) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let security = state.security.read().await.clone();
    let profile = match authenticate_oidc_token(&security, &web_identity_token, None).await {
        Ok(profile) => profile,
        Err(err) => return sts_error(StatusCode::FORBIDDEN, "InvalidIdentityToken", &err.message),
    };
    if let Err(err) = sync_external_identity_profile(&state, &profile).await {
        return sts_error(StatusCode::FORBIDDEN, "AccessDenied", &err.message);
    }

    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    let session = match issue_sts_session(
        &state,
        &profile.username,
        duration_seconds,
        "oidc",
        session_name,
        role_arn,
        session_policy,
        profile.subject.clone(),
        profile.audience.clone(),
    )
    .await
    {
        Ok(session) => session,
        Err(err) => {
            let code = if err.code == "bad_request" {
                "InvalidParameterValue"
            } else {
                "AccessDenied"
            };
            return sts_error(StatusCode::BAD_REQUEST, code, &err.message);
        }
    };
    if let Err(err) =
        commit_iam_runtime_change(state.as_ref(), "iam-sts-web-identity", rollback).await
    {
        return sts_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AccessDenied",
            &err.message,
        );
    }
    state
        .append_runtime_audit(
            &profile.username,
            "iam.sts_session.assume_role_with_web_identity",
            &format!("iam/sts-session/{}", session.session_id),
            "success",
            None,
            json!({
                "provider": session.provider,
                "principal": session.principal,
                "role": profile.role.clone(),
                "groups": profile.groups.clone(),
                "role_arn": session.role_arn,
                "session_name": session.session_name,
                "has_session_policy": session.session_policy.is_some()
            }),
        )
        .await;
    build_sts_assume_role_response(
        "AssumeRoleWithWebIdentityResponse",
        "AssumeRoleWithWebIdentityResult",
        &session,
        Some("web-identity"),
        Some("SubjectFromWebIdentityToken"),
        profile.subject.as_deref(),
        profile.audience.as_deref(),
    )
}

pub(crate) async fn handle_assume_role_with_custom_token(
    state: Arc<AppState>,
    pairs: &[(String, String)],
) -> Response {
    if let Err(response) = validate_sts_version(pairs) {
        return response;
    }
    let duration_seconds = match sts_duration_seconds(pairs) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let custom_token = match require_sts_param(pairs, "Token", "Token") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let session_policy = match sts_session_policy_from_pairs(pairs) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let role_arn =
        normalize_sts_role_arn(query_value_case_insensitive(pairs, "RoleArn").as_deref());
    let session_name = query_value_case_insensitive(pairs, "RoleSessionName");
    let provider_name = query_value_case_insensitive(pairs, "ProviderName")
        .map(|value| sanitize_sts_session_component(&value, "custom-token"));
    let overrides = ExternalIdentityClaimOverrides {
        username_claim: query_value_case_insensitive(pairs, "UsernameClaim"),
        groups_claim: query_value_case_insensitive(pairs, "GroupsClaim"),
        role_claim: query_value_case_insensitive(pairs, "RoleClaim"),
        default_role: query_value_case_insensitive(pairs, "DefaultRole"),
        group_role_map: query_value_case_insensitive(pairs, "GroupRoleMap"),
        display_name_claim: query_value_case_insensitive(pairs, "DisplayNameClaim"),
        subject_claim: query_value_case_insensitive(pairs, "SubjectClaim"),
        audience_claim: query_value_case_insensitive(pairs, "AudienceClaim"),
        provider_name: provider_name.clone(),
    };
    let security = state.security.read().await.clone();
    let claims = match decode_oidc_claims(&security, &custom_token, None).await {
        Ok(value) => value,
        Err(err) => return sts_error(StatusCode::FORBIDDEN, "InvalidIdentityToken", &err.message),
    };
    let profile = match external_identity_profile_from_oidc_claims(&security, &claims, &overrides) {
        Ok(value) => value,
        Err(err) => return sts_error(StatusCode::FORBIDDEN, "InvalidIdentityToken", &err.message),
    };
    if let Err(err) = sync_external_identity_profile(&state, &profile).await {
        return sts_error(StatusCode::FORBIDDEN, "AccessDenied", &err.message);
    }
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    let session = match issue_sts_session(
        &state,
        &profile.username,
        duration_seconds,
        &profile.provider,
        session_name,
        role_arn,
        session_policy,
        profile.subject.clone(),
        profile.audience.clone(),
    )
    .await
    {
        Ok(session) => session,
        Err(err) => {
            let code = if err.code == "bad_request" {
                "InvalidParameterValue"
            } else {
                "AccessDenied"
            };
            return sts_error(StatusCode::BAD_REQUEST, code, &err.message);
        }
    };
    if let Err(err) =
        commit_iam_runtime_change(state.as_ref(), "iam-sts-custom-token", rollback).await
    {
        return sts_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AccessDenied",
            &err.message,
        );
    }
    state
        .append_runtime_audit(
            &profile.username,
            "iam.sts_session.assume_role_with_custom_token",
            &format!("iam/sts-session/{}", session.session_id),
            "success",
            None,
            json!({
                "provider": session.provider,
                "principal": session.principal,
                "role": profile.role.clone(),
                "groups": profile.groups.clone(),
                "role_arn": session.role_arn,
                "session_name": session.session_name,
                "has_session_policy": session.session_policy.is_some(),
                "username_claim": overrides.username_claim,
                "groups_claim": overrides.groups_claim,
                "role_claim": overrides.role_claim,
            }),
        )
        .await;
    build_sts_assume_role_response(
        "AssumeRoleWithCustomTokenResponse",
        "AssumeRoleWithCustomTokenResult",
        &session,
        Some(profile.provider.as_str()),
        Some("SubjectFromCustomToken"),
        profile.subject.as_deref(),
        profile.audience.as_deref(),
    )
}

pub(crate) async fn handle_assume_role_with_ldap_identity(
    state: Arc<AppState>,
    pairs: &[(String, String)],
) -> Response {
    if let Err(response) = validate_sts_version(pairs) {
        return response;
    }
    let duration_seconds = match sts_duration_seconds(pairs) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(config_name) = query_value_case_insensitive(pairs, "LDAPConfigName")
        .or_else(|| query_value_case_insensitive(pairs, "ConfigName"))
        .filter(|value| !value.trim().is_empty())
    {
        if config_name != "_" {
            return sts_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "当前仅支持默认 LDAP 配置 '_' / only default ldap config '_' is supported",
            );
        }
    }
    let username = match require_sts_param(pairs, "LDAPUsername", "LDAPUsername") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let password = match require_sts_param(pairs, "LDAPPassword", "LDAPPassword") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let session_policy = match sts_session_policy_from_pairs(pairs) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let security = state.security.read().await.clone();
    let login_request = LoginRequest {
        username: username.clone(),
        password,
        provider: Some("ldap".to_string()),
        id_token: None,
    };
    let profile = match authenticate_ldap_identity(&security, &login_request).await {
        Ok(profile) => profile,
        Err(err) => return sts_error(StatusCode::FORBIDDEN, "AccessDenied", &err.message),
    };
    if let Err(err) = sync_external_identity_profile(&state, &profile).await {
        return sts_error(StatusCode::FORBIDDEN, "AccessDenied", &err.message);
    }
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    let session = match issue_sts_session(
        &state,
        &profile.username,
        duration_seconds,
        "ldap",
        query_value_case_insensitive(pairs, "RoleSessionName"),
        None,
        session_policy,
        Some(profile.username.clone()),
        None,
    )
    .await
    {
        Ok(session) => session,
        Err(err) => {
            return sts_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                &err.message,
            )
        }
    };
    if let Err(err) =
        commit_iam_runtime_change(state.as_ref(), "iam-sts-ldap-identity", rollback).await
    {
        return sts_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AccessDenied",
            &err.message,
        );
    }
    state
        .append_runtime_audit(
            &profile.username,
            "iam.sts_session.assume_role_with_ldap_identity",
            &format!("iam/sts-session/{}", session.session_id),
            "success",
            None,
            json!({
                "provider": session.provider,
                "principal": session.principal,
                "role": profile.role.clone(),
                "groups": profile.groups.clone(),
                "session_name": session.session_name,
                "has_session_policy": session.session_policy.is_some()
            }),
        )
        .await;
    build_sts_assume_role_response(
        "AssumeRoleWithLDAPIdentityResponse",
        "AssumeRoleWithLDAPIdentityResult",
        &session,
        Some("ldap"),
        Some("LDAPUsername"),
        Some(&profile.username),
        None,
    )
}

pub(crate) async fn handle_root_sts_request(
    state: Arc<AppState>,
    method: &Method,
    uri: &Uri,
    body: Option<&[u8]>,
) -> Option<Response> {
    if !matches!(method, &Method::GET | &Method::POST) {
        return None;
    }
    let pairs = match sts_request_pairs(uri, body) {
        Ok(pairs) => pairs,
        Err(response) => return Some(response),
    };
    let action = query_value_case_insensitive(&pairs, "Action")?;
    if !sts_action_supported(&action) {
        return Some(sts_error(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            &format!("不支持的 STS 动作 / unsupported sts action: {action}"),
        ));
    }
    Some(
        if action.eq_ignore_ascii_case("AssumeRoleWithWebIdentity") {
            handle_assume_role_with_web_identity(state, &pairs).await
        } else if action.eq_ignore_ascii_case("AssumeRoleWithCustomToken") {
            handle_assume_role_with_custom_token(state, &pairs).await
        } else {
            handle_assume_role_with_ldap_identity(state, &pairs).await
        },
    )
}
