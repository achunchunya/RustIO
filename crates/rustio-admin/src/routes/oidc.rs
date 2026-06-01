//! OIDC 浏览器登录流程

use super::*;

pub(crate) fn env_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn normalize_role_name(role: &str) -> Option<String> {
    match role.trim().to_ascii_lowercase().as_str() {
        "admin" => Some("admin".to_string()),
        "operator" => Some("operator".to_string()),
        "auditor" => Some("auditor".to_string()),
        "viewer" => Some("viewer".to_string()),
        _ => None,
    }
}

pub(crate) type RoleMappings = Vec<(String, String)>;

pub(crate) fn parse_role_mapping(raw: Option<String>) -> RoleMappings {
    raw.unwrap_or_default()
        .split([',', ';'])
        .filter_map(|entry| {
            let mut split = entry.splitn(2, '=');
            let key = split.next()?.trim().to_ascii_lowercase();
            let value = normalize_role_name(split.next()?.trim())?;
            (!key.is_empty()).then_some((key, value))
        })
        .collect()
}

pub(crate) fn resolve_external_role(
    explicit_role: Option<String>,
    groups: &[String],
    mappings: &RoleMappings,
    default_role: &str,
) -> String {
    if let Some(role) = explicit_role.as_deref().and_then(normalize_role_name) {
        return role;
    }
    let normalized_groups = groups
        .iter()
        .map(|group| group.trim().to_ascii_lowercase())
        .filter(|group| !group.is_empty())
        .collect::<HashSet<_>>();
    for (group_name, role) in mappings {
        if normalized_groups.contains(group_name) {
            return role.clone();
        }
    }
    normalize_role_name(default_role).unwrap_or_else(|| "viewer".to_string())
}

pub(crate) fn json_value_by_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

pub(crate) fn json_string_by_path(value: &Value, path: &str) -> Option<String> {
    match json_value_by_path(value, path) {
        Some(Value::String(text)) => Some(text.trim().to_string()).filter(|text| !text.is_empty()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(flag)) => Some(flag.to_string()),
        _ => None,
    }
}

pub(crate) fn json_string_list_by_path(value: &Value, path: &str) -> Vec<String> {
    match json_value_by_path(value, path) {
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            (!trimmed.is_empty())
                .then_some(trimmed.to_string())
                .into_iter()
                .collect()
        }
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(text) => Some(text.trim().to_string()),
                Value::Number(number) => Some(number.to_string()),
                _ => None,
            })
            .filter(|item| !item.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn parse_algorithm_name(value: &str) -> Option<Algorithm> {
    match value.trim().to_ascii_uppercase().as_str() {
        "HS256" => Some(Algorithm::HS256),
        "HS384" => Some(Algorithm::HS384),
        "HS512" => Some(Algorithm::HS512),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EDDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

pub(crate) fn configured_text(configured: &str, env_key: &str) -> Option<String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        return Some(configured.to_string());
    }
    env_trimmed(env_key)
}

pub(crate) fn configured_text_env_first(configured: &str, env_key: &str) -> Option<String> {
    env_trimmed(env_key).or_else(|| {
        let configured = configured.trim();
        (!configured.is_empty()).then_some(configured.to_string())
    })
}

pub(crate) fn configured_or_default_env_first(
    configured: &str,
    env_key: &str,
    default: &str,
) -> String {
    configured_text_env_first(configured, env_key).unwrap_or_else(|| default.to_string())
}

pub(crate) fn oidc_discovery_url(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.oidc_discovery_url, "RUSTIO_OIDC_DISCOVERY_URL").or_else(|| {
        configured_text(&security.oidc_issuer, "RUSTIO_OIDC_ISSUER").map(|issuer| {
            format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            )
        })
    })
}

pub(crate) fn oidc_jwks_url_override(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.oidc_jwks_url, "RUSTIO_OIDC_JWKS_URL")
}

pub(crate) fn oidc_expected_issuer(
    security: &rustio_core::SecurityConfig,
    discovery: &OidcDiscoveryDocument,
) -> String {
    configured_text(&security.oidc_issuer, "RUSTIO_OIDC_ISSUER")
        .unwrap_or_else(|| discovery.issuer.clone())
}

pub(crate) fn oidc_client_id(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.oidc_client_id, "RUSTIO_OIDC_CLIENT_ID")
}

pub(crate) fn oidc_client_secret() -> Option<String> {
    env_trimmed("RUSTIO_OIDC_CLIENT_SECRET")
}

pub(crate) fn oidc_missing_requirements(security: &rustio_core::SecurityConfig) -> Vec<String> {
    let mut missing = Vec::new();
    if oidc_discovery_url(security).is_none() {
        missing.push("oidc_discovery_url".to_string());
    }
    if oidc_client_id(security).is_none() {
        missing.push("oidc_client_id".to_string());
    }
    missing
}

pub(crate) fn ensure_oidc_login_available(
    security: &rustio_core::SecurityConfig,
) -> Result<Vec<String>, AppError> {
    if !security.oidc_enabled {
        return Err(AppError::forbidden(
            "OIDC 登录未启用 / oidc login is disabled",
        ));
    }
    let missing = oidc_missing_requirements(security);
    if !missing.is_empty() {
        let joined = missing.join(", ");
        return Err(AppError::forbidden(format!(
            "OIDC 登录未完成配置，缺少 {} / oidc login is not fully configured, missing {}",
            joined, joined
        )));
    }
    Ok(missing)
}

pub(crate) fn oidc_browser_scopes() -> String {
    env_trimmed("RUSTIO_OIDC_SCOPES").unwrap_or_else(|| "openid profile email".to_string())
}

pub(crate) fn oidc_username_claim(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(
        &security.oidc_username_claim,
        "RUSTIO_OIDC_USERNAME_CLAIM",
        "preferred_username",
    )
}

pub(crate) fn oidc_groups_claim(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(
        &security.oidc_groups_claim,
        "RUSTIO_OIDC_GROUPS_CLAIM",
        "groups",
    )
}

pub(crate) fn oidc_role_claim(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(&security.oidc_role_claim, "RUSTIO_OIDC_ROLE_CLAIM", "role")
}

pub(crate) fn oidc_default_role(security: &rustio_core::SecurityConfig) -> String {
    configured_text_env_first(&security.oidc_default_role, "RUSTIO_OIDC_DEFAULT_ROLE")
        .and_then(|role| normalize_role_name(&role))
        .unwrap_or_else(|| "viewer".to_string())
}

pub(crate) fn oidc_role_mapping(security: &rustio_core::SecurityConfig) -> RoleMappings {
    parse_role_mapping(configured_text(
        &security.oidc_group_role_map,
        "RUSTIO_OIDC_GROUP_ROLE_MAP",
    ))
}

pub(crate) fn oidc_allowed_algorithms(
    security: &rustio_core::SecurityConfig,
    discovery: &OidcDiscoveryDocument,
) -> Vec<Algorithm> {
    configured_text(&security.oidc_allowed_algs, "RUSTIO_OIDC_ALLOWED_ALGS")
        .map(|raw| {
            raw.split([',', ';'])
                .filter_map(parse_algorithm_name)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            discovery
                .id_token_signing_alg_values_supported
                .iter()
                .filter_map(|value| parse_algorithm_name(value))
                .collect::<Vec<_>>()
        })
}

pub(crate) fn oidc_console_callback_path() -> &'static str {
    "/login/oidc/callback"
}

pub(crate) fn url_encode_component(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

pub(crate) fn request_origin(headers: &HeaderMap) -> Result<String, AppError> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(HOST))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::bad_request("缺少 Host 请求头 / missing host header"))?;
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("http");
    Ok(format!("{scheme}://{host}"))
}

pub(crate) fn oidc_backend_callback_url(headers: &HeaderMap) -> Result<String, AppError> {
    Ok(format!(
        "{}{}",
        request_origin(headers)?,
        "/api/v1/auth/oidc/callback"
    ))
}

pub(crate) fn oidc_callback_redirect_target(
    request_id: Option<&str>,
    error: Option<&str>,
) -> String {
    let mut target = oidc_console_callback_path().to_string();
    let mut query = Vec::new();
    if let Some(request_id) = request_id.filter(|value| !value.is_empty()) {
        query.push(format!("request_id={}", url_encode_component(request_id)));
    }
    if let Some(error) = error.filter(|value| !value.is_empty()) {
        query.push(format!("error={}", url_encode_component(error)));
    }
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query.join("&"));
    }
    target
}

pub(crate) fn oidc_pkce_verifier() -> String {
    let entropy = format!(
        "{}-{}-{}",
        Uuid::new_v4(),
        Uuid::new_v4(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let digest = Sha256::digest(entropy.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub(crate) fn oidc_pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) async fn purge_stale_oidc_browser_state(state: &AppState) {
    let expires_before = Utc::now() - Duration::minutes(10);
    state
        .oidc_auth_requests
        .write()
        .await
        .retain(|_, item| item.created_at >= expires_before);
    state
        .oidc_completed_logins
        .write()
        .await
        .retain(|_, item| item.created_at >= expires_before);
}

pub(crate) async fn fetch_json_document<T: DeserializeOwned>(
    client: &Client,
    url: &str,
) -> Result<T, AppError> {
    let response = client.get(url).send().await.map_err(|err| {
        AppError::internal(format!(
            "访问外部身份提供方失败 / failed to reach external identity provider: {err}"
        ))
    })?;
    if !response.status().is_success() {
        return Err(AppError::internal(format!(
            "外部身份提供方返回异常状态 / external identity provider returned unexpected status: {}",
            response.status()
        )));
    }
    response.json::<T>().await.map_err(|err| {
        AppError::internal(format!(
            "解析外部身份响应失败 / failed to decode external identity response: {err}"
        ))
    })
}

pub(crate) async fn decode_oidc_claims(
    security: &rustio_core::SecurityConfig,
    id_token: &str,
    expected_nonce: Option<&str>,
) -> Result<Value, AppError> {
    ensure_oidc_login_available(security)?;
    let id_token = id_token.trim();
    if id_token.is_empty() {
        return Err(AppError::bad_request(
            "OIDC ID Token 不能为空 / oidc id token cannot be empty",
        ));
    }
    let discovery_url = oidc_discovery_url(security).ok_or_else(|| {
        AppError::internal("OIDC Discovery 地址未配置 / oidc discovery url is not configured")
    })?;
    let client = Client::new();
    let discovery = fetch_json_document::<OidcDiscoveryDocument>(&client, &discovery_url).await?;
    let expected_issuer = oidc_expected_issuer(security, &discovery);
    let jwks_url = oidc_jwks_url_override(security).unwrap_or_else(|| discovery.jwks_uri.clone());
    let jwks = fetch_json_document::<JwkSet>(&client, &jwks_url).await?;

    let header = decode_header(id_token).map_err(|err| {
        AppError::unauthorized(format!(
            "OIDC Token 头解析失败 / failed to decode oidc token header: {err}"
        ))
    })?;
    let allowed_algs = oidc_allowed_algorithms(security, &discovery);
    if !allowed_algs.is_empty() && !allowed_algs.contains(&header.alg) {
        return Err(AppError::unauthorized(format!(
            "OIDC Token 签名算法不受支持 / oidc token signing algorithm is unsupported: {:?}",
            header.alg
        )));
    }
    let jwk = header
        .kid
        .as_deref()
        .and_then(|kid| jwks.find(kid))
        .or_else(|| (jwks.keys.len() == 1).then_some(&jwks.keys[0]))
        .ok_or_else(|| {
            AppError::unauthorized(
                "OIDC Token 未匹配到签名密钥 / oidc token signing key was not found",
            )
        })?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|err| {
        AppError::unauthorized(format!(
            "OIDC 签名密钥无效 / oidc signing key is invalid: {err}"
        ))
    })?;

    let mut validation = Validation::new(header.alg);
    validation.validate_nbf = true;
    validation.set_issuer(&[expected_issuer]);
    if let Some(client_id) = oidc_client_id(security) {
        validation.set_audience(&[client_id]);
    } else {
        validation.validate_aud = false;
    }

    let claims = jwt_decode::<Value>(id_token, &decoding_key, &validation)
        .map_err(|err| {
            AppError::unauthorized(format!(
                "OIDC Token 校验失败 / oidc token validation failed: {err}"
            ))
        })?
        .claims;
    if let Some(expected_nonce) = expected_nonce.filter(|value| !value.trim().is_empty()) {
        let actual_nonce = json_string_by_path(&claims, "nonce").unwrap_or_default();
        if actual_nonce != expected_nonce {
            return Err(AppError::unauthorized(
                "OIDC Token nonce 不匹配 / oidc token nonce does not match",
            ));
        }
    }
    Ok(claims)
}

pub(crate) fn external_identity_profile_from_oidc_claims(
    security: &rustio_core::SecurityConfig,
    claims: &Value,
    overrides: &ExternalIdentityClaimOverrides,
) -> Result<ExternalIdentityProfile, AppError> {
    let username_claim = overrides
        .username_claim
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| oidc_username_claim(security));
    let groups_claim = overrides
        .groups_claim
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| oidc_groups_claim(security));
    let role_claim = overrides
        .role_claim
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| oidc_role_claim(security));
    let default_role = overrides
        .default_role
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| oidc_default_role(security));
    let role_mapping = overrides
        .group_role_map
        .clone()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_role_mapping(Some(value)))
        .unwrap_or_else(|| oidc_role_mapping(security));
    let display_name_claim = overrides
        .display_name_claim
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "name".to_string());
    let subject_claim = overrides
        .subject_claim
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "sub".to_string());
    let audience_claim = overrides
        .audience_claim
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "aud".to_string());

    let username = json_string_by_path(claims, &username_claim)
        .or_else(|| json_string_by_path(claims, "email"))
        .or_else(|| json_string_by_path(claims, "sub"))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::unauthorized(
                "OIDC Token 缺少主体标识 / oidc token does not contain a principal identifier",
            )
        })?;
    let groups = json_string_list_by_path(claims, &groups_claim);
    let role = resolve_external_role(
        json_string_by_path(claims, &role_claim),
        &groups,
        &role_mapping,
        &default_role,
    );
    let display_name = json_string_by_path(claims, &display_name_claim)
        .or_else(|| json_string_by_path(claims, "display_name"))
        .unwrap_or_else(|| username.clone());

    Ok(ExternalIdentityProfile {
        username,
        role,
        display_name,
        groups,
        provider: overrides
            .provider_name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "oidc".to_string()),
        subject: json_string_by_path(claims, &subject_claim)
            .or_else(|| json_string_by_path(claims, "sub")),
        audience: json_string_by_path(claims, &audience_claim).or_else(|| {
            json_string_list_by_path(claims, &audience_claim)
                .into_iter()
                .next()
        }),
    })
}

pub(crate) async fn authenticate_oidc_token(
    security: &rustio_core::SecurityConfig,
    id_token: &str,
    expected_nonce: Option<&str>,
) -> Result<ExternalIdentityProfile, AppError> {
    let claims = decode_oidc_claims(security, id_token, expected_nonce).await?;
    external_identity_profile_from_oidc_claims(
        security,
        &claims,
        &ExternalIdentityClaimOverrides::default(),
    )
}

pub(crate) async fn authenticate_oidc_identity(
    security: &rustio_core::SecurityConfig,
    body: &LoginRequest,
) -> Result<ExternalIdentityProfile, AppError> {
    let id_token = body
        .id_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            AppError::bad_request("OIDC ID Token 不能为空 / oidc id token cannot be empty")
        })?;
    authenticate_oidc_token(security, id_token, None).await
}

pub(crate) fn oidc_callback_error_response(message: &str) -> Response {
    Redirect::temporary(&oidc_callback_redirect_target(None, Some(message))).into_response()
}

pub(crate) fn append_query_to_url(base: &str, query: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}{query}")
}

pub(crate) async fn exchange_oidc_authorization_code(
    security: &rustio_core::SecurityConfig,
    client: &Client,
    discovery: &OidcDiscoveryDocument,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<OidcTokenResponse, AppError> {
    let client_id = oidc_client_id(security).ok_or_else(|| {
        AppError::internal("OIDC Client ID 未配置 / oidc client id is not configured")
    })?;
    if discovery.token_endpoint.trim().is_empty() {
        return Err(AppError::internal(
            "OIDC Token Endpoint 未配置 / oidc token endpoint is not configured",
        ));
    }

    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("client_id", client_id),
        ("code_verifier", code_verifier.to_string()),
    ];
    if let Some(secret) = oidc_client_secret() {
        form.push(("client_secret", secret));
    }

    let response = client
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "请求 OIDC Token Endpoint 失败 / failed to request oidc token endpoint: {err}"
            ))
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AppError::unauthorized(format!(
            "OIDC 授权码换取令牌失败 / oidc authorization code exchange failed: {status} {}",
            body.trim()
        )));
    }

    response.json::<OidcTokenResponse>().await.map_err(|err| {
        AppError::internal(format!(
            "解析 OIDC Token 响应失败 / failed to decode oidc token response: {err}"
        ))
    })
}

pub(crate) async fn begin_oidc_browser_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Redirect, AppError> {
    purge_stale_oidc_browser_state(&state).await;
    let security = state.security.read().await.clone();
    ensure_oidc_login_available(&security)?;

    let discovery_url = oidc_discovery_url(&security).ok_or_else(|| {
        AppError::internal("OIDC Discovery 地址未配置 / oidc discovery url is not configured")
    })?;
    let client_id = oidc_client_id(&security).ok_or_else(|| {
        AppError::internal("OIDC Client ID 未配置 / oidc client id is not configured")
    })?;
    let client = Client::new();
    let discovery = fetch_json_document::<OidcDiscoveryDocument>(&client, &discovery_url).await?;
    if discovery.authorization_endpoint.trim().is_empty() {
        return Err(AppError::internal(
            "OIDC Authorization Endpoint 未配置 / oidc authorization endpoint is not configured",
        ));
    }

    let callback_url = oidc_backend_callback_url(&headers)?;
    let auth_request_id = format!("oidc-{}", Uuid::new_v4().simple());
    let nonce = Uuid::new_v4().simple().to_string();
    let code_verifier = oidc_pkce_verifier();
    let code_challenge = oidc_pkce_challenge(&code_verifier);
    state.oidc_auth_requests.write().await.insert(
        auth_request_id.clone(),
        PendingOidcAuthorization {
            code_verifier,
            nonce: nonce.clone(),
            created_at: Utc::now(),
        },
    );

    let query = [
        format!("response_type={}", url_encode_component("code")),
        format!("client_id={}", url_encode_component(&client_id)),
        format!("redirect_uri={}", url_encode_component(&callback_url)),
        format!("scope={}", url_encode_component(&oidc_browser_scopes())),
        format!("state={}", url_encode_component(&auth_request_id)),
        format!("nonce={}", url_encode_component(&nonce)),
        format!("code_challenge={}", url_encode_component(&code_challenge)),
        format!("code_challenge_method={}", url_encode_component("S256")),
    ]
    .join("&");
    Ok(Redirect::temporary(&append_query_to_url(
        &discovery.authorization_endpoint,
        &query,
    )))
}

pub(crate) async fn complete_oidc_browser_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    purge_stale_oidc_browser_state(&state).await;

    if let Some(error) = query
        .error
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let description = query
            .error_description
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(error);
        return oidc_callback_error_response(&format!(
            "OIDC 浏览器登录失败 / oidc browser login failed: {description}"
        ));
    }

    let state_id = match query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.to_string(),
        None => {
            return oidc_callback_error_response(
                "OIDC 回调缺少 state / oidc callback is missing state",
            )
        }
    };
    let code = match query
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.to_string(),
        None => {
            return oidc_callback_error_response(
                "OIDC 回调缺少 code / oidc callback is missing authorization code",
            )
        }
    };

    let pending = match state.oidc_auth_requests.write().await.remove(&state_id) {
        Some(item) => item,
        None => {
            return oidc_callback_error_response(
                "OIDC 登录状态不存在或已过期 / oidc login state does not exist or has expired",
            )
        }
    };
    let security = state.security.read().await.clone();
    if let Err(err) = ensure_oidc_login_available(&security) {
        return oidc_callback_error_response(&err.message);
    }
    let discovery_url = match oidc_discovery_url(&security) {
        Some(value) => value,
        None => {
            return oidc_callback_error_response(
                "OIDC Discovery 地址未配置 / oidc discovery url is not configured",
            )
        }
    };
    let callback_url = match oidc_backend_callback_url(&headers) {
        Ok(value) => value,
        Err(err) => return oidc_callback_error_response(&err.message),
    };
    let client = Client::new();
    let discovery =
        match fetch_json_document::<OidcDiscoveryDocument>(&client, &discovery_url).await {
            Ok(value) => value,
            Err(err) => return oidc_callback_error_response(&err.message),
        };
    let token_response = match exchange_oidc_authorization_code(
        &security,
        &client,
        &discovery,
        &code,
        &callback_url,
        &pending.code_verifier,
    )
    .await
    {
        Ok(value) => value,
        Err(err) => return oidc_callback_error_response(&err.message),
    };
    if token_response.id_token.trim().is_empty() {
        return oidc_callback_error_response(
            "OIDC Token 响应缺少 ID Token / oidc token response does not contain id token",
        );
    }

    let profile =
        match authenticate_oidc_token(&security, &token_response.id_token, Some(&pending.nonce))
            .await
        {
            Ok(value) => value,
            Err(err) => return oidc_callback_error_response(&err.message),
        };
    if let Err(err) = sync_external_identity_profile(&state, &profile).await {
        return oidc_callback_error_response(&err.message);
    }
    let (response, session) = match create_console_login_response(
        state.as_ref(),
        &profile.username,
        &profile.role,
        "oidc",
    )
    .await
    {
        Ok(value) => value,
        Err(err) => return oidc_callback_error_response(&err.message),
    };

    let completed_request_id = format!("oidc-session-{}", Uuid::new_v4().simple());
    state.oidc_completed_logins.write().await.insert(
        completed_request_id.clone(),
        CompletedOidcLogin {
            response,
            created_at: Utc::now(),
        },
    );
    state
        .append_runtime_audit(
            &profile.username,
            "auth.login.oidc.browser",
            "session",
            "success",
            None,
            json!({
                "role": profile.role,
                "groups": profile.groups,
                "provider": profile.provider,
                "session_id": session.session_id,
                "redirect": "console"
            }),
        )
        .await;

    Redirect::temporary(&oidc_callback_redirect_target(
        Some(&completed_request_id),
        None,
    ))
    .into_response()
}

pub(crate) async fn redeem_oidc_browser_login(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> Result<Json<ApiEnvelope<rustio_core::LoginResponse>>, AppError> {
    purge_stale_oidc_browser_state(&state).await;
    let completed = state
        .oidc_completed_logins
        .write()
        .await
        .remove(&request_id)
        .ok_or_else(|| {
            AppError::not_found(
                "OIDC 登录会话不存在或已过期 / oidc login session does not exist or has expired",
            )
        })?;
    Ok(wrap(completed.response))
}
