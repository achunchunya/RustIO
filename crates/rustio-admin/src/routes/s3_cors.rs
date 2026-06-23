//! S3 per-bucket CORS：OPTIONS 预检 + 实际请求 Access-Control-* 注入。
//!
//! 与全局 console CORS 层（tower-http，固定 origin）分离：console CORS 仅作用于管理路由，
//! S3 路由（/{bucket}...）按各 bucket 配置的 CORS 规则动态匹配 Origin。

use super::*;

use tower_http::cors::CorsLayer;

/// 读取 bucket 的 CORS 规则：先查内存缓存，miss 回退磁盘并回填（无规则返回 None）。
pub(crate) async fn load_bucket_cors_rules(
    state: &AppState,
    bucket: &str,
) -> Option<Vec<BucketCorsRule>> {
    if let Some(rules) = state.bucket_cors_rules.read().await.get(bucket).cloned() {
        return Some(rules);
    }
    let bucket_dir = bucket_path(state, bucket).ok()?;
    let path = bucket_cors_path(&bucket_dir);
    let bytes = tokio::fs::read(&path).await.ok()?;
    let parsed = serde_json::from_slice::<Vec<BucketCorsRule>>(&bytes).ok()?;
    state
        .bucket_cors_rules
        .write()
        .await
        .insert(bucket.to_string(), parsed.clone());
    Some(parsed)
}

/// 按 AWS 语义匹配一条 CORS 规则：origin（支持 `*` 通配）、method、（预检时）请求头全部命中。
/// request_headers 为空表示实际请求（不校验 AllowedHeader）。
pub(crate) fn match_cors_rule<'a>(
    rules: &'a [BucketCorsRule],
    origin: &str,
    method: &str,
    request_headers: &[String],
) -> Option<&'a BucketCorsRule> {
    rules.iter().find(|rule| {
        let origin_ok = rule
            .allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || wildcard_match(allowed, origin));
        let method_ok = rule
            .allowed_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method));
        let headers_ok = request_headers.iter().all(|requested| {
            let requested = requested.trim().to_ascii_lowercase();
            requested.is_empty()
                || rule.allowed_headers.iter().any(|allowed| {
                    allowed == "*" || wildcard_match(&allowed.to_ascii_lowercase(), &requested)
                })
        });
        origin_ok && method_ok && headers_ok
    })
}

/// 预检命中时返回的 Access-Control-Allow-Origin 值：规则含 `*` 通配则回显具体 origin（兼容带凭据场景）。
fn allow_origin_value(origin: &str) -> String {
    origin.to_string()
}

/// OPTIONS 预检处理：匹配 bucket CORS 规则后返回 200 + Access-Control-* 头；无 Origin → 400；不匹配 → 403。
pub(crate) async fn s3_cors_preflight(
    state: Arc<AppState>,
    bucket: String,
    headers: &HeaderMap,
) -> Response {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let request_method = headers
        .get("access-control-request-method")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let (Some(origin), Some(request_method)) = (origin, request_method) else {
        return s3_error(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "Insufficient information. Origin request header needed.",
            &bucket,
        );
    };

    let request_headers: Vec<String> = headers
        .get("access-control-request-headers")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let rules = load_bucket_cors_rules(&state, &bucket).await.unwrap_or_default();
    let Some(rule) = match_cors_rule(&rules, &origin, &request_method, &request_headers) else {
        return s3_error(
            StatusCode::FORBIDDEN,
            "AccessForbidden",
            "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.",
            &bucket,
        );
    };

    let mut response = StatusCode::OK.into_response();
    let h = response.headers_mut();
    let set = |h: &mut HeaderMap, name: &'static str, value: &str| {
        if let Ok(v) = axum::http::HeaderValue::from_str(value) {
            h.insert(axum::http::header::HeaderName::from_static(name), v);
        }
    };
    set(h, "access-control-allow-origin", &allow_origin_value(&origin));
    set(h, "access-control-allow-methods", &rule.allowed_methods.join(", "));
    if !request_headers.is_empty() {
        set(h, "access-control-allow-headers", &request_headers.join(", "));
    } else if !rule.allowed_headers.is_empty() {
        set(h, "access-control-allow-headers", &rule.allowed_headers.join(", "));
    }
    if !rule.expose_headers.is_empty() {
        set(h, "access-control-expose-headers", &rule.expose_headers.join(", "));
    }
    if let Some(max_age) = rule.max_age_seconds {
        set(h, "access-control-max-age", &max_age.to_string());
    }
    set(
        h,
        "vary",
        "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    response
}

/// OPTIONS 路由包装：桶级路径 /{bucket}。
pub(crate) async fn s3_cors_preflight_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> Response {
    s3_cors_preflight(state, bucket, &headers).await
}

/// OPTIONS 路由包装：对象级路径 /{bucket}/{*key}（仍按 bucket 配置匹配）。
pub(crate) async fn s3_cors_preflight_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, _key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    s3_cors_preflight(state, bucket, &headers).await
}

/// S3 实际请求（非 OPTIONS）的 CORS 响应头注入中间件：带 Origin 且匹配 bucket CORS 规则时，
/// 注入 Access-Control-Allow-Origin + Expose-Headers + Vary。对管理路由 / 无 Origin 请求为 no-op。
pub(crate) async fn inject_s3_cors_headers(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let mut response = next.run(request).await;

    // 仅对带 Origin 的非 OPTIONS S3 请求处理（OPTIONS 由 preflight handler 负责）。
    let Some(origin) = origin else {
        return response;
    };
    if method == Method::OPTIONS {
        return response;
    }
    let Some(bucket) = s3_bucket_from_path(&path) else {
        return response;
    };

    let rules = load_bucket_cors_rules(&state, &bucket).await.unwrap_or_default();
    if let Some(rule) = match_cors_rule(&rules, &origin, method.as_str(), &[]) {
        let h = response.headers_mut();
        if let Ok(v) = axum::http::HeaderValue::from_str(&origin) {
            h.insert(
                axum::http::header::HeaderName::from_static("access-control-allow-origin"),
                v,
            );
        }
        if !rule.expose_headers.is_empty() {
            if let Ok(v) = axum::http::HeaderValue::from_str(&rule.expose_headers.join(", ")) {
                h.insert(
                    axum::http::header::HeaderName::from_static("access-control-expose-headers"),
                    v,
                );
            }
        }
        if let Ok(v) = axum::http::HeaderValue::from_str("Origin") {
            h.insert(axum::http::header::VARY, v);
        }
    }
    response
}

/// 从请求路径提取 S3 bucket 名（首段）；保留前缀（管理/健康/监控路由）返回 None。
fn s3_bucket_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    let first = trimmed.split('/').next().unwrap_or("");
    if first.is_empty() {
        return None;
    }
    const RESERVED: &[&str] = &["api", "health", "minio", "metrics", "console", "internal"];
    if RESERVED.contains(&first) {
        return None;
    }
    Some(first.to_string())
}

/// console 跨域层（原 rustio-server::build_cors_layer 迁来）：固定 origin（RUSTIO_CORS_ORIGIN，
/// 默认 http://localhost:9000），仅作用于管理路由。解析失败回退默认 origin（不再 fail 启动）。
pub(crate) fn build_console_cors_layer() -> CorsLayer {
    let methods = [
        Method::GET,
        Method::PUT,
        Method::POST,
        Method::DELETE,
        Method::HEAD,
    ];
    let headers = [
        axum::http::header::CONTENT_TYPE,
        axum::http::header::AUTHORIZATION,
        axum::http::header::HeaderName::from_static("x-amz-content-sha256"),
        axum::http::header::HeaderName::from_static("x-amz-date"),
    ];
    let origin_raw = std::env::var("RUSTIO_CORS_ORIGIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "http://localhost:9000".to_string());
    let origin_value = origin_raw
        .trim()
        .parse::<axum::http::HeaderValue>()
        .unwrap_or_else(|_| {
            tracing::warn!("RUSTIO_CORS_ORIGIN 无效,回退 http://localhost:9000: {origin_raw}");
            axum::http::HeaderValue::from_static("http://localhost:9000")
        });
    CorsLayer::new()
        .allow_origin(origin_value)
        .allow_methods(methods)
        .allow_headers(headers)
}
