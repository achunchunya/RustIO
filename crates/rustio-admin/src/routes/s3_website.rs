//! S3 静态网站托管(website hosting)的请求服务:根据 bucket website 配置返回
//! index document / error document / 整桶重定向。配置 CRUD 见 s3_bucket_ops.rs。

use super::*;

/// 尝试以静态网站语义服务一个裸浏览器 GET 请求。
/// 返回 `Some(response)` 表示该 bucket 配了 website 并已处理;`None` 表示未配置,调用方回退原有逻辑。
pub(crate) async fn serve_website_request(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Option<Response> {
    let config = load_bucket_website_config(state, bucket).await?;

    // RedirectAllRequestsTo: 整桶 301 重定向到目标 host(S3 用 301 MovedPermanently,非 308)。
    if let Some(host) = config.redirect_all_to_host.as_deref() {
        let protocol = config.redirect_all_protocol.as_deref().unwrap_or("http");
        let location = if key.is_empty() {
            format!("{protocol}://{host}/")
        } else {
            format!("{protocol}://{host}/{key}")
        };
        let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
        if let Ok(value) = axum::http::HeaderValue::from_str(&location) {
            response
                .headers_mut()
                .insert(axum::http::header::LOCATION, value);
        }
        return Some(response);
    }

    // 解析目标对象 key:根路径或以 / 结尾 → 追加 index document;否则用 key 本身。
    let index = config.index_document.as_deref().unwrap_or("index.html");
    let target_key = if key.is_empty() || key.ends_with('/') {
        format!("{key}{index}")
    } else {
        key.to_string()
    };

    match read_website_object(state, bucket, &target_key).await {
        Some((payload, content_type)) => {
            Some(website_object_response(StatusCode::OK, payload, &content_type))
        }
        None => Some(serve_website_error(state, bucket, &config).await),
    }
}

/// 对象不存在时返回 error document(404),无 error document 则返回纯 404 文本。
async fn serve_website_error(
    state: &AppState,
    bucket: &str,
    config: &BucketWebsiteConfig,
) -> Response {
    if let Some(error_key) = config.error_document.as_deref() {
        if let Some((payload, content_type)) = read_website_object(state, bucket, error_key).await {
            return website_object_response(StatusCode::NOT_FOUND, payload, &content_type);
        }
    }
    website_object_response(
        StatusCode::NOT_FOUND,
        b"404 Not Found".to_vec(),
        "text/plain",
    )
}

/// 读取 website 对象的明文 + 解析 content-type(优先对象元数据,缺失按扩展名猜测)。
async fn read_website_object(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Option<(Vec<u8>, String)> {
    let meta = read_current_object_meta(state, bucket, key).await.ok()??;
    if meta.delete_marker {
        return None;
    }
    let payload = read_current_object_payload(state, bucket, key, Some(&meta), None)
        .await
        .ok()??;
    let content_type = meta
        .content_type
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| guess_website_content_type(key).to_string());
    Some((payload, content_type))
}

fn website_object_response(status: StatusCode, payload: Vec<u8>, content_type: &str) -> Response {
    let mut response = (status, payload).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(content_type) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, value);
    }
    response
}

/// website 配置读取:内存缓存优先,miss 回退磁盘并回填(无配置返回 None)。
async fn load_bucket_website_config(
    state: &AppState,
    bucket: &str,
) -> Option<BucketWebsiteConfig> {
    if let Some(config) = state.bucket_website_configs.read().await.get(bucket).cloned() {
        return Some(config);
    }
    let bucket_dir = bucket_path(state, bucket).ok()?;
    let path = bucket_website_path(&bucket_dir);
    let bytes = tokio::fs::read(&path).await.ok()?;
    let parsed = serde_json::from_slice::<BucketWebsiteConfig>(&bytes).ok()?;
    state
        .bucket_website_configs
        .write()
        .await
        .insert(bucket.to_string(), parsed.clone());
    Some(parsed)
}

/// 按扩展名猜测 content-type(对象未声明时的兜底,确保 html/css/js 正确渲染)。
fn guess_website_content_type(key: &str) -> &'static str {
    let ext = key.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}
