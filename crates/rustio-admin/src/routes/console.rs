//! 管理控制台静态资源服务

use super::*;

pub(crate) async fn serve_console_path(path: &str, allow_spa_fallback: bool) -> Option<Response> {
    let dist_dir = resolve_console_dist_dir()?;
    let normalized = normalize_console_path(path)?;
    let requested = dist_dir.join(&normalized);
    if tokio::fs::try_exists(&requested).await.unwrap_or(false) {
        if let Ok(metadata) = tokio::fs::metadata(&requested).await {
            if metadata.is_file() {
                if let Ok(response) = read_console_file_response(&requested).await {
                    return Some(response);
                }
            }
        }
    }

    if !allow_spa_fallback {
        return None;
    }

    let index_path = dist_dir.join("index.html");
    if !tokio::fs::try_exists(&index_path).await.unwrap_or(false) {
        return None;
    }
    read_console_file_response(&index_path).await.ok()
}

pub(crate) fn resolve_console_dist_dir() -> Option<PathBuf> {
    if let Ok(raw) = std::env::var("RUSTIO_CONSOLE_DIST") {
        let path = PathBuf::from(raw);
        if path.join("index.html").is_file() {
            return Some(path);
        }
    }

    let mut candidates = vec![PathBuf::from("./web/console/dist"), PathBuf::from("./dist")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("web/console/dist"));
            candidates.push(exe_dir.join("../web/console/dist"));
            candidates.push(exe_dir.join("../../web/console/dist"));
            candidates.push(exe_dir.join("console/dist"));
        }
    }

    candidates
        .into_iter()
        .find(|path| path.join("index.html").is_file())
}

pub(crate) fn normalize_console_path(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(PathBuf::from("index.html"));
    }

    let fs_path = FsPath::new(trimmed);
    let mut normalized = PathBuf::new();
    for component in fs_path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            _ => return None,
        }
    }
    Some(normalized)
}

pub(crate) async fn read_console_file_response(path: &FsPath) -> std::io::Result<Response> {
    let bytes = tokio::fs::read(path).await?;
    let mime = console_content_type(path);
    let mut response = (StatusCode::OK, bytes).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(mime),
    );
    Ok(response)
}

pub(crate) fn console_content_type(path: &FsPath) -> &'static str {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if ext.eq_ignore_ascii_case("html") {
        "text/html; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("css") {
        "text/css; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("js") {
        "text/javascript; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("json") {
        "application/json; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("svg") {
        "image/svg+xml"
    } else if ext.eq_ignore_ascii_case("png") {
        "image/png"
    } else if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
        "image/jpeg"
    } else if ext.eq_ignore_ascii_case("ico") {
        "image/x-icon"
    } else if ext.eq_ignore_ascii_case("webp") {
        "image/webp"
    } else if ext.eq_ignore_ascii_case("woff") {
        "font/woff"
    } else if ext.eq_ignore_ascii_case("woff2") {
        "font/woff2"
    } else if ext.eq_ignore_ascii_case("map") {
        "application/json; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

pub(crate) fn request_accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.split(',').map(str::trim).any(|item| {
                item.starts_with("text/html") || item.starts_with("application/xhtml+xml")
            })
        })
        .unwrap_or(false)
}
