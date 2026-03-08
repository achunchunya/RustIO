use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use rustio_core::ApiError;
use serde_json::json;
use uuid::Uuid;

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn precondition(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            message,
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let message = bilingual_message(self.code, &self.message);
        let error = ApiError {
            code: self.code.to_string(),
            message,
            request_id: Uuid::new_v4().to_string(),
        };
        (self.status, Json(json!({ "error": error }))).into_response()
    }
}

fn bilingual_message(code: &str, message: &str) -> String {
    if message.contains(" / ") {
        return message.to_string();
    }

    let (zh, en_default) = match code {
        "bad_request" => ("请求参数错误", "bad request"),
        "unauthorized" => ("未认证或令牌无效", "unauthorized"),
        "forbidden" => ("权限不足", "forbidden"),
        "not_found" => ("资源不存在", "not found"),
        "precondition_required" => ("缺少前置条件", "precondition required"),
        "internal_error" => ("服务器内部错误", "internal server error"),
        "service_unavailable" => ("服务暂不可用", "service unavailable"),
        _ => ("请求处理失败", "request failed"),
    };

    let text = message.trim();
    if text.is_empty() {
        return format!("{zh} / {en_default}");
    }

    if contains_cjk(text) && !contains_ascii_alpha(text) {
        return format!("{text} / {en_default}");
    }

    format!("{zh} / {text}")
}

fn contains_ascii_alpha(text: &str) -> bool {
    text.chars().any(|ch| ch.is_ascii_alphabetic())
}

fn contains_cjk(text: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::bilingual_message;

    #[test]
    fn bilingual_message_keeps_existing_bilingual_text() {
        let msg = bilingual_message("bad_request", "参数错误 / invalid argument");
        assert_eq!(msg, "参数错误 / invalid argument");
    }

    #[test]
    fn bilingual_message_wraps_english_only_message() {
        let msg = bilingual_message("bad_request", "invalid argument");
        assert_eq!(msg, "请求参数错误 / invalid argument");
    }

    #[test]
    fn bilingual_message_wraps_chinese_only_message() {
        let msg = bilingual_message("not_found", "存储桶不存在");
        assert_eq!(msg, "存储桶不存在 / not found");
    }

    #[test]
    fn bilingual_message_handles_empty_message() {
        let msg = bilingual_message("internal_error", "");
        assert_eq!(msg, "服务器内部错误 / internal server error");
    }

    #[test]
    fn bilingual_message_maps_service_unavailable() {
        let msg = bilingual_message("service_unavailable", "");
        assert_eq!(msg, "服务暂不可用 / service unavailable");
    }
}
