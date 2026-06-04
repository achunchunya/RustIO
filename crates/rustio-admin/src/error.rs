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
        let request_id = Uuid::new_v4().to_string();
        let client_message = if self.status.is_server_error() {
            // 5xx:脱敏,不向客户端暴露内部错误细节(文件路径/数据库错误等)。
            // 完整原始消息只进服务端日志,客户端仅得到开发者显式提供的双语语义。
            tracing::warn!(
                %request_id,
                original_message = %self.message,
                "内部错误已脱敏 / internal error sanitized"
            );
            sanitize_server_error(self.code, &self.message)
        } else {
            bilingual_message(self.code, &self.message)
        };

        let error = ApiError {
            code: self.code.to_string(),
            message: client_message,
            request_id,
        };
        (self.status, Json(json!({ "error": error }))).into_response()
    }
}

/// 5xx 错误脱敏:保留开发者显式提供的双语语义短语,剥离 `: {err}` 动态细节尾巴
/// (文件路径/数据库/底层库错误)。无双语语义的裸错误整体替换为通用文案。
fn sanitize_server_error(code: &str, message: &str) -> String {
    let fallback = generic_server_message(code);
    // 仅信任开发者写的双语消息(含 " / "),其余视为内部裸错误,整体脱敏。
    if !message.contains(" / ") {
        return fallback;
    }
    // 剥离 ": detail" 细节尾巴:取最后一个 ": " 之前的语义部分。
    // 例:"LDAP 管理绑定被拒绝 / ldap administrative bind was rejected: <err>"
    //  → "LDAP 管理绑定被拒绝 / ldap administrative bind was rejected"
    let semantic = match message.rsplit_once(": ") {
        Some((head, _detail)) if head.contains(" / ") => head,
        _ => message,
    };
    let trimmed = semantic.trim();
    if trimmed.is_empty() {
        fallback
    } else {
        trimmed.to_string()
    }
}

fn generic_server_message(code: &str) -> String {
    let (zh, en) = match code {
        "internal_error" => ("服务器内部错误", "internal server error"),
        "service_unavailable" => ("服务暂不可用", "service unavailable"),
        _ => ("请求处理失败", "request failed"),
    };
    format!("{zh} / {en}")
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

