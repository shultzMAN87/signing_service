//! Ошибки сервиса: код из ТЗ (раздел 4) + HTTP-статус.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, Clone)]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
    pub request_id: Option<String>,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), request_id: None }
    }
    pub fn code(code: &'static str) -> Self {
        Self::new(code, code)
    }
    pub fn status(&self) -> StatusCode {
        match self.code {
            "bad_request" | "hash_requires_detached" | "unsupported_ext" | "bad_hash_length" => StatusCode::BAD_REQUEST,
            "unauthenticated" => StatusCode::UNAUTHORIZED,
            "forbidden" | "second_approver_required" => StatusCode::FORBIDDEN,
            "key_not_found" | "upload_not_found" => StatusCode::NOT_FOUND,
            "key_exists" => StatusCode::CONFLICT,
            "upload_expired" => StatusCode::GONE,
            "too_large" => StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_pin" | "invalid_container" | "unsupported_format" | "cert_expired" | "cert_not_yet_valid"
            | "untrusted_chain" | "key_mismatch" | "not_gost" | "decrypt_failed" | "crypto_error" => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            "key_blocked" | "key_deleted" | "emergency_block" => StatusCode::LOCKED,
            "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
            "dependency_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database");
        AppError::new("dependency_unavailable", "База данных недоступна")
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = serde_json::json!({ "code": self.code, "message": self.message, "request_id": self.request_id });
        let mut resp = (status, Json(body)).into_response();
        resp.extensions_mut().insert(ErrorCode(self.code));
        resp
    }
}

/// Код ошибки для метрик.
#[derive(Clone, Copy)]
pub struct ErrorCode(pub &'static str);
