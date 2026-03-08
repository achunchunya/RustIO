use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rustio_core::{permissions_for_role, AuthClaims, ConsoleSession, LoginResponse, Permission};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

pub const ACCESS_TOKEN_USE: &str = "access";
pub const REFRESH_TOKEN_USE: &str = "refresh";

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub username: String,
    pub claims: AuthClaims,
}

impl AuthContext {
    pub fn require(&self, permission: Permission) -> Result<(), AppError> {
        if self.claims.has_permission(permission) {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "缺少权限 {} / missing permission {}",
                permission.as_str(),
                permission.as_str()
            )))
        }
    }
}

fn permissions_for_session(role: &str) -> Vec<String> {
    permissions_for_role(role)
        .into_iter()
        .map(|permission| permission.as_str().to_string())
        .collect()
}

pub fn create_console_session(username: &str, role: &str, provider: &str) -> ConsoleSession {
    let now = Utc::now();
    ConsoleSession {
        session_id: Uuid::new_v4().to_string(),
        principal: username.to_string(),
        role: role.to_string(),
        permissions: permissions_for_session(role),
        provider: provider.to_string(),
        status: "active".to_string(),
        issued_at: now,
        access_expires_at: now + Duration::hours(4),
        refresh_expires_at: now + Duration::days(7),
        last_refreshed_at: None,
        revoked_at: None,
        revoked_reason: None,
    }
}

pub fn refresh_console_session(session: &ConsoleSession) -> ConsoleSession {
    let now = Utc::now();
    let mut next = session.clone();
    next.permissions = permissions_for_session(&next.role);
    next.status = "active".to_string();
    next.access_expires_at = now + Duration::hours(4);
    next.refresh_expires_at = now + Duration::days(7);
    next.last_refreshed_at = Some(now);
    next.revoked_at = None;
    next.revoked_reason = None;
    next
}

pub fn issue_tokens(session: &ConsoleSession, jwt_secret: &str) -> Result<LoginResponse, AppError> {
    let now = Utc::now();
    let claims = AuthClaims {
        sub: session.principal.clone(),
        role: session.role.clone(),
        permissions: session.permissions.clone(),
        session_id: session.session_id.clone(),
        token_use: ACCESS_TOKEN_USE.to_string(),
        iat: now.timestamp(),
        exp: session.access_expires_at.timestamp(),
    };

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|err| AppError::internal(format!("签发访问令牌失败 / failed to sign token: {err}")))?;

    let refresh_claims = AuthClaims {
        token_use: REFRESH_TOKEN_USE.to_string(),
        exp: session.refresh_expires_at.timestamp(),
        ..claims.clone()
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|err| {
        AppError::internal(format!(
            "签发刷新令牌失败 / failed to sign refresh token: {err}"
        ))
    })?;

    Ok(LoginResponse {
        access_token,
        refresh_token,
        session_id: session.session_id.clone(),
        role: session.role.clone(),
        permissions: claims.permissions.clone(),
        expires_at: session.access_expires_at,
        refresh_expires_at: session.refresh_expires_at,
    })
}

pub fn decode_token(token: &str, jwt_secret: &str) -> Result<AuthClaims, AppError> {
    let validation = Validation::default();
    let data = decode::<AuthClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::unauthorized("令牌无效 / invalid token"))?;
    Ok(data.claims)
}

fn require_token_use(claims: &AuthClaims, expected: &str) -> Result<(), AppError> {
    if claims.token_use == expected {
        return Ok(());
    }

    let expected_label = match expected {
        ACCESS_TOKEN_USE => "访问令牌 / access token",
        REFRESH_TOKEN_USE => "刷新令牌 / refresh token",
        _ => "指定类型令牌 / expected token type",
    };
    Err(AppError::unauthorized(format!(
        "令牌类型无效，期望 {} / invalid token type, expected {}",
        expected_label, expected
    )))
}

async fn require_active_session(
    claims: &AuthClaims,
    app_state: &AppState,
) -> Result<ConsoleSession, AppError> {
    if claims.session_id.trim().is_empty() {
        return Err(AppError::unauthorized(
            "会话标识缺失，请重新登录 / missing session identifier, please log in again",
        ));
    }

    let sessions = app_state.admin_sessions.read().await;
    let session = sessions
        .iter()
        .find(|session| session.session_id == claims.session_id)
        .cloned()
        .ok_or_else(|| {
            AppError::unauthorized("会话不存在或已失效 / session does not exist or has expired")
        })?;

    if session.status != "active" {
        return Err(AppError::unauthorized(
            "会话已注销或撤销 / session has been logged out or revoked",
        ));
    }
    if session.principal != claims.sub {
        return Err(AppError::unauthorized(
            "会话主体不匹配 / session principal does not match",
        ));
    }

    let user = app_state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == session.principal)
        .cloned()
        .ok_or_else(|| {
            AppError::unauthorized("用户不存在或已删除 / user does not exist or has been deleted")
        })?;
    if !user.enabled {
        return Err(AppError::unauthorized("用户已禁用 / user is disabled"));
    }

    Ok(session)
}

pub async fn validate_access_token(
    token: &str,
    app_state: &AppState,
) -> Result<AuthClaims, AppError> {
    let mut claims = decode_token(token, &app_state.jwt_secret)?;
    require_token_use(&claims, ACCESS_TOKEN_USE)?;
    let session = require_active_session(&claims, app_state).await?;
    let user = app_state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == session.principal)
        .cloned()
        .ok_or_else(|| {
            AppError::unauthorized("用户不存在或已删除 / user does not exist or has been deleted")
        })?;
    claims.role = user.role.clone();
    claims.permissions = permissions_for_role(&user.role)
        .into_iter()
        .map(|permission| permission.as_str().to_string())
        .collect();
    Ok(claims)
}

pub async fn validate_refresh_token(
    token: &str,
    app_state: &AppState,
) -> Result<(AuthClaims, ConsoleSession), AppError> {
    let claims = decode_token(token, &app_state.jwt_secret)?;
    require_token_use(&claims, REFRESH_TOKEN_USE)?;
    let session = require_active_session(&claims, app_state).await?;
    Ok((claims, session))
}

impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
    Arc<AppState>: axum::extract::FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("缺少认证头 / missing authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::unauthorized("认证方案无效 / invalid authorization scheme"))?;

        let claims = validate_access_token(token, app_state.as_ref()).await?;
        Ok(Self {
            username: claims.sub.clone(),
            claims,
        })
    }
}
