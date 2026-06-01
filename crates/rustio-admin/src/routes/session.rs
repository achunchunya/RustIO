//! 登录会话与 IAM 运行时快照

use super::*;

pub(crate) async fn capture_iam_runtime_snapshot(state: &AppState) -> IamRuntimeSnapshot {
    IamRuntimeSnapshot {
        credentials: state.credentials.read().await.clone(),
        users: state.users.read().await.clone(),
        groups: state.groups.read().await.clone(),
        policies: state.policies.read().await.clone(),
        service_accounts: state.service_accounts.read().await.clone(),
        admin_sessions: state.admin_sessions.read().await.clone(),
        sts_sessions: state.sts_sessions.read().await.clone(),
    }
}

pub(crate) async fn restore_iam_runtime_snapshot(state: &AppState, snapshot: IamRuntimeSnapshot) {
    *state.credentials.write().await = snapshot.credentials;
    *state.users.write().await = snapshot.users;
    *state.groups.write().await = snapshot.groups;
    *state.policies.write().await = snapshot.policies;
    *state.service_accounts.write().await = snapshot.service_accounts;
    *state.admin_sessions.write().await = snapshot.admin_sessions.clone();
    *state.sts_sessions.write().await = snapshot.sts_sessions;
    let _ = AppState::persist_console_sessions_snapshot(&state.data_dir, &snapshot.admin_sessions);
}

pub(crate) async fn commit_iam_runtime_change(
    state: &AppState,
    reason: &str,
    rollback: IamRuntimeSnapshot,
) -> Result<(), AppError> {
    if let Err(err) = state.sync_metadata_raft(reason).await {
        restore_iam_runtime_snapshot(state, rollback).await;
        return Err(AppError::internal(format!(
            "IAM 元数据 Raft 提交失败 / iam metadata raft commit failed: {err}"
        )));
    }

    let sessions = state.admin_sessions.read().await.clone();
    AppState::persist_console_sessions_snapshot(&state.data_dir, &sessions).map_err(|err| {
        AppError::internal(format!(
            "持久化控制台会话快照失败 / failed to persist console session snapshot: {err}"
        ))
    })?;
    Ok(())
}

pub(crate) async fn align_console_sessions_for_principal_in_memory(
    state: &AppState,
    principal: &str,
    role: &str,
) {
    let permissions = rustio_core::permissions_for_role(role)
        .into_iter()
        .map(|permission| permission.as_str().to_string())
        .collect::<Vec<_>>();
    let mut sessions = state.admin_sessions.write().await;
    for session in sessions.iter_mut() {
        if session.principal == principal && session.status == "active" {
            session.role = role.to_string();
            session.permissions = permissions.clone();
        }
    }
}

pub(crate) async fn revoke_console_sessions_for_principal_in_memory(
    state: &AppState,
    principal: &str,
    revoked_reason: &str,
) -> usize {
    let now = Utc::now();
    let mut sessions = state.admin_sessions.write().await;
    let mut revoked = 0usize;
    for session in sessions.iter_mut() {
        if session.principal == principal && session.status == "active" {
            session.status = "revoked".to_string();
            session.revoked_at = Some(now);
            session.revoked_reason = Some(revoked_reason.to_string());
            revoked += 1;
        }
    }
    revoked
}

pub(crate) async fn persist_console_session(
    state: &AppState,
    session: ConsoleSession,
) -> Result<(), AppError> {
    let previous_sessions = state.admin_sessions.read().await.clone();
    let next_sessions = {
        let mut sessions = previous_sessions.clone();
        sessions.retain(|item| item.session_id != session.session_id);
        sessions.push(session);
        sessions
    };
    {
        let mut sessions = state.admin_sessions.write().await;
        *sessions = next_sessions.clone();
    }

    if let Err(err) = AppState::persist_console_sessions_snapshot(&state.data_dir, &next_sessions) {
        *state.admin_sessions.write().await = previous_sessions;
        return Err(AppError::internal(format!(
            "持久化控制台会话失败 / failed to persist console sessions: {err}"
        )));
    }

    if let Some(synced_session) = next_sessions.last().cloned() {
        state
            .broadcast_console_session_runtime(&synced_session)
            .await;
    }

    Ok(())
}

pub(crate) async fn create_console_login_response(
    state: &AppState,
    username: &str,
    role: &str,
    provider: &str,
) -> Result<(rustio_core::LoginResponse, ConsoleSession), AppError> {
    let session = create_console_session(username, role, provider);
    let response = issue_tokens(&session, &state.jwt_secret)?;
    persist_console_session(state, session.clone()).await?;
    Ok((response, session))
}

pub(crate) async fn revoke_console_session(
    state: &AppState,
    session_id: &str,
    revoked_reason: &str,
) -> Result<Option<ConsoleSession>, AppError> {
    let previous_sessions = state.admin_sessions.read().await.clone();
    let mut next_sessions = previous_sessions.clone();
    let revoked = {
        let mut revoked_session = None;
        for session in next_sessions.iter_mut() {
            if session.session_id == session_id {
                session.status = "revoked".to_string();
                session.revoked_at = Some(Utc::now());
                session.revoked_reason = Some(revoked_reason.to_string());
                revoked_session = Some(session.clone());
                break;
            }
        }
        revoked_session
    };

    if revoked.is_none() {
        return Ok(None);
    }
    {
        let mut sessions = state.admin_sessions.write().await;
        *sessions = next_sessions.clone();
    }

    if let Err(err) = AppState::persist_console_sessions_snapshot(&state.data_dir, &next_sessions) {
        *state.admin_sessions.write().await = previous_sessions;
        return Err(AppError::internal(format!(
            "持久化控制台会话撤销失败 / failed to persist console session revocation: {err}"
        )));
    }

    if let Some(session) = revoked.as_ref() {
        state.broadcast_console_session_runtime(session).await;
    }

    Ok(revoked)
}

pub(crate) async fn list_auth_providers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiEnvelope<Vec<AuthProviderInfo>>>, AppError> {
    let security = state.security.read().await.clone();
    let oidc_missing = oidc_missing_requirements(&security);
    let ldap_missing = ldap_missing_requirements(&security);
    Ok(wrap(vec![
        AuthProviderInfo {
            id: "local".to_string(),
            enabled: true,
            configured: true,
            supports_username_password: true,
            supports_browser_redirect: false,
            supports_id_token: false,
            authorize_url: None,
            missing_requirements: Vec::new(),
        },
        AuthProviderInfo {
            id: "oidc".to_string(),
            enabled: security.oidc_enabled && oidc_missing.is_empty(),
            configured: oidc_missing.is_empty(),
            supports_username_password: false,
            supports_browser_redirect: true,
            supports_id_token: true,
            authorize_url: Some("/api/v1/auth/oidc/authorize".to_string()),
            missing_requirements: oidc_missing,
        },
        AuthProviderInfo {
            id: "ldap".to_string(),
            enabled: security.ldap_enabled && ldap_missing.is_empty(),
            configured: ldap_missing.is_empty(),
            supports_username_password: true,
            supports_browser_redirect: false,
            supports_id_token: false,
            authorize_url: None,
            missing_requirements: ldap_missing,
        },
    ]))
}

pub(crate) async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::LoginResponse>>, AppError> {
    let provider = body
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|provider| !provider.is_empty())
        .map(|provider| provider.to_ascii_lowercase());
    let security = state.security.read().await.clone();

    if matches!(provider.as_deref(), Some("oidc")) {
        let profile = authenticate_oidc_identity(&security, &body).await?;
        sync_external_identity_profile(&state, &profile).await?;
        let (response, session) =
            create_console_login_response(state.as_ref(), &profile.username, &profile.role, "oidc")
                .await?;
        state
            .append_runtime_audit(
                &profile.username,
                "auth.login.oidc",
                "session",
                "success",
                None,
                json!({
                    "role": profile.role,
                    "groups": profile.groups,
                    "provider": profile.provider,
                    "session_id": session.session_id
                }),
            )
            .await;
        return Ok(wrap(response));
    }

    if matches!(provider.as_deref(), Some("ldap")) {
        let profile = authenticate_ldap_identity(&security, &body).await?;
        sync_external_identity_profile(&state, &profile).await?;
        let (response, session) =
            create_console_login_response(state.as_ref(), &profile.username, &profile.role, "ldap")
                .await?;
        state
            .append_runtime_audit(
                &profile.username,
                "auth.login.ldap",
                "session",
                "success",
                None,
                json!({
                    "role": profile.role,
                    "groups": profile.groups,
                    "provider": profile.provider,
                    "session_id": session.session_id
                }),
            )
            .await;
        return Ok(wrap(response));
    }

    if let Some(provider) = provider {
        return Err(AppError::bad_request(format!(
            "不支持的登录提供方 / unsupported login provider: {provider}"
        )));
    }

    let credentials = state.credentials.read().await;
    let found = credentials
        .get(&body.username)
        .ok_or_else(|| AppError::unauthorized("凭证无效 / invalid credentials"))?;

    if found.password != body.password {
        return Err(AppError::unauthorized("凭证无效 / invalid credentials"));
    }

    if let Some(user) = state
        .users
        .read()
        .await
        .iter()
        .find(|item| item.username == body.username)
        .cloned()
    {
        if !user.enabled {
            return Err(AppError::unauthorized("用户已禁用 / user is disabled"));
        }
    }

    let (response, session) =
        create_console_login_response(state.as_ref(), &body.username, &found.role, "local").await?;
    state
        .append_runtime_audit(
            &body.username,
            "auth.login",
            "session",
            "success",
            None,
            json!({ "role": found.role, "session_id": session.session_id }),
        )
        .await;
    Ok(wrap(response))
}

pub(crate) async fn refresh_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RefreshTokenRequest>>,
) -> Result<Json<ApiEnvelope<rustio_core::LoginResponse>>, AppError> {
    let refresh_token = body
        .map(|payload| payload.0.refresh_token)
        .filter(|token| !token.trim().is_empty())
        .or_else(|| extract_access_token(&headers, None))
        .ok_or_else(|| AppError::bad_request("缺少刷新令牌 / missing refresh token"))?;
    let (_, current_session) = validate_refresh_token(&refresh_token, state.as_ref()).await?;
    let effective_role = state
        .users
        .read()
        .await
        .iter()
        .find(|user| user.username == current_session.principal)
        .map(|user| user.role.clone())
        .unwrap_or_else(|| current_session.role.clone());
    let mut next_session = refresh_console_session(&current_session);
    next_session.role = effective_role;
    next_session.permissions = rustio_core::permissions_for_role(&next_session.role)
        .into_iter()
        .map(|permission| permission.as_str().to_string())
        .collect();
    let response = issue_tokens(&next_session, &state.jwt_secret)?;
    persist_console_session(state.as_ref(), next_session.clone()).await?;
    state
        .append_runtime_audit(
            &next_session.principal,
            "auth.refresh",
            "session",
            "success",
            None,
            json!({
                "session_id": next_session.session_id,
                "provider": next_session.provider
            }),
        )
        .await;
    Ok(wrap(response))
}

pub(crate) async fn logout(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    let session_id = auth.claims.session_id.clone();
    let revoked = revoke_console_session(
        state.as_ref(),
        &session_id,
        "用户主动退出 / user requested logout",
    )
    .await?;
    state
        .append_runtime_audit(
            &auth.username,
            "auth.logout",
            "session",
            "success",
            None,
            json!({
                "session_id": session_id,
                "revoked": revoked.is_some()
            }),
        )
        .await;
    Ok(wrap(json!({
        "logged_out": true,
        "session_id": auth.claims.session_id
    })))
}

pub(crate) async fn current_console_session(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<ConsoleSession>>, AppError> {
    let mut session = state
        .admin_sessions
        .read()
        .await
        .iter()
        .find(|session| session.session_id == auth.claims.session_id)
        .cloned()
        .ok_or_else(|| {
            AppError::unauthorized("会话不存在或已失效 / session does not exist or has expired")
        })?;
    session.role = auth.claims.role.clone();
    session.permissions = auth.claims.permissions.clone();
    Ok(wrap(session))
}

pub(crate) async fn list_console_sessions(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<ConsoleSession>>>, AppError> {
    auth.require(Permission::IamRead)?;
    let mut sessions = state.admin_sessions.read().await.clone();
    sessions.sort_by(|left, right| {
        right
            .issued_at
            .cmp(&left.issued_at)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    Ok(wrap(sessions))
}

pub(crate) async fn delete_console_session(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(session_id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    let target_session = state
        .admin_sessions
        .read()
        .await
        .iter()
        .find(|session| session.session_id == session_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("控制台会话不存在 / console session not found"))?;

    let can_revoke_other = auth.claims.has_permission(Permission::IamWrite);
    if auth.claims.session_id != session_id
        && auth.username != target_session.principal
        && !can_revoke_other
    {
        return Err(AppError::forbidden(
            "无权回收其他用户会话 / not allowed to revoke another user's session",
        ));
    }

    let revoked = revoke_console_session(
        state.as_ref(),
        &session_id,
        &format!(
            "{} 主动回收会话 / {} revoked session",
            auth.username, auth.username
        ),
    )
    .await?;
    let revoked_session = revoked.unwrap_or(target_session.clone());
    let already_revoked = target_session.status != "active";

    state
        .append_runtime_audit(
            &auth.username,
            "auth.session.revoke",
            &format!("auth/session/{session_id}"),
            "success",
            None,
            json!({
                "principal": revoked_session.principal,
                "provider": revoked_session.provider,
                "already_revoked": already_revoked
            }),
        )
        .await;

    Ok(wrap(json!({
        "revoked": true,
        "already_revoked": already_revoked,
        "session_id": session_id
    })))
}
