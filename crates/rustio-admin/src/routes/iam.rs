//! IAM 用户、组、策略、服务账号

use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct CreateUserRequest {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) display_name: String,
    pub(crate) role: String,
}

pub(crate) async fn list_users(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<IamUser>>>, AppError> {
    auth.require(Permission::IamRead)?;
    Ok(wrap(state.users.read().await.clone()))
}

pub(crate) async fn create_user(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateUserRequest>,
) -> Result<Json<ApiEnvelope<IamUser>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.username.trim().is_empty() {
        return Err(AppError::bad_request(
            "用户名不能为空 / username cannot be empty",
        ));
    }
    if body.password.trim().is_empty() {
        return Err(AppError::bad_request(
            "密码不能为空 / password cannot be empty",
        ));
    }
    if state
        .users
        .read()
        .await
        .iter()
        .any(|item| item.username == body.username)
    {
        return Err(AppError::bad_request("用户已存在 / user already exists"));
    }

    state.credentials.write().await.insert(
        body.username.clone(),
        LocalCredential {
            password: body.password,
            role: body.role.clone(),
        },
    );

    let user = IamUser {
        username: body.username,
        display_name: body.display_name,
        role: body.role,
        enabled: true,
        created_at: Utc::now(),
    };

    state.users.write().await.push(user.clone());
    commit_iam_runtime_change(state.as_ref(), "iam-user-create", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.user.create",
            &format!("iam/user/{}", user.username),
            "success",
            None,
            json!({ "role": user.role }),
        )
        .await;
    Ok(wrap(user))
}

pub(crate) async fn enable_user(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(username): Path<String>,
) -> Result<Json<ApiEnvelope<IamUser>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;

    let snapshot = {
        let mut users = state.users.write().await;
        let user = users
            .iter_mut()
            .find(|item| item.username == username)
            .ok_or_else(|| AppError::not_found("用户不存在 / user not found"))?;
        user.enabled = true;
        user.clone()
    };

    commit_iam_runtime_change(state.as_ref(), "iam-user-enable", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.user.enable",
            &format!("iam/user/{username}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn disable_user(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(username): Path<String>,
) -> Result<Json<ApiEnvelope<IamUser>>, AppError> {
    auth.require(Permission::IamWrite)?;
    if auth.username == username {
        return Err(AppError::precondition(
            "不能禁用当前用户 / cannot disable current user",
        ));
    }
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;

    let snapshot = {
        let mut users = state.users.write().await;
        let enabled_admin_count = users
            .iter()
            .filter(|item| item.role == "admin" && item.enabled)
            .count();
        let user = users
            .iter_mut()
            .find(|item| item.username == username)
            .ok_or_else(|| AppError::not_found("用户不存在 / user not found"))?;
        if user.role == "admin" && user.enabled && enabled_admin_count <= 1 {
            return Err(AppError::precondition(
                "at least one enabled admin is required",
            ));
        }
        user.enabled = false;
        user.clone()
    };
    let revoked_console_sessions = revoke_console_sessions_for_principal_in_memory(
        state.as_ref(),
        &username,
        "用户已禁用 / user disabled",
    )
    .await;

    commit_iam_runtime_change(state.as_ref(), "iam-user-disable", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.user.disable",
            &format!("iam/user/{username}"),
            "success",
            None,
            json!({ "revoked_console_sessions": revoked_console_sessions }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn delete_user(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(username): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::IamWrite)?;
    if auth.username == username {
        return Err(AppError::precondition(
            "不能删除当前用户 / cannot delete current user",
        ));
    }
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;

    let deleted_user = {
        let mut users = state.users.write().await;
        let enabled_admin_count = users
            .iter()
            .filter(|item| item.role == "admin" && item.enabled)
            .count();
        let index = users
            .iter()
            .position(|item| item.username == username)
            .ok_or_else(|| AppError::not_found("用户不存在 / user not found"))?;
        let candidate = users[index].clone();
        if candidate.role == "admin" && candidate.enabled && enabled_admin_count <= 1 {
            return Err(AppError::precondition(
                "at least one enabled admin is required",
            ));
        }
        users.remove(index)
    };

    state.credentials.write().await.remove(&username);

    let removed_group_memberships = {
        let mut groups = state.groups.write().await;
        let mut removed = 0usize;
        for group in groups.iter_mut() {
            let before = group.members.len();
            group.members.retain(|member| member != &username);
            removed += before.saturating_sub(group.members.len());
        }
        removed
    };

    let removed_policy_attachments = {
        let mut policies = state.policies.write().await;
        let mut removed = 0usize;
        for policy in policies.iter_mut() {
            let before = policy.attached_to.len();
            policy
                .attached_to
                .retain(|principal| principal != &username);
            removed += before.saturating_sub(policy.attached_to.len());
        }
        removed
    };

    let removed_service_accounts = {
        let mut service_accounts = state.service_accounts.write().await;
        let before = service_accounts.len();
        service_accounts.retain(|item| item.owner != username.as_str());
        before.saturating_sub(service_accounts.len())
    };

    let removed_sts_sessions = {
        let mut sessions = state.sts_sessions.write().await;
        let before = sessions.len();
        sessions.retain(|session| session.principal != username.as_str());
        before.saturating_sub(sessions.len())
    };

    let removed_console_session_ids = {
        let mut sessions = state.admin_sessions.write().await;
        let removed = sessions
            .iter()
            .filter(|session| session.principal == username.as_str())
            .map(|session| session.session_id.clone())
            .collect::<Vec<_>>();
        sessions.retain(|session| session.principal != username.as_str());
        removed
    };
    let removed_console_sessions = removed_console_session_ids.len();

    commit_iam_runtime_change(state.as_ref(), "iam-user-delete", rollback).await?;
    for session_id in &removed_console_session_ids {
        state
            .broadcast_console_session_delete_runtime(session_id)
            .await;
    }

    state
        .append_audit(
            &auth.username,
            "iam.user.delete",
            &format!("iam/user/{username}"),
            "success",
            None,
            json!({
                "removed_group_memberships": removed_group_memberships,
                "removed_policy_attachments": removed_policy_attachments,
                "removed_service_accounts": removed_service_accounts,
                "removed_sts_sessions": removed_sts_sessions,
                "removed_console_sessions": removed_console_sessions,
                "role": deleted_user.role,
            }),
        )
        .await;

    Ok(wrap(json!({
        "deleted": true,
        "username": username,
        "removed_group_memberships": removed_group_memberships,
        "removed_policy_attachments": removed_policy_attachments,
        "removed_service_accounts": removed_service_accounts,
        "removed_sts_sessions": removed_sts_sessions,
        "removed_console_sessions": removed_console_sessions,
    })))
}

pub(crate) async fn list_groups(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::IamGroup>>>, AppError> {
    auth.require(Permission::IamRead)?;
    Ok(wrap(state.groups.read().await.clone()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateGroupRequest {
    pub(crate) name: String,
}

pub(crate) async fn create_group(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateGroupRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::IamGroup>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "用户组名称不能为空 / group name cannot be empty",
        ));
    }

    let group = {
        let mut groups = state.groups.write().await;
        if groups.iter().any(|group| group.name == body.name) {
            return Err(AppError::bad_request("用户组已存在 / group already exists"));
        }

        let group = rustio_core::IamGroup {
            name: body.name,
            members: Vec::new(),
        };
        groups.push(group.clone());
        group
    };

    commit_iam_runtime_change(state.as_ref(), "iam-group-create", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.group.create",
            &format!("iam/group/{}", group.name),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(group))
}

#[derive(Debug, Deserialize)]
pub(crate) struct GroupMemberRequest {
    pub(crate) username: String,
}

pub(crate) async fn add_group_member(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<GroupMemberRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::IamGroup>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.username.trim().is_empty() {
        return Err(AppError::bad_request(
            "用户名不能为空 / username cannot be empty",
        ));
    }

    if !state
        .users
        .read()
        .await
        .iter()
        .any(|user| user.username == body.username)
    {
        return Err(AppError::not_found("用户不存在 / user not found"));
    }

    let snapshot = {
        let mut groups = state.groups.write().await;
        let group = groups
            .iter_mut()
            .find(|group| group.name == name)
            .ok_or_else(|| AppError::not_found("用户组不存在 / group not found"))?;
        if !group.members.iter().any(|member| member == &body.username) {
            group.members.push(body.username.clone());
        }
        group.clone()
    };

    commit_iam_runtime_change(state.as_ref(), "iam-group-member-add", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.group.member.add",
            &format!("iam/group/{}", snapshot.name),
            "success",
            None,
            json!({ "username": body.username }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn remove_group_member(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path((name, username)): Path<(String, String)>,
) -> Result<Json<ApiEnvelope<rustio_core::IamGroup>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    let snapshot = {
        let mut groups = state.groups.write().await;
        let group = groups
            .iter_mut()
            .find(|group| group.name == name)
            .ok_or_else(|| AppError::not_found("用户组不存在 / group not found"))?;
        let before = group.members.len();
        group.members.retain(|member| member != &username);
        if before == group.members.len() {
            return Err(AppError::not_found(
                "用户组成员不存在 / group member not found",
            ));
        }
        group.clone()
    };

    commit_iam_runtime_change(state.as_ref(), "iam-group-member-remove", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.group.member.remove",
            &format!("iam/group/{}", snapshot.name),
            "success",
            None,
            json!({ "username": username }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn list_policies(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<IamPolicy>>>, AppError> {
    auth.require(Permission::IamRead)?;
    Ok(wrap(state.policies.read().await.clone()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreatePolicyRequest {
    pub(crate) name: String,
    pub(crate) document: serde_json::Value,
}

pub(crate) async fn create_policy(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreatePolicyRequest>,
) -> Result<Json<ApiEnvelope<IamPolicy>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    let policy = IamPolicy {
        name: body.name,
        document: body.document,
        attached_to: Vec::new(),
    };
    {
        let mut policies = state.policies.write().await;
        policies.push(policy.clone());
    }
    commit_iam_runtime_change(state.as_ref(), "iam-policy-create", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.policy.create",
            &format!("iam/policy/{}", policy.name),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(policy))
}

#[derive(Debug, Deserialize)]
pub(crate) struct PolicyPrincipalRequest {
    pub(crate) principal: String,
}

pub(crate) async fn attach_policy_principal(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<PolicyPrincipalRequest>,
) -> Result<Json<ApiEnvelope<IamPolicy>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.principal.trim().is_empty() {
        return Err(AppError::bad_request(
            "主体不能为空 / principal cannot be empty",
        ));
    }

    let snapshot = {
        let mut policies = state.policies.write().await;
        let policy = policies
            .iter_mut()
            .find(|policy| policy.name == name)
            .ok_or_else(|| AppError::not_found("策略不存在 / policy not found"))?;
        if !policy
            .attached_to
            .iter()
            .any(|item| item == &body.principal)
        {
            policy.attached_to.push(body.principal.clone());
        }
        policy.clone()
    };

    commit_iam_runtime_change(state.as_ref(), "iam-policy-attach", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.policy.attach",
            &format!("iam/policy/{}", snapshot.name),
            "success",
            None,
            json!({ "principal": body.principal }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn detach_policy_principal(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(name): Path<String>,
    Json(body): Json<PolicyPrincipalRequest>,
) -> Result<Json<ApiEnvelope<IamPolicy>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.principal.trim().is_empty() {
        return Err(AppError::bad_request(
            "主体不能为空 / principal cannot be empty",
        ));
    }

    let snapshot = {
        let mut policies = state.policies.write().await;
        let policy = policies
            .iter_mut()
            .find(|policy| policy.name == name)
            .ok_or_else(|| AppError::not_found("策略不存在 / policy not found"))?;
        let before = policy.attached_to.len();
        policy.attached_to.retain(|item| item != &body.principal);
        if before == policy.attached_to.len() {
            return Err(AppError::not_found("主体未绑定 / principal not attached"));
        }
        policy.clone()
    };

    commit_iam_runtime_change(state.as_ref(), "iam-policy-detach", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.policy.detach",
            &format!("iam/policy/{}", snapshot.name),
            "success",
            None,
            json!({ "principal": body.principal }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn list_service_accounts(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::ServiceAccount>>>, AppError> {
    auth.require(Permission::IamRead)?;
    Ok(wrap(state.service_accounts.read().await.clone()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateServiceAccountRequest {
    pub(crate) owner: String,
}

pub(crate) async fn create_service_account(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateServiceAccountRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::ServiceAccount>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.owner.trim().is_empty() {
        return Err(AppError::bad_request(
            "所有者不能为空 / owner cannot be empty",
        ));
    }

    if !state
        .users
        .read()
        .await
        .iter()
        .any(|user| user.username == body.owner)
    {
        return Err(AppError::not_found(
            "所有者用户不存在 / owner user not found",
        ));
    }

    let access_key = format!("sa-{}", Uuid::new_v4().simple());
    let secret_key = format!("sa-sk-{}", Uuid::new_v4().simple());
    let account = rustio_core::ServiceAccount {
        access_key: access_key.clone(),
        secret_key,
        owner: body.owner.clone(),
        created_at: Utc::now(),
        status: "enabled".to_string(),
    };

    {
        let mut service_accounts = state.service_accounts.write().await;
        service_accounts.push(account.clone());
    }
    commit_iam_runtime_change(state.as_ref(), "iam-service-account-create", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.service_account.create",
            &format!("iam/service-account/{access_key}"),
            "success",
            None,
            json!({ "owner": body.owner }),
        )
        .await;
    Ok(wrap(account))
}

pub(crate) async fn delete_service_account(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(access_key): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    {
        let mut accounts = state.service_accounts.write().await;
        let before = accounts.len();
        accounts.retain(|account| account.access_key != access_key);
        if before == accounts.len() {
            return Err(AppError::not_found(
                "服务账号不存在 / service account not found",
            ));
        }
    }

    commit_iam_runtime_change(state.as_ref(), "iam-service-account-delete", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.service_account.delete",
            &format!("iam/service-account/{access_key}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "access_key": access_key })))
}

pub(crate) async fn list_sts_sessions(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::StsSession>>>, AppError> {
    auth.require(Permission::IamRead)?;
    Ok(wrap(state.sts_sessions.read().await.clone()))
}

pub(crate) fn sanitize_sts_session_component(value: &str, fallback: &str) -> String {
    let sanitized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '=' | ',' | '.' | '@' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let sanitized = if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    };
    sanitized.chars().take(64).collect()
}

pub(crate) fn normalize_sts_role_arn(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn sts_policy_name_from_role_arn(role_arn: &str) -> Option<String> {
    let trimmed = role_arn.trim().trim_end_matches('/');
    let role_name = trimmed.rsplit('/').next()?.trim();
    (!role_name.is_empty()).then(|| role_name.to_string())
}

pub(crate) fn validate_sts_session_policy_document(
    policy: Value,
    source: &str,
) -> Result<Value, AppError> {
    if !policy.is_object() {
        return Err(AppError::bad_request(format!(
            "STS 会话策略必须是 JSON 对象 / sts session policy must be a JSON object: {source}"
        )));
    }
    if collect_policy_statements(&policy).is_empty() {
        return Err(AppError::bad_request(format!(
            "STS 会话策略至少需要一条 Statement / sts session policy must contain at least one statement: {source}"
        )));
    }
    Ok(policy)
}

pub(crate) fn parse_sts_session_policy_string(
    raw_policy: Option<&str>,
    source: &str,
) -> Result<Option<Value>, AppError> {
    let Some(raw_policy) = raw_policy.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if raw_policy.len() > 2_048 {
        return Err(AppError::bad_request(format!(
            "STS 会话策略不能超过 2048 个字符 / sts session policy cannot exceed 2048 characters: {source}"
        )));
    }
    let policy = serde_json::from_str::<Value>(raw_policy).map_err(|err| {
        AppError::bad_request(format!(
            "STS 会话策略 JSON 无法解析 / failed to parse sts session policy json: {err}"
        ))
    })?;
    validate_sts_session_policy_document(policy, source).map(Some)
}

pub(crate) fn normalize_sts_provider(provider: &str) -> String {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" => "manual".to_string(),
        "oidc" => "oidc".to_string(),
        "ldap" => "ldap".to_string(),
        _ => sanitize_sts_session_component(provider, "manual").to_ascii_lowercase(),
    }
}

pub(crate) async fn validate_sts_role_arn_exists(
    state: &Arc<AppState>,
    role_arn: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(role_arn) = role_arn.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let policy_name = sts_policy_name_from_role_arn(role_arn)
        .ok_or_else(|| AppError::bad_request("RoleArn 无效 / role arn is invalid"))?;
    let policy_exists = state
        .policies
        .read()
        .await
        .iter()
        .any(|policy| policy.name == policy_name);
    if !policy_exists {
        return Err(AppError::bad_request(format!(
            "RoleArn 对应的策略不存在 / role arn policy does not exist: {policy_name}"
        )));
    }
    Ok(Some(role_arn.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_sts_session(
    state: &Arc<AppState>,
    principal: &str,
    ttl_seconds: i64,
    provider: &str,
    session_name: Option<String>,
    role_arn: Option<String>,
    session_policy: Option<Value>,
    subject: Option<String>,
    audience: Option<String>,
) -> Result<rustio_core::StsSession, AppError> {
    let principal = principal.trim();
    if principal.is_empty() {
        return Err(AppError::bad_request(
            "主体不能为空 / principal cannot be empty",
        ));
    }
    let normalized_role_arn = validate_sts_role_arn_exists(state, role_arn.as_deref()).await?;
    let normalized_session_policy = match session_policy {
        Some(policy) => Some(validate_sts_session_policy_document(
            policy,
            "session_policy",
        )?),
        None => None,
    };
    let now = Utc::now();
    let session = rustio_core::StsSession {
        session_id: Uuid::new_v4().to_string(),
        principal: principal.to_string(),
        access_key: format!("sts-{}", Uuid::new_v4().simple()),
        secret_key: format!("sts-sk-{}", Uuid::new_v4().simple()),
        session_token: Uuid::new_v4().to_string(),
        provider: normalize_sts_provider(provider),
        role_arn: normalized_role_arn,
        session_name: Some(sanitize_sts_session_component(
            session_name.as_deref().unwrap_or(principal),
            principal,
        )),
        session_policy: normalized_session_policy,
        subject,
        audience,
        status: "active".to_string(),
        issued_at: now,
        expires_at: now + Duration::seconds(ttl_seconds),
    };

    {
        let mut sts_sessions = state.sts_sessions.write().await;
        sts_sessions.push(session.clone());
    }
    Ok(session)
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateStsSessionRequest {
    pub(crate) principal: String,
    pub(crate) ttl_minutes: Option<i64>,
    #[serde(default)]
    pub(crate) session_policy: Option<Value>,
}

pub(crate) async fn create_sts_session(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateStsSessionRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::StsSession>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    if body.principal.trim().is_empty() {
        return Err(AppError::bad_request(
            "主体不能为空 / principal cannot be empty",
        ));
    }

    if !state
        .users
        .read()
        .await
        .iter()
        .any(|user| user.username == body.principal)
    {
        return Err(AppError::not_found(
            "主体用户不存在 / principal user not found",
        ));
    }

    let ttl = body.ttl_minutes.unwrap_or(60).clamp(5, 7 * 24 * 60);
    let session = issue_sts_session(
        &state,
        &body.principal,
        ttl * 60,
        "manual",
        None,
        None,
        body.session_policy.clone(),
        None,
        None,
    )
    .await?;
    commit_iam_runtime_change(state.as_ref(), "iam-sts-session-create", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.sts_session.create",
            &format!("iam/sts-session/{}", session.session_id),
            "success",
            None,
            json!({
                "principal": body.principal,
                "ttl_minutes": ttl,
                "provider": session.provider,
                "role_arn": session.role_arn,
                "session_name": session.session_name,
                "has_session_policy": session.session_policy.is_some()
            }),
        )
        .await;
    Ok(wrap(session))
}

pub(crate) async fn delete_sts_session(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(session_id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::IamWrite)?;
    let rollback = capture_iam_runtime_snapshot(state.as_ref()).await;
    {
        let mut sessions = state.sts_sessions.write().await;
        let before = sessions.len();
        sessions.retain(|session| session.session_id != session_id);
        if before == sessions.len() {
            return Err(AppError::not_found(
                "STS 会话不存在 / sts session not found",
            ));
        }
    }

    commit_iam_runtime_change(state.as_ref(), "iam-sts-session-delete", rollback).await?;
    state
        .append_audit(
            &auth.username,
            "iam.sts_session.delete",
            &format!("iam/sts-session/{session_id}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "session_id": session_id })))
}
