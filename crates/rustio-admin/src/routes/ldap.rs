//! LDAP 认证与外部身份同步

use super::*;

pub(crate) fn ldap_url(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.ldap_url, "RUSTIO_LDAP_URL")
}

pub(crate) fn ldap_bind_dn(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.ldap_bind_dn, "RUSTIO_LDAP_BIND_DN")
}

pub(crate) fn ldap_bind_password(_security: &rustio_core::SecurityConfig) -> Option<String> {
    env_trimmed("RUSTIO_LDAP_BIND_PASSWORD")
}

pub(crate) fn ldap_missing_requirements(security: &rustio_core::SecurityConfig) -> Vec<String> {
    let mut missing = Vec::new();
    if ldap_url(security).is_none() {
        missing.push("ldap_url".to_string());
    }
    if ldap_user_base_dn(security).is_none() {
        missing.push("ldap_user_base_dn".to_string());
    }
    missing
}

pub(crate) fn ensure_ldap_login_available(
    security: &rustio_core::SecurityConfig,
) -> Result<Vec<String>, AppError> {
    if !security.ldap_enabled {
        return Err(AppError::forbidden(
            "LDAP 登录未启用 / ldap login is disabled",
        ));
    }
    let missing = ldap_missing_requirements(security);
    if !missing.is_empty() {
        let joined = missing.join(", ");
        return Err(AppError::forbidden(format!(
            "LDAP 登录未完成配置，缺少 {} / ldap login is not fully configured, missing {}",
            joined, joined
        )));
    }
    Ok(missing)
}

pub(crate) fn ldap_user_base_dn(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.ldap_user_base_dn, "RUSTIO_LDAP_USER_BASE_DN")
}

pub(crate) fn ldap_user_filter_template(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(
        &security.ldap_user_filter,
        "RUSTIO_LDAP_USER_FILTER",
        "(uid={username})",
    )
}

pub(crate) fn ldap_group_base_dn(security: &rustio_core::SecurityConfig) -> Option<String> {
    configured_text(&security.ldap_group_base_dn, "RUSTIO_LDAP_GROUP_BASE_DN")
}

pub(crate) fn ldap_group_filter_template(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(
        &security.ldap_group_filter,
        "RUSTIO_LDAP_GROUP_FILTER",
        "(member={user_dn})",
    )
}

pub(crate) fn ldap_group_attribute(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(
        &security.ldap_group_attribute,
        "RUSTIO_LDAP_GROUP_ATTRIBUTE",
        "memberOf",
    )
}

pub(crate) fn ldap_group_name_attribute(security: &rustio_core::SecurityConfig) -> String {
    configured_or_default_env_first(
        &security.ldap_group_name_attribute,
        "RUSTIO_LDAP_GROUP_NAME_ATTRIBUTE",
        "cn",
    )
}

pub(crate) fn ldap_default_role(security: &rustio_core::SecurityConfig) -> String {
    configured_text_env_first(&security.ldap_default_role, "RUSTIO_LDAP_DEFAULT_ROLE")
        .and_then(|role| normalize_role_name(&role))
        .unwrap_or_else(|| "viewer".to_string())
}

pub(crate) fn ldap_role_mapping(security: &rustio_core::SecurityConfig) -> RoleMappings {
    parse_role_mapping(configured_text(
        &security.ldap_group_role_map,
        "RUSTIO_LDAP_GROUP_ROLE_MAP",
    ))
}

pub(crate) fn ldap_escape_filter_value(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'*' => escaped.push_str("\\2a"),
            b'(' => escaped.push_str("\\28"),
            b')' => escaped.push_str("\\29"),
            b'\\' => escaped.push_str("\\5c"),
            0 => escaped.push_str("\\00"),
            _ => escaped.push(*byte as char),
        }
    }
    escaped
}

pub(crate) fn render_ldap_filter(template: &str, username: &str, user_dn: &str) -> String {
    template
        .replace("{username}", &ldap_escape_filter_value(username))
        .replace("{user_dn}", &ldap_escape_filter_value(user_dn))
}

pub(crate) fn ldap_group_name_from_dn(dn: &str, attribute_name: &str) -> Option<String> {
    let attribute_name = if attribute_name.trim().is_empty() {
        "cn"
    } else {
        attribute_name.trim()
    };
    dn.split(',').find_map(|segment| {
        let mut split = segment.trim().splitn(2, '=');
        let key = split.next()?.trim();
        let value = split.next()?.trim();
        key.eq_ignore_ascii_case(attribute_name)
            .then_some(value.to_string())
    })
}

pub(crate) fn ldap_search_single_user(
    ldap: &mut LdapConn,
    security: &rustio_core::SecurityConfig,
    username: &str,
) -> Result<SearchEntry, AppError> {
    let base_dn = ldap_user_base_dn(security).ok_or_else(|| {
        AppError::internal("LDAP 用户 Base DN 未配置 / ldap user base dn is not configured")
    })?;
    let group_attr = ldap_group_attribute(security);
    let (entries, _result) = ldap
        .search(
            &base_dn,
            Scope::Subtree,
            &render_ldap_filter(&ldap_user_filter_template(security), username, ""),
            vec!["uid", "dn", "cn", "displayName", group_attr.as_str()],
        )
        .map_err(|err| {
            AppError::internal(format!(
                "执行 LDAP 用户查询失败 / failed to execute ldap user search: {err}"
            ))
        })?
        .success()
        .map_err(|err| {
            AppError::unauthorized(format!(
                "LDAP 用户查询被拒绝 / ldap user search was rejected: {err}"
            ))
        })?;
    entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| AppError::unauthorized("LDAP 用户不存在 / ldap user does not exist"))
}

pub(crate) fn ldap_collect_groups(
    ldap: &mut LdapConn,
    security: &rustio_core::SecurityConfig,
    user_entry: &SearchEntry,
) -> Result<Vec<String>, AppError> {
    let group_attr = ldap_group_attribute(security);
    let group_name_attr = ldap_group_name_attribute(security);
    let mut groups = user_entry
        .attrs
        .get(&group_attr)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| ldap_group_name_from_dn(&value, &group_name_attr).or(Some(value)))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    if groups.is_empty() {
        if let Some(group_base_dn) = ldap_group_base_dn(security) {
            let (entries, _result) = ldap
                .search(
                    &group_base_dn,
                    Scope::Subtree,
                    &render_ldap_filter(
                        &ldap_group_filter_template(security),
                        &user_entry.dn,
                        &user_entry.dn,
                    ),
                    vec!["dn", group_name_attr.as_str()],
                )
                .map_err(|err| {
                    AppError::internal(format!(
                        "执行 LDAP 用户组查询失败 / failed to execute ldap group search: {err}"
                    ))
                })?
                .success()
                .map_err(|err| {
                    AppError::unauthorized(format!(
                        "LDAP 用户组查询被拒绝 / ldap group search was rejected: {err}"
                    ))
                })?;
            for entry in entries.into_iter().map(SearchEntry::construct) {
                if let Some(values) = entry.attrs.get(&group_name_attr) {
                    groups.extend(values.iter().filter(|value| !value.is_empty()).cloned());
                } else if let Some(name) = ldap_group_name_from_dn(&entry.dn, &group_name_attr) {
                    groups.push(name);
                }
            }
        }
    }

    groups.sort();
    groups.dedup();
    Ok(groups)
}

pub(crate) fn authenticate_ldap_identity_blocking(
    username: String,
    password: String,
    security: rustio_core::SecurityConfig,
) -> Result<ExternalIdentityProfile, AppError> {
    let url = ldap_url(&security)
        .ok_or_else(|| AppError::internal("LDAP 地址未配置 / ldap url is not configured"))?;

    let mut lookup_ldap = LdapConn::new(&url).map_err(|err| {
        AppError::internal(format!("连接 LDAP 失败 / failed to connect to ldap: {err}"))
    })?;
    if let Some(bind_dn) = ldap_bind_dn(&security) {
        let bind_password = ldap_bind_password(&security).unwrap_or_default();
        lookup_ldap
            .simple_bind(&bind_dn, &bind_password)
            .map_err(|err| {
                AppError::internal(format!(
                    "LDAP 管理绑定失败 / ldap administrative bind failed: {err}"
                ))
            })?
            .success()
            .map_err(|err| {
                AppError::internal(format!(
                    "LDAP 管理绑定被拒绝 / ldap administrative bind was rejected: {err}"
                ))
            })?;
    }
    let user_entry = ldap_search_single_user(&mut lookup_ldap, &security, &username)?;
    let user_dn = user_entry.dn.clone();

    let mut user_ldap = LdapConn::new(&url).map_err(|err| {
        AppError::internal(format!(
            "建立 LDAP 用户会话失败 / failed to establish ldap user session: {err}"
        ))
    })?;
    user_ldap
        .simple_bind(&user_dn, &password)
        .map_err(|err| {
            AppError::unauthorized(format!("LDAP 用户绑定失败 / ldap user bind failed: {err}"))
        })?
        .success()
        .map_err(|err| {
            AppError::unauthorized(format!(
                "LDAP 用户名或密码无效 / ldap username or password is invalid: {err}"
            ))
        })?;

    let groups = ldap_collect_groups(&mut lookup_ldap, &security, &user_entry)?;
    let display_name = user_entry
        .attrs
        .get("displayName")
        .and_then(|values| values.first().cloned())
        .or_else(|| {
            user_entry
                .attrs
                .get("cn")
                .and_then(|values| values.first().cloned())
        })
        .unwrap_or_else(|| username.clone());
    let record = LdapIdentityRecord {
        username: user_entry
            .attrs
            .get("uid")
            .and_then(|values| values.first().cloned())
            .unwrap_or(username),
        display_name,
        groups,
    };

    let _ = user_ldap.unbind();
    let _ = lookup_ldap.unbind();

    Ok(ExternalIdentityProfile {
        username: record.username,
        role: resolve_external_role(
            None,
            &record.groups,
            &ldap_role_mapping(&security),
            &ldap_default_role(&security),
        ),
        display_name: record.display_name,
        groups: record.groups,
        provider: "ldap".to_string(),
        subject: None,
        audience: None,
    })
}

pub(crate) async fn authenticate_ldap_identity(
    security: &rustio_core::SecurityConfig,
    body: &LoginRequest,
) -> Result<ExternalIdentityProfile, AppError> {
    ensure_ldap_login_available(security)?;
    let username = body.username.trim().to_string();
    if username.is_empty() {
        return Err(AppError::bad_request(
            "LDAP 用户名不能为空 / ldap username cannot be empty",
        ));
    }
    let password = body.password.clone();
    if password.trim().is_empty() {
        return Err(AppError::bad_request(
            "LDAP 密码不能为空 / ldap password cannot be empty",
        ));
    }
    let security = security.clone();
    tokio::task::spawn_blocking(move || {
        authenticate_ldap_identity_blocking(username, password, security)
    })
    .await
    .map_err(|err| {
        AppError::internal(format!(
            "LDAP 认证任务失败 / ldap authentication task failed: {err}"
        ))
    })?
}

pub(crate) async fn sync_external_identity_profile(
    state: &AppState,
    profile: &ExternalIdentityProfile,
) -> Result<(), AppError> {
    let rollback = capture_iam_runtime_snapshot(state).await;
    {
        let mut users = state.users.write().await;
        if let Some(user) = users
            .iter_mut()
            .find(|user| user.username == profile.username)
        {
            if !user.enabled {
                return Err(AppError::unauthorized("用户已禁用 / user is disabled"));
            }
            user.display_name = profile.display_name.clone();
            user.role = profile.role.clone();
        } else {
            users.push(IamUser {
                username: profile.username.clone(),
                display_name: profile.display_name.clone(),
                role: profile.role.clone(),
                enabled: true,
                created_at: Utc::now(),
            });
        }
    }

    {
        let desired_groups = profile
            .groups
            .iter()
            .map(|group_name| group_name.trim())
            .filter(|group_name| !group_name.is_empty())
            .map(str::to_string)
            .collect::<HashSet<_>>();
        let mut groups = state.groups.write().await;

        for group in groups.iter_mut() {
            if !group
                .members
                .iter()
                .any(|member| member == &profile.username)
            {
                continue;
            }
            if !desired_groups.contains(&group.name) {
                group.members.retain(|member| member != &profile.username);
            }
        }

        for group_name in desired_groups {
            if let Some(group) = groups.iter_mut().find(|group| group.name == group_name) {
                if !group
                    .members
                    .iter()
                    .any(|member| member == &profile.username)
                {
                    group.members.push(profile.username.clone());
                }
                continue;
            }
            groups.push(IamGroup {
                name: group_name,
                members: vec![profile.username.clone()],
            });
        }
    }
    align_console_sessions_for_principal_in_memory(state, &profile.username, &profile.role).await;
    commit_iam_runtime_change(state, "external-identity-sync", rollback).await?;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct IamRuntimeSnapshot {
    pub(crate) credentials: HashMap<String, LocalCredential>,
    pub(crate) users: Vec<IamUser>,
    pub(crate) groups: Vec<IamGroup>,
    pub(crate) policies: Vec<IamPolicy>,
    pub(crate) service_accounts: Vec<rustio_core::ServiceAccount>,
    pub(crate) admin_sessions: Vec<ConsoleSession>,
    pub(crate) sts_sessions: Vec<rustio_core::StsSession>,
}
