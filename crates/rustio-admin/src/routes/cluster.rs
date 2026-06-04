//! 集群、租户、诊断、配置、备份

use super::*;

pub(crate) async fn cluster_health(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<ClusterHealth>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let nodes = state.nodes.read().await;
    let online = nodes.iter().filter(|node| node.online).count() as u32;
    let total = nodes.len() as u32;
    let status = if online == total {
        "healthy"
    } else if online == 0 {
        "critical"
    } else {
        "degraded"
    };

    Ok(wrap(ClusterHealth {
        status: status.to_string(),
        timestamp: Utc::now(),
        nodes_online: online,
        nodes_total: total,
    }))
}

pub(crate) async fn list_nodes(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::ClusterNode>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    Ok(wrap(state.nodes.read().await.clone()))
}

pub(crate) async fn set_node_offline(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::ClusterNode>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;

    let mut nodes = state.nodes.write().await;
    let node = nodes
        .iter_mut()
        .find(|n| n.id == id)
        .ok_or_else(|| AppError::not_found("节点不存在 / node not found"))?;
    node.online = false;
    node.last_heartbeat = Utc::now();
    let snapshot = node.clone();

    state
        .append_audit(
            &auth.username,
            "cluster.node.offline",
            &format!("node/{}", snapshot.id),
            "success",
            Some(body.reason.clone()),
            json!({ "online": false }),
        )
        .await;
    state
        .push_event(
            "cluster.node.offline",
            "cluster-service",
            json!({ "node": snapshot.id }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn set_node_online(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<rustio_core::ClusterNode>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;

    let mut nodes = state.nodes.write().await;
    let node = nodes
        .iter_mut()
        .find(|n| n.id == id)
        .ok_or_else(|| AppError::not_found("节点不存在 / node not found"))?;
    node.online = true;
    node.last_heartbeat = Utc::now();
    let snapshot = node.clone();

    state
        .append_audit(
            &auth.username,
            "cluster.node.online",
            &format!("node/{}", snapshot.id),
            "success",
            Some(body.reason.clone()),
            json!({ "online": true }),
        )
        .await;
    state
        .push_event(
            "cluster.node.online",
            "cluster-service",
            json!({ "node": snapshot.id }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn list_quotas(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::ClusterQuota>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let quotas = {
        let tenants = state.tenants.read().await;
        tenants
            .iter()
            .map(|tenant| rustio_core::ClusterQuota {
                tenant: tenant.id.clone(),
                hard_limit_bytes: tenant.hard_limit_bytes,
                used_bytes: tenant.used_bytes,
            })
            .collect::<Vec<_>>()
    };
    *state.quotas.write().await = quotas.clone();
    Ok(wrap(quotas))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateTenantRequest {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
    #[serde(default)]
    pub(crate) owner_group: Option<String>,
    pub(crate) hard_limit_bytes: u64,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) project_name: Option<String>,
    #[serde(default)]
    pub(crate) domain_id: Option<String>,
    #[serde(default)]
    pub(crate) domain_name: Option<String>,
    pub(crate) labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateTenantRequest {
    pub(crate) display_name: Option<String>,
    pub(crate) owner_group: Option<String>,
    pub(crate) hard_limit_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) project_name: Option<String>,
    #[serde(default)]
    pub(crate) domain_id: Option<String>,
    #[serde(default)]
    pub(crate) domain_name: Option<String>,
    pub(crate) labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct ListTenantsQuery {
    #[serde(default)]
    pub(crate) project_id: Option<String>,
    #[serde(default)]
    pub(crate) domain_id: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) status: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentityDomainView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) projects_total: usize,
    pub(crate) enabled_projects: usize,
}

pub(crate) fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

pub(crate) fn tenant_project_id_value(tenant: &TenantSpec) -> String {
    tenant
        .project_id
        .clone()
        .unwrap_or_else(|| tenant.id.clone())
}

pub(crate) fn tenant_project_name_value(tenant: &TenantSpec) -> String {
    tenant
        .project_name
        .clone()
        .unwrap_or_else(|| tenant.display_name.clone())
}

pub(crate) fn tenant_domain_id_value(tenant: &TenantSpec) -> String {
    tenant
        .domain_id
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

pub(crate) fn tenant_domain_name_value(tenant: &TenantSpec) -> String {
    tenant
        .domain_name
        .clone()
        .unwrap_or_else(|| "Default".to_string())
}

pub(crate) fn tenant_matches_identifier(tenant: &TenantSpec, identifier: &str) -> bool {
    let identifier = identifier.trim();
    !identifier.is_empty()
        && (tenant.id == identifier
            || tenant_project_id_value(tenant) == identifier
            || tenant_project_name_value(tenant) == identifier)
}

pub(crate) fn tenant_matches_domain_identifier(tenant: &TenantSpec, identifier: &str) -> bool {
    let identifier = identifier.trim();
    !identifier.is_empty()
        && (tenant_domain_id_value(tenant) == identifier
            || tenant_domain_name_value(tenant).eq_ignore_ascii_case(identifier))
}

pub(crate) fn ensure_unique_tenant_identity(
    tenants: &[TenantSpec],
    skip_tenant_id: Option<&str>,
    tenant_id: &str,
    project_id: &str,
) -> Result<(), AppError> {
    let tenant_conflict = tenants
        .iter()
        .any(|tenant| Some(tenant.id.as_str()) != skip_tenant_id && tenant.id == tenant_id);
    if tenant_conflict {
        return Err(AppError::bad_request("租户已存在 / tenant already exists"));
    }

    let project_conflict = tenants.iter().any(|tenant| {
        Some(tenant.id.as_str()) != skip_tenant_id && tenant_project_id_value(tenant) == project_id
    });
    if project_conflict {
        return Err(AppError::bad_request(
            "项目 ID 已存在 / project id already exists",
        ));
    }
    Ok(())
}

pub(crate) fn sync_quotas_from_tenants(tenants: &[TenantSpec]) -> Vec<rustio_core::ClusterQuota> {
    tenants
        .iter()
        .map(|tenant| rustio_core::ClusterQuota {
            tenant: tenant.id.clone(),
            hard_limit_bytes: tenant.hard_limit_bytes,
            used_bytes: tenant.used_bytes,
        })
        .collect::<Vec<_>>()
}

pub(crate) async fn list_tenants(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ListTenantsQuery>,
) -> Result<Json<ApiEnvelope<Vec<TenantSpec>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let mut tenants = state.tenants.read().await.clone();
    if let Some(project_id) = normalize_optional_text(query.project_id) {
        tenants.retain(|tenant| tenant_matches_identifier(tenant, &project_id));
    }
    if let Some(domain_id) = normalize_optional_text(query.domain_id) {
        tenants.retain(|tenant| tenant_matches_domain_identifier(tenant, &domain_id));
    }
    if let Some(enabled) = query.enabled {
        tenants.retain(|tenant| tenant.enabled == enabled);
    }
    if let Some(status) = normalize_optional_text(query.status) {
        tenants.retain(|tenant| tenant.status.eq_ignore_ascii_case(&status));
    }
    tenants.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(wrap(tenants))
}

pub(crate) async fn list_identity_domains(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<IdentityDomainView>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let tenants = state.tenants.read().await.clone();
    let mut domains = HashMap::<String, IdentityDomainView>::new();
    for tenant in tenants {
        let domain_id = tenant_domain_id_value(&tenant);
        let entry = domains
            .entry(domain_id.clone())
            .or_insert_with(|| IdentityDomainView {
                id: domain_id,
                name: tenant_domain_name_value(&tenant),
                projects_total: 0,
                enabled_projects: 0,
            });
        entry.projects_total += 1;
        if tenant.enabled {
            entry.enabled_projects += 1;
        }
    }
    let mut domains = domains.into_values().collect::<Vec<_>>();
    domains.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(wrap(domains))
}

pub(crate) async fn create_tenant(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateTenantRequest>,
) -> Result<Json<ApiEnvelope<TenantSpec>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    let id = normalize_optional_text(body.id)
        .or_else(|| normalize_optional_text(body.project_id.clone()))
        .ok_or_else(|| AppError::bad_request("租户 ID 不能为空 / tenant id cannot be empty"))?;
    let display_name = normalize_optional_text(body.display_name)
        .or_else(|| normalize_optional_text(body.project_name.clone()))
        .ok_or_else(|| {
            AppError::bad_request(
                "租户 display_name 不能为空 / tenant display_name cannot be empty",
            )
        })?;
    let owner_group = normalize_optional_text(body.owner_group).ok_or_else(|| {
        AppError::bad_request("租户 owner_group 不能为空 / tenant owner_group cannot be empty")
    })?;
    let project_id = normalize_optional_text(body.project_id).or_else(|| Some(id.clone()));
    let project_name =
        normalize_optional_text(body.project_name).or_else(|| Some(display_name.clone()));
    let domain_id = normalize_optional_text(body.domain_id).or_else(|| Some("default".to_string()));
    let domain_name =
        normalize_optional_text(body.domain_name).or_else(|| Some("Default".to_string()));
    if id.is_empty() {
        return Err(AppError::bad_request(
            "租户 ID 不能为空 / tenant id cannot be empty",
        ));
    }
    if display_name.is_empty() {
        return Err(AppError::bad_request(
            "租户 display_name 不能为空 / tenant display_name cannot be empty",
        ));
    }
    if owner_group.is_empty() {
        return Err(AppError::bad_request(
            "租户 owner_group 不能为空 / tenant owner_group cannot be empty",
        ));
    }
    if body.hard_limit_bytes == 0 {
        return Err(AppError::bad_request(
            "租户 hard_limit_bytes 必须大于 0 / tenant hard_limit_bytes must be > 0",
        ));
    }

    let now = Utc::now();
    let snapshot = {
        let mut tenants = state.tenants.write().await;
        ensure_unique_tenant_identity(
            &tenants,
            None,
            &id,
            project_id.as_deref().unwrap_or(id.as_str()),
        )?;
        let tenant = TenantSpec {
            id: id.clone(),
            display_name,
            owner_group,
            project_id,
            project_name,
            domain_id,
            domain_name,
            enabled: true,
            status: "active".to_string(),
            hard_limit_bytes: body.hard_limit_bytes,
            used_bytes: 0,
            created_at: now,
            updated_at: now,
            labels: body.labels.unwrap_or_default(),
        };
        tenants.push(tenant.clone());
        let quotas = sync_quotas_from_tenants(&tenants);
        *state.quotas.write().await = quotas;
        tenant
    };

    state
        .append_audit(
            &auth.username,
            "cluster.tenant.create",
            &format!("cluster/tenant/{id}"),
            "success",
            None,
            json!({
                "owner_group": snapshot.owner_group,
                "hard_limit_bytes": snapshot.hard_limit_bytes,
            }),
        )
        .await;
    state
        .push_event(
            "cluster.tenant.created",
            "cluster-tenant-service",
            json!({ "tenant": id }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn update_tenant(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<UpdateTenantRequest>,
) -> Result<Json<ApiEnvelope<TenantSpec>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    let now = Utc::now();
    let snapshot = {
        let mut tenants = state.tenants.write().await;
        let tenant_index = tenants
            .iter()
            .position(|tenant| tenant_matches_identifier(tenant, &id))
            .ok_or_else(|| AppError::not_found("租户不存在 / tenant not found"))?;
        let current = tenants[tenant_index].clone();
        let next_display_name = match body.display_name.as_ref() {
            Some(display_name) => {
                let trimmed = display_name.trim();
                if trimmed.is_empty() {
                    return Err(AppError::bad_request(
                        "租户 display_name 不能为空 / tenant display_name cannot be empty",
                    ));
                }
                trimmed.to_string()
            }
            None => current.display_name.clone(),
        };
        let next_project_id = normalize_optional_text(body.project_id.clone())
            .or(current.project_id.clone())
            .or_else(|| Some(current.id.clone()))
            .unwrap_or_else(|| current.id.clone());
        ensure_unique_tenant_identity(
            &tenants,
            Some(current.id.as_str()),
            &current.id,
            &next_project_id,
        )?;

        let tenant = &mut tenants[tenant_index];
        if let Some(display_name) = body.display_name.as_ref() {
            let trimmed = display_name.trim();
            if trimmed.is_empty() {
                return Err(AppError::bad_request(
                    "租户 display_name 不能为空 / tenant display_name cannot be empty",
                ));
            }
            tenant.display_name = trimmed.to_string();
        } else {
            tenant.display_name = next_display_name.clone();
        }
        if let Some(owner_group) = body.owner_group.as_ref() {
            let trimmed = owner_group.trim();
            if trimmed.is_empty() {
                return Err(AppError::bad_request(
                    "租户 owner_group 不能为空 / tenant owner_group cannot be empty",
                ));
            }
            tenant.owner_group = trimmed.to_string();
        }
        if let Some(hard_limit_bytes) = body.hard_limit_bytes {
            if hard_limit_bytes == 0 {
                return Err(AppError::bad_request(
                    "租户 hard_limit_bytes 必须大于 0 / tenant hard_limit_bytes must be > 0",
                ));
            }
            tenant.hard_limit_bytes = hard_limit_bytes;
        }
        if let Some(labels) = body.labels {
            tenant.labels = labels;
        }
        tenant.project_id = Some(next_project_id);
        if let Some(project_name) = normalize_optional_text(body.project_name) {
            tenant.project_name = Some(project_name);
        } else if tenant.project_name.is_none() {
            tenant.project_name = Some(tenant.display_name.clone());
        }
        if let Some(domain_id) = normalize_optional_text(body.domain_id) {
            tenant.domain_id = Some(domain_id);
        } else if tenant.domain_id.is_none() {
            tenant.domain_id = Some("default".to_string());
        }
        if let Some(domain_name) = normalize_optional_text(body.domain_name) {
            tenant.domain_name = Some(domain_name);
        } else if tenant.domain_name.is_none() {
            tenant.domain_name = Some("Default".to_string());
        }
        tenant.updated_at = now;
        let snapshot = tenant.clone();
        let quotas = sync_quotas_from_tenants(&tenants);
        *state.quotas.write().await = quotas;
        snapshot
    };

    state
        .append_audit(
            &auth.username,
            "cluster.tenant.update",
            &format!("cluster/tenant/{id}"),
            "success",
            None,
            json!({
                "enabled": snapshot.enabled,
                "status": snapshot.status,
                "hard_limit_bytes": snapshot.hard_limit_bytes,
            }),
        )
        .await;
    state
        .push_event(
            "cluster.tenant.updated",
            "cluster-tenant-service",
            json!({ "tenant": id }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn suspend_tenant(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<TenantSpec>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }

    let snapshot = {
        let mut tenants = state.tenants.write().await;
        let tenant = tenants
            .iter_mut()
            .find(|tenant| tenant_matches_identifier(tenant, &id))
            .ok_or_else(|| AppError::not_found("租户不存在 / tenant not found"))?;
        if !tenant.enabled {
            return Err(AppError::bad_request(
                "租户已是暂停状态 / tenant is already suspended",
            ));
        }
        tenant.enabled = false;
        tenant.status = "suspended".to_string();
        tenant.updated_at = Utc::now();
        tenant.clone()
    };

    state
        .append_audit(
            &auth.username,
            "cluster.tenant.suspend",
            &format!("cluster/tenant/{}", snapshot.id),
            "success",
            Some(body.reason),
            json!({ "status": snapshot.status }),
        )
        .await;
    state
        .push_event(
            "cluster.tenant.suspended",
            "cluster-tenant-service",
            json!({ "tenant": snapshot.id }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn resume_tenant(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<TenantSpec>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }

    let snapshot = {
        let mut tenants = state.tenants.write().await;
        let tenant = tenants
            .iter_mut()
            .find(|tenant| tenant_matches_identifier(tenant, &id))
            .ok_or_else(|| AppError::not_found("租户不存在 / tenant not found"))?;
        if tenant.enabled {
            return Err(AppError::bad_request(
                "租户已是激活状态 / tenant is already active",
            ));
        }
        tenant.enabled = true;
        tenant.status = "active".to_string();
        tenant.updated_at = Utc::now();
        tenant.clone()
    };

    state
        .append_audit(
            &auth.username,
            "cluster.tenant.resume",
            &format!("cluster/tenant/{}", snapshot.id),
            "success",
            Some(body.reason),
            json!({ "status": snapshot.status }),
        )
        .await;
    state
        .push_event(
            "cluster.tenant.resumed",
            "cluster-tenant-service",
            json!({ "tenant": snapshot.id }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DangerActionRequest>,
) -> Result<Json<ApiEnvelope<Value>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }

    let deleted_id = {
        let mut tenants = state.tenants.write().await;
        let tenant_index = tenants
            .iter()
            .position(|tenant| tenant_matches_identifier(tenant, &id))
            .ok_or_else(|| AppError::not_found("租户不存在 / tenant not found"))?;
        if tenants[tenant_index].id == "default" {
            return Err(AppError::bad_request(
                "默认租户不能删除 / default tenant cannot be deleted",
            ));
        }
        let deleted_id = tenants[tenant_index].id.clone();
        tenants.remove(tenant_index);
        let quotas = sync_quotas_from_tenants(&tenants);
        *state.quotas.write().await = quotas;
        deleted_id
    };

    state
        .append_audit(
            &auth.username,
            "cluster.tenant.delete",
            &format!("cluster/tenant/{deleted_id}"),
            "success",
            Some(body.reason),
            json!({ "deleted": true }),
        )
        .await;
    state
        .push_event(
            "cluster.tenant.deleted",
            "cluster-tenant-service",
            json!({ "tenant": deleted_id }),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "id": deleted_id })))
}

pub(crate) const SUPPORT_BUNDLE_FORMAT_VERSION: &str = "support-bundle.v1";
pub(crate) const INCIDENT_PACK_FORMAT_VERSION: &str = "incident-pack.v1";

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_diagnostic_limit() -> usize {
    25
}

pub(crate) fn support_bundle_sections() -> Vec<String> {
    [
        "cluster_config",
        "system_metrics",
        "raft_status",
        "replication",
        "kms_status",
        "audits",
        "jobs",
        "site_drift",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub(crate) fn incident_pack_sections() -> Vec<String> {
    let mut sections = support_bundle_sections();
    sections.extend(
        [
            "incident_summary",
            "triage_flow",
            "restore_playbook",
            "runbook_catalog",
        ]
        .into_iter()
        .map(str::to_string),
    );
    sections
}

pub(crate) fn normalize_diagnostic_kind(value: Option<&str>) -> Result<String, AppError> {
    match value
        .map(|item| item.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("") | Some("support-bundle") | Some("support_bundle") | Some("support") => {
            Ok("support-bundle".to_string())
        }
        Some("incident-pack") | Some("incident_pack") | Some("incident") => {
            Ok("incident-pack".to_string())
        }
        Some(other) => Err(AppError::bad_request(format!(
            "诊断包类型不支持：{other} / unsupported diagnostic kind: {other}"
        ))),
    }
}

pub(crate) fn normalize_incident_severity(value: Option<&str>) -> String {
    value
        .and_then(|item| {
            let trimmed = item.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_ascii_uppercase())
        })
        .unwrap_or_else(|| "P1".to_string())
}

pub(crate) fn diagnostic_format_version(kind: &str) -> &'static str {
    match kind {
        "incident-pack" => INCIDENT_PACK_FORMAT_VERSION,
        _ => SUPPORT_BUNDLE_FORMAT_VERSION,
    }
}

pub(crate) fn diagnostic_sections(kind: &str) -> Vec<String> {
    match kind {
        "incident-pack" => incident_pack_sections(),
        _ => support_bundle_sections(),
    }
}

pub(crate) fn support_bundle_summary() -> String {
    "离线支持包：配置、Raft、复制、KMS、审计与任务快照 / offline support bundle: config, raft, replication, kms, audit and jobs snapshot".to_string()
}

pub(crate) fn diagnostic_summary(kind: &str, query: &CreateDiagnosticQuery) -> String {
    match kind {
        "incident-pack" => {
            let summary = normalize_optional_text(query.incident_summary.clone())
                .unwrap_or_else(|| "待补充事件摘要 / incident summary pending".to_string());
            format!(
                "事件处置包：{} / incident response pack: {}",
                summary, summary
            )
        }
        _ => support_bundle_summary(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateDiagnosticQuery {
    #[serde(default = "default_true")]
    pub(crate) redact_sensitive: bool,
    #[serde(default = "default_diagnostic_limit")]
    pub(crate) audit_limit: usize,
    #[serde(default = "default_diagnostic_limit")]
    pub(crate) job_limit: usize,
    #[serde(default = "default_diagnostic_limit")]
    pub(crate) backlog_limit: usize,
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) incident_id: Option<String>,
    #[serde(default)]
    pub(crate) severity: Option<String>,
    #[serde(default)]
    pub(crate) incident_summary: Option<String>,
}

pub(crate) fn support_bundle_dir(state: &AppState) -> PathBuf {
    state.data_dir.join(".rustio_support_bundles")
}

pub(crate) fn support_bundle_path(state: &AppState, report_id: &str) -> PathBuf {
    support_bundle_dir(state).join(format!("{report_id}.json"))
}

pub(crate) fn support_bundle_download_name(report_id: &str) -> String {
    format!("rustio-support-bundle-{report_id}.json")
}

pub(crate) fn diagnostic_download_name(kind: &str, report_id: &str) -> String {
    match kind {
        "incident-pack" => format!("rustio-incident-pack-{report_id}.json"),
        _ => support_bundle_download_name(report_id),
    }
}

pub(crate) fn incident_pack_runbook_catalog() -> Vec<Value> {
    vec![
        json!({
            "title": "事件处置总览 / incident response overview",
            "path": "docs/operations/incident-runbook.md",
            "purpose": "统一查看值班分流、诊断包生成与恢复步骤 / central runbook for triage, diagnostic pack generation and recovery"
        }),
        json!({
            "title": "升级与回滚基线 / upgrade and rollback baseline",
            "path": "docs/operations/upgrade-rollback.md",
            "purpose": "升级失败时的 Helm 与元数据回滚 / Helm and metadata rollback during failed upgrades"
        }),
        json!({
            "title": "远端层生产矩阵 / remote tier production matrix",
            "path": "docs/storage/remote-tier-production-matrix.md",
            "purpose": "远端 tier backend 的兼容矩阵、样例配置与 smoke 入口 / backend compatibility matrix, samples and smoke entrypoints"
        }),
        json!({
            "title": "发布工程与兼容矩阵 / release engineering and compatibility matrix",
            "path": "docs/release/compatibility-matrix.md",
            "purpose": "版本矩阵、交付物与发布约束 / version matrix, release artifacts and constraints"
        }),
    ]
}

pub(crate) fn incident_pack_triage_flow() -> Vec<Value> {
    vec![
        json!({
            "step": 1,
            "title": "确认服务与集群健康 / confirm service and cluster health",
            "checks": ["/health/live", "/health/ready", "/health/cluster", "/api/v1/system/metrics/summary"],
            "when_to_escalate": "健康检查持续失败超过 5 分钟 / health checks fail continuously for more than 5 minutes"
        }),
        json!({
            "step": 2,
            "title": "确认 Raft 与复制状态 / inspect raft and replication state",
            "checks": ["/api/v1/system/raft/status", "/api/v1/replication/sites", "/api/v1/jobs/replication-backlog/metrics"],
            "when_to_escalate": "leader 丢失、复制 backlog 持续增长或 failover 卡住 / leader is missing, replication backlog keeps growing, or failover is stuck"
        }),
        json!({
            "step": 3,
            "title": "确认 KMS、远端层与任务面 / inspect kms, remote tiers and jobs",
            "checks": ["/api/v1/security/kms/status", "/api/v1/storage/tiers", "/api/v1/jobs/async/summary"],
            "when_to_escalate": "KMS rotate 连续失败、tier 退化或 async worker 队列阻塞 / repeated KMS rotate failures, degraded remote tiers, or blocked async workers"
        }),
        json!({
            "step": 4,
            "title": "决定回滚还是修复 / decide rollback versus live remediation",
            "checks": ["/api/v1/cluster/backup/export", "/api/v1/cluster/backup/restore"],
            "when_to_escalate": "数据面已受损或控制面配置不可恢复 / data plane is impaired or control plane configuration cannot be safely recovered"
        }),
    ]
}

pub(crate) fn incident_pack_restore_playbook() -> Vec<Value> {
    vec![
        json!({
            "step": 1,
            "title": "冻结变更并导出现状 / freeze changes and export current state",
            "action": "先导出当前 cluster backup 与 Helm values，避免二次覆盖 / export current cluster backup and Helm values before making further changes",
            "commands": [
                "GET /api/v1/cluster/backup/export",
                "helm get values rustio -n rustio -o yaml"
            ]
        }),
        json!({
            "step": 2,
            "title": "回滚部署物 / rollback deployment assets",
            "action": "若故障与发布相关，优先执行镜像或 Helm 回滚 / rollback image or Helm release first when the incident is release-related",
            "commands": [
                "helm history rustio -n rustio",
                "helm rollback rustio <REVISION> -n rustio"
            ]
        }),
        json!({
            "step": 3,
            "title": "恢复控制面元数据 / restore control-plane metadata",
            "action": "必要时使用 cluster backup restore 恢复元数据与远端 tier 快照 / use cluster backup restore to recover metadata and remote tier snapshots when required",
            "commands": [
                "POST /api/v1/cluster/backup/restore"
            ]
        }),
        json!({
            "step": 4,
            "title": "执行收尾验证 / run post-restore validation",
            "action": "校验健康检查、metrics、raft、replication、tier 与 KMS 状态 / validate health, metrics, raft, replication, tiers and KMS after restore",
            "commands": [
                "/health/ready",
                "/api/v1/system/metrics/summary",
                "/api/v1/system/raft/status",
                "/api/v1/storage/tiers",
                "/api/v1/security/kms/status"
            ]
        }),
    ]
}

pub(crate) fn append_incident_pack_sections(
    bundle: &mut Value,
    report: &rustio_core::DiagnosticReport,
    query: &CreateDiagnosticQuery,
) {
    let Some(sections) = bundle.get_mut("sections").and_then(Value::as_object_mut) else {
        return;
    };
    let incident_id = normalize_optional_text(query.incident_id.clone())
        .unwrap_or_else(|| format!("INCIDENT-{}", report.id.to_ascii_uppercase()));
    let incident_summary = normalize_optional_text(query.incident_summary.clone())
        .unwrap_or_else(|| "待补充事件摘要 / incident summary pending".to_string());
    let severity = normalize_incident_severity(query.severity.as_deref());
    let cluster_status = sections
        .get("system_metrics")
        .and_then(|value| value.get("cluster_status"))
        .cloned()
        .unwrap_or_else(|| json!("unknown"));
    let kms_provider = sections
        .get("kms_status")
        .and_then(|value| value.get("provider"))
        .cloned()
        .unwrap_or_else(|| json!("local"));
    let backlog_status_counts = sections
        .get("replication")
        .and_then(|value| value.get("backlog_status_counts"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    sections.insert(
        "incident_summary".to_string(),
        json!({
            "incident_id": incident_id,
            "severity": severity,
            "summary": incident_summary,
            "generated_at": report.created_at,
            "generated_by": report.generated_by,
            "cluster_status": cluster_status,
            "kms_provider": kms_provider,
            "replication_backlog_status_counts": backlog_status_counts,
            "first_response_slo": "15 分钟内完成首轮分流 / complete first triage within 15 minutes",
        }),
    );
    sections.insert(
        "triage_flow".to_string(),
        Value::Array(incident_pack_triage_flow()),
    );
    sections.insert(
        "restore_playbook".to_string(),
        Value::Array(incident_pack_restore_playbook()),
    );
    sections.insert(
        "runbook_catalog".to_string(),
        Value::Array(incident_pack_runbook_catalog()),
    );
}

pub(crate) fn diagnostic_sensitive_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "password"
            | "secret"
            | "secret_key"
            | "access_key"
            | "session_token"
            | "token"
            | "api_key"
            | "authorization"
            | "x-vault-token"
            | "x-kes-api-key"
            | "cookie"
    ) || normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("api_key")
        || normalized.contains("authorization")
}

pub(crate) fn redact_support_bundle_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map.iter_mut() {
                if diagnostic_sensitive_key(key) {
                    *inner = Value::String("***REDACTED***".to_string());
                } else {
                    redact_support_bundle_value(inner);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_support_bundle_value(item);
            }
        }
        _ => {}
    }
}

pub(crate) fn audit_category_counts(audits: &[rustio_core::AuditEvent]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for audit in audits {
        let category = audit_category(&audit.action).to_string();
        counts
            .entry(category)
            .and_modify(|current| *current += 1)
            .or_insert(1);
    }
    counts
}

pub(crate) fn sorted_recent_audits(
    audits: &[rustio_core::AuditEvent],
    limit: usize,
) -> Vec<rustio_core::AuditEvent> {
    let mut items = audits.to_vec();
    items.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp));
    items.into_iter().take(limit).collect()
}

pub(crate) fn sorted_recent_jobs(jobs: &[JobStatus], limit: usize) -> Vec<JobStatus> {
    let mut items = jobs.to_vec();
    items.sort_by_key(|entry| std::cmp::Reverse(entry.updated_at));
    items.into_iter().take(limit).collect()
}

pub(crate) fn replication_backlog_status_counts(
    items: &[ReplicationBacklogItem],
) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for item in items {
        counts
            .entry(item.status.clone())
            .and_modify(|current| *current += 1)
            .or_insert(1);
    }
    counts
}

pub(crate) fn sorted_replication_backlog_preview(
    items: &[ReplicationBacklogItem],
    limit: usize,
) -> Vec<ReplicationBacklogItem> {
    let mut preview = items
        .iter()
        .filter(|item| !matches!(item.status.as_str(), "done" | "completed"))
        .cloned()
        .collect::<Vec<_>>();
    preview.sort_by(|left, right| {
        right
            .last_attempt_at
            .cmp(&left.last_attempt_at)
            .then_with(|| right.queued_at.cmp(&left.queued_at))
    });
    preview.into_iter().take(limit).collect()
}

pub(crate) async fn persist_support_bundle(
    state: &AppState,
    report_id: &str,
    bundle: &Value,
) -> Result<(), AppError> {
    let dir = support_bundle_dir(state);
    tokio::fs::create_dir_all(&dir).await.map_err(|err| {
        AppError::internal(format!(
            "创建支持包目录失败 / failed to create support bundle dir: {err}"
        ))
    })?;
    let payload = serde_json::to_vec_pretty(bundle).map_err(|err| {
        AppError::internal(format!(
            "序列化支持包失败 / failed to serialize support bundle: {err}"
        ))
    })?;
    tokio::fs::write(support_bundle_path(state, report_id), payload)
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "写入支持包失败 / failed to write support bundle: {err}"
            ))
        })?;
    Ok(())
}

pub(crate) async fn read_support_bundle(
    state: &AppState,
    report_id: &str,
) -> Result<Value, AppError> {
    let path = support_bundle_path(state, report_id);
    let payload = tokio::fs::read(&path).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            AppError::not_found("诊断支持包不存在 / diagnostic support bundle not found")
        } else {
            AppError::internal(format!(
                "读取支持包失败 / failed to read support bundle: {err}"
            ))
        }
    })?;
    serde_json::from_slice::<Value>(&payload).map_err(|err| {
        AppError::internal(format!(
            "解析支持包失败 / failed to decode support bundle: {err}"
        ))
    })
}

pub(crate) fn report_metadata_from_bundle(value: &Value) -> Option<rustio_core::DiagnosticReport> {
    value
        .get("report")
        .cloned()
        .and_then(|report| serde_json::from_value(report).ok())
}

pub(crate) async fn load_diagnostics_from_disk(
    state: &AppState,
) -> Result<Vec<rustio_core::DiagnosticReport>, AppError> {
    let dir = support_bundle_dir(state);
    let mut reports = Vec::new();
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(state.diagnostics.read().await.clone());
        }
        Err(err) => {
            return Err(AppError::internal(format!(
                "读取支持包目录失败 / failed to read support bundle dir: {err}"
            )));
        }
    };

    while let Some(entry) = entries.next_entry().await.map_err(|err| {
        AppError::internal(format!(
            "遍历支持包目录失败 / failed to iterate support bundle dir: {err}"
        ))
    })? {
        let file_type = entry.file_type().await.map_err(|err| {
            AppError::internal(format!(
                "读取支持包文件类型失败 / failed to read support bundle file type: {err}"
            ))
        })?;
        if !file_type.is_file() {
            continue;
        }
        let payload = tokio::fs::read(entry.path()).await.map_err(|err| {
            AppError::internal(format!(
                "读取支持包文件失败 / failed to read support bundle file: {err}"
            ))
        })?;
        let bundle = serde_json::from_slice::<Value>(&payload).map_err(|err| {
            AppError::internal(format!(
                "解析支持包文件失败 / failed to decode support bundle file: {err}"
            ))
        })?;
        if let Some(report) = report_metadata_from_bundle(&bundle) {
            reports.push(report);
        }
    }

    if reports.is_empty() {
        reports = state.diagnostics.read().await.clone();
    }
    reports.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
    Ok(reports)
}

pub(crate) async fn build_support_bundle_document(
    state: &Arc<AppState>,
    report: &rustio_core::DiagnosticReport,
    query: &CreateDiagnosticQuery,
) -> Result<Value, AppError> {
    sync_site_replication_from_rules(state).await;

    let system_metrics = build_system_metrics_summary(state).await;
    let raft_status = state.metadata_raft_status().await;
    let security = state.security.read().await.clone();
    let kms_status = build_system_kms_metrics(&security);
    let cluster_payload = current_cluster_config_payload(state.as_ref()).await;
    let cluster_snapshot = ClusterConfigSnapshot {
        version: format!("support-bundle-{}", report.id),
        updated_at: report.created_at,
        updated_by: report.generated_by.clone(),
        source: "diagnostic".to_string(),
        reason: Some("support bundle".to_string()),
        etag: cluster_config_etag(&cluster_payload)?,
        payload: cluster_payload,
    };
    let audits = state.audits.read().await.clone();
    let jobs = state.jobs.read().await.clone();
    let async_jobs = collect_async_jobs(state).await;
    let async_summary = summarize_async_jobs(&async_jobs);
    let replications = state.replications.read().await.clone();
    let replication_backlog = state.replication_backlog.read().await.clone();
    let site_replications = state.site_replications.read().await.clone();
    let backlog_preview =
        sorted_replication_backlog_preview(&replication_backlog, query.backlog_limit.clamp(1, 200));
    let mut site_drift_preview = Vec::new();
    let mut sorted_sites = site_replications
        .iter()
        .map(|site| site.site_id.clone())
        .collect::<Vec<_>>();
    sorted_sites.sort();
    for site_id in sorted_sites {
        site_drift_preview.push(
            serde_json::to_value(
                build_site_replication_drift_report(state, &site_id, "inspect").await?,
            )
            .map_err(|err| {
                AppError::internal(format!(
                    "序列化复制站点漂移报告失败 / failed to encode site drift report: {err}"
                ))
            })?,
        );
    }

    let mut bundle = json!({
        "format_version": report.format,
        "generated_at": report.created_at,
        "offline_ready": true,
        "redacted": report.redacted,
        "report": report,
        "sections": {
            "cluster_config": cluster_snapshot,
            "system_metrics": system_metrics,
            "raft_status": raft_status,
            "replication": {
                "rules_total": replications.len(),
                "sites": site_replications,
                "backlog_status_counts": replication_backlog_status_counts(&replication_backlog),
                "backlog_preview": backlog_preview,
                "site_drift_preview": site_drift_preview,
            },
            "kms_status": kms_status,
            "audits": {
                "total": audits.len(),
                "by_category": audit_category_counts(&audits),
                "recent": sorted_recent_audits(&audits, query.audit_limit.clamp(1, 200)),
            },
            "jobs": {
                "total": jobs.len(),
                "recent": sorted_recent_jobs(&jobs, query.job_limit.clamp(1, 200)),
                "async_summary": async_summary,
            }
        }
    });

    if report.kind == "incident-pack" {
        append_incident_pack_sections(&mut bundle, report, query);
    }

    if query.redact_sensitive {
        redact_support_bundle_value(&mut bundle);
    }
    Ok(bundle)
}

pub(crate) async fn list_diagnostics(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::DiagnosticReport>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    Ok(wrap(load_diagnostics_from_disk(state.as_ref()).await?))
}

pub(crate) async fn create_diagnostic(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<CreateDiagnosticQuery>,
) -> Result<Json<ApiEnvelope<rustio_core::DiagnosticReport>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    let kind = normalize_diagnostic_kind(query.kind.as_deref())?;
    let report = rustio_core::DiagnosticReport {
        id: Uuid::new_v4().to_string(),
        created_at: Utc::now(),
        generated_by: auth.username.clone(),
        summary: diagnostic_summary(&kind, &query),
        kind: kind.clone(),
        format: diagnostic_format_version(&kind).to_string(),
        redacted: query.redact_sensitive,
        sections: diagnostic_sections(&kind),
        download_name: Some(diagnostic_download_name(&kind, "pending")),
    };
    let mut report = report;
    report.download_name = Some(diagnostic_download_name(&kind, &report.id));

    let bundle = build_support_bundle_document(&state, &report, &query).await?;
    persist_support_bundle(state.as_ref(), &report.id, &bundle).await?;

    {
        let mut diagnostics = state.diagnostics.write().await;
        diagnostics.retain(|item| item.id != report.id);
        diagnostics.insert(0, report.clone());
        if diagnostics.len() > 200 {
            diagnostics.truncate(200);
        }
    }

    state
        .append_audit(
            &auth.username,
            "cluster.diagnostic.create",
            "cluster/diagnostics",
            "success",
            None,
            json!({
                "report_id": report.id,
                "kind": report.kind,
                "format": report.format,
                "redacted": report.redacted,
                "download_name": report.download_name,
            }),
        )
        .await;
    Ok(wrap(report))
}

pub(crate) async fn get_diagnostic(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<Value>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    Ok(wrap(read_support_bundle(state.as_ref(), &id).await?))
}

pub(crate) async fn download_diagnostic(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    auth.require(Permission::ClusterRead)?;
    let bundle = read_support_bundle(state.as_ref(), &id).await?;
    let payload = serde_json::to_vec_pretty(&bundle).map_err(|err| {
        AppError::internal(format!(
            "序列化支持包下载失败 / failed to serialize support bundle download: {err}"
        ))
    })?;
    let mut response = payload.into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let download_name = bundle
        .pointer("/report/download_name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| support_bundle_download_name(&id));
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{download_name}\"")).map_err(
            |_| {
                AppError::internal(
                    "生成支持包下载头失败 / failed to build support bundle download header",
                )
            },
        )?,
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub(crate) struct ClusterConfigHistoryQuery {
    pub(crate) limit: Option<usize>,
}

pub(crate) fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(a, _)| *a);
            let mut normalized = serde_json::Map::new();
            for (key, inner) in entries {
                normalized.insert(key.clone(), canonicalize_json_value(inner));
            }
            Value::Object(normalized)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json_value).collect()),
        _ => value.clone(),
    }
}

pub(crate) fn cluster_config_etag(payload: &Value) -> Result<String, AppError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| {
        AppError::internal("序列化集群配置失败 / failed to serialize cluster config")
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

pub(crate) fn validate_cluster_config_payload(payload: &Value) -> ClusterConfigValidateResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let root = match payload.as_object() {
        Some(root) => root,
        None => {
            return ClusterConfigValidateResult {
                valid: false,
                errors: vec![bilingual_text(
                    "集群配置载荷必须是 JSON 对象",
                    "cluster config payload must be a JSON object",
                )],
                warnings,
            };
        }
    };

    if root.is_empty() {
        errors.push(bilingual_text(
            "集群配置载荷不能为空",
            "cluster config payload cannot be empty",
        ));
    }

    let cluster_name = payload
        .pointer("/cluster/name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if cluster_name.is_empty() {
        errors.push(bilingual_text(
            "cluster.name 为必填项",
            "cluster.name is required",
        ));
    }

    let api_address = payload
        .pointer("/network/api/address")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if api_address.is_empty() {
        errors.push(bilingual_text(
            "network.api.address 为必填项",
            "network.api.address is required",
        ));
    } else if !api_address.contains(':') {
        warnings.push(bilingual_text(
            "network.api.address 建议包含 host:port",
            "network.api.address should include host:port",
        ));
    }

    let console_embedded = payload
        .pointer("/network/console/embedded")
        .and_then(Value::as_bool);
    if console_embedded == Some(false) {
        warnings.push(bilingual_text(
            "network.console.embedded=false 需要外置 Console 部署",
            "network.console.embedded=false requires an external console deployment",
        ));
    }

    let erasure_set_size = payload
        .pointer("/storage/erasure_set_size")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if erasure_set_size == 0 {
        warnings.push(bilingual_text(
            "生产环境建议配置 storage.erasure_set_size",
            "storage.erasure_set_size is recommended for production",
        ));
    }

    let sse_mode = payload
        .pointer("/security/sse_mode")
        .and_then(Value::as_str)
        .unwrap_or("");
    let oidc_enabled = payload
        .pointer("/security/oidc_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if oidc_enabled {
        let discovery_url = payload
            .pointer("/security/oidc_discovery_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let issuer = payload
            .pointer("/security/oidc_issuer")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let client_id = payload
            .pointer("/security/oidc_client_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if discovery_url.is_empty() && issuer.is_empty() {
            warnings.push(bilingual_text(
                "当 security.oidc_enabled=true 时，oidc_discovery_url 或 oidc_issuer 至少配置一个",
                "when security.oidc_enabled=true, either oidc_discovery_url or oidc_issuer must be configured",
            ));
        }
        if client_id.is_empty() {
            warnings.push(bilingual_text(
                "当 security.oidc_enabled=true 时，security.oidc_client_id 为必填项",
                "security.oidc_client_id is required when security.oidc_enabled=true",
            ));
        }
    }
    let ldap_enabled = payload
        .pointer("/security/ldap_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if ldap_enabled {
        let ldap_url = payload
            .pointer("/security/ldap_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let ldap_user_base_dn = payload
            .pointer("/security/ldap_user_base_dn")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if ldap_url.is_empty() {
            warnings.push(bilingual_text(
                "当 security.ldap_enabled=true 时，security.ldap_url 为必填项",
                "security.ldap_url is required when security.ldap_enabled=true",
            ));
        }
        if ldap_user_base_dn.is_empty() {
            warnings.push(bilingual_text(
                "当 security.ldap_enabled=true 时，security.ldap_user_base_dn 为必填项",
                "security.ldap_user_base_dn is required when security.ldap_enabled=true",
            ));
        }
    }
    if sse_mode.eq_ignore_ascii_case("SSE-KMS") {
        let kms_endpoint = payload
            .pointer("/security/kms_endpoint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if kms_endpoint.is_empty() {
            errors.push(bilingual_text(
                "当 security.sse_mode=SSE-KMS 时，security.kms_endpoint 为必填项",
                "security.kms_endpoint is required when security.sse_mode=SSE-KMS",
            ));
        }
    }

    ClusterConfigValidateResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

pub(crate) fn bilingual_text(zh: &str, en: &str) -> String {
    format!("{zh} / {en}")
}

pub(crate) fn cluster_config_security_payload(security: &rustio_core::SecurityConfig) -> Value {
    json!({
        "oidc_enabled": security.oidc_enabled,
        "ldap_enabled": security.ldap_enabled,
        "oidc_discovery_url": security.oidc_discovery_url,
        "oidc_issuer": security.oidc_issuer,
        "oidc_client_id": security.oidc_client_id,
        "oidc_jwks_url": security.oidc_jwks_url,
        "oidc_allowed_algs": security.oidc_allowed_algs,
        "oidc_username_claim": security.oidc_username_claim,
        "oidc_groups_claim": security.oidc_groups_claim,
        "oidc_role_claim": security.oidc_role_claim,
        "oidc_default_role": security.oidc_default_role,
        "oidc_group_role_map": security.oidc_group_role_map,
        "ldap_url": security.ldap_url,
        "ldap_bind_dn": security.ldap_bind_dn,
        "ldap_user_base_dn": security.ldap_user_base_dn,
        "ldap_user_filter": security.ldap_user_filter,
        "ldap_group_base_dn": security.ldap_group_base_dn,
        "ldap_group_filter": security.ldap_group_filter,
        "ldap_group_attribute": security.ldap_group_attribute,
        "ldap_group_name_attribute": security.ldap_group_name_attribute,
        "ldap_default_role": security.ldap_default_role,
        "ldap_group_role_map": security.ldap_group_role_map,
        "kms_endpoint": security.kms_endpoint,
        "sse_mode": security.sse_mode
    })
}

pub(crate) fn cluster_config_payload_with_security(
    base: &Value,
    security: &rustio_core::SecurityConfig,
) -> Value {
    let mut payload = canonicalize_json_value(base);
    let root = match payload {
        Value::Object(ref mut root) => root,
        _ => {
            payload = Value::Object(serde_json::Map::new());
            payload.as_object_mut().expect("payload must be object")
        }
    };
    root.insert(
        "security".to_string(),
        cluster_config_security_payload(security),
    );
    canonicalize_json_value(&payload)
}

pub(crate) async fn current_cluster_config_payload(state: &AppState) -> Value {
    let base = state
        .cluster_config_history
        .read()
        .await
        .first()
        .map(|snapshot| snapshot.payload.clone())
        .unwrap_or_else(|| json!({}));
    let security = state.security.read().await.clone();
    cluster_config_payload_with_security(&base, &security)
}

pub(crate) async fn apply_cluster_config_runtime_security(
    state: &AppState,
    payload: &Value,
) -> Result<rustio_core::SecurityConfig, AppError> {
    let mut security = state.security.write().await;
    if let Some(value) = payload
        .pointer("/security/oidc_enabled")
        .and_then(Value::as_bool)
    {
        security.oidc_enabled = value;
    }
    if let Some(value) = payload
        .pointer("/security/ldap_enabled")
        .and_then(Value::as_bool)
    {
        security.ldap_enabled = value;
    }
    if let Some(value) = payload
        .pointer("/security/oidc_discovery_url")
        .and_then(Value::as_str)
    {
        security.oidc_discovery_url = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_issuer")
        .and_then(Value::as_str)
    {
        security.oidc_issuer = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_client_id")
        .and_then(Value::as_str)
    {
        security.oidc_client_id = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_jwks_url")
        .and_then(Value::as_str)
    {
        security.oidc_jwks_url = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_allowed_algs")
        .and_then(Value::as_str)
    {
        security.oidc_allowed_algs = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_username_claim")
        .and_then(Value::as_str)
    {
        security.oidc_username_claim = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_groups_claim")
        .and_then(Value::as_str)
    {
        security.oidc_groups_claim = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_role_claim")
        .and_then(Value::as_str)
    {
        security.oidc_role_claim = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_default_role")
        .and_then(Value::as_str)
    {
        security.oidc_default_role = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/oidc_group_role_map")
        .and_then(Value::as_str)
    {
        security.oidc_group_role_map = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_url")
        .and_then(Value::as_str)
    {
        security.ldap_url = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_bind_dn")
        .and_then(Value::as_str)
    {
        security.ldap_bind_dn = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_user_base_dn")
        .and_then(Value::as_str)
    {
        security.ldap_user_base_dn = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_user_filter")
        .and_then(Value::as_str)
    {
        security.ldap_user_filter = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_group_base_dn")
        .and_then(Value::as_str)
    {
        security.ldap_group_base_dn = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_group_filter")
        .and_then(Value::as_str)
    {
        security.ldap_group_filter = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_group_attribute")
        .and_then(Value::as_str)
    {
        security.ldap_group_attribute = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_group_name_attribute")
        .and_then(Value::as_str)
    {
        security.ldap_group_name_attribute = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_default_role")
        .and_then(Value::as_str)
    {
        security.ldap_default_role = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/ldap_group_role_map")
        .and_then(Value::as_str)
    {
        security.ldap_group_role_map = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/kms_endpoint")
        .and_then(Value::as_str)
    {
        security.kms_endpoint = value.to_string();
    }
    if let Some(value) = payload
        .pointer("/security/sse_mode")
        .and_then(Value::as_str)
    {
        security.sse_mode = value.to_string();
    }
    let snapshot = security.clone();
    drop(security);
    AppState::persist_security_config_snapshot(&state.data_dir, &snapshot).map_err(|err| {
        AppError::internal(format!(
            "持久化安全配置失败 / failed to persist security config: {err}"
        ))
    })?;
    Ok(snapshot)
}

pub(crate) async fn append_cluster_config_history_snapshot(
    state: &AppState,
    snapshot: ClusterConfigSnapshot,
) -> Result<Option<String>, AppError> {
    let mut history = state.cluster_config_history.write().await;
    let previous_version = history.first().map(|item| item.version.clone());
    if history
        .first()
        .map(|item| item.etag.as_str() == snapshot.etag.as_str())
        .unwrap_or(false)
    {
        return Err(AppError::bad_request(
            "集群配置没有变更 / cluster config has no changes",
        ));
    }
    history.insert(0, snapshot);
    if history.len() > 200 {
        history.truncate(200);
    }
    AppState::persist_cluster_config_history_snapshot(&state.data_dir, &history).map_err(
        |err| {
            AppError::internal(format!(
                "持久化集群配置历史失败 / failed to persist cluster config history: {err}"
            ))
        },
    )?;
    Ok(previous_version)
}

pub(crate) fn require_non_empty_reason(reason: Option<String>) -> Result<String, AppError> {
    let reason = reason.unwrap_or_default().trim().to_string();
    if reason.is_empty() {
        return Err(AppError::bad_request(
            "原因不能为空 / reason cannot be empty",
        ));
    }
    Ok(reason)
}

pub(crate) async fn get_cluster_config_current(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<ClusterConfigSnapshot>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let current = state
        .cluster_config_history
        .read()
        .await
        .first()
        .cloned()
        .ok_or_else(|| AppError::internal("集群配置历史为空 / cluster config history is empty"))?;
    Ok(wrap(current))
}

pub(crate) async fn list_cluster_config_history(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ClusterConfigHistoryQuery>,
) -> Result<Json<ApiEnvelope<Vec<ClusterConfigSnapshot>>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    let history = state.cluster_config_history.read().await;
    let items = history.iter().take(limit).cloned().collect::<Vec<_>>();
    Ok(wrap(items))
}

pub(crate) async fn validate_cluster_config(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<ClusterConfigValidateRequest>,
) -> Result<Json<ApiEnvelope<ClusterConfigValidateResult>>, AppError> {
    auth.require(Permission::ClusterRead)?;
    let normalized = canonicalize_json_value(&body.payload);
    let result = validate_cluster_config_payload(&normalized);
    state
        .append_audit(
            &auth.username,
            "cluster.config.validate",
            "cluster/config",
            "success",
            None,
            json!({
                "valid": result.valid,
                "errors": result.errors.len(),
                "warnings": result.warnings.len(),
            }),
        )
        .await;
    Ok(wrap(result))
}

pub(crate) async fn apply_cluster_config(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ClusterConfigApplyRequest>,
) -> Result<Json<ApiEnvelope<ClusterConfigSnapshot>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;

    let reason = require_non_empty_reason(body.reason)?;
    let normalized = canonicalize_json_value(&body.payload);
    let validation = validate_cluster_config_payload(&normalized);
    if !validation.valid {
        return Err(AppError::bad_request(format!(
            "cluster config validation failed: {}",
            validation.errors.join("; ")
        )));
    }

    let security = apply_cluster_config_runtime_security(&state, &normalized).await?;
    let snapshot_payload = cluster_config_payload_with_security(&normalized, &security);
    let etag = cluster_config_etag(&snapshot_payload)?;
    let snapshot = ClusterConfigSnapshot {
        version: format!("cfg-{}", Uuid::new_v4().simple()),
        updated_at: Utc::now(),
        updated_by: auth.username.clone(),
        source: "apply".to_string(),
        reason: Some(reason.clone()),
        etag: etag.clone(),
        payload: snapshot_payload,
    };

    let previous_version = append_cluster_config_history_snapshot(&state, snapshot.clone()).await?;
    let security_snapshot = Box::new(state.security.read().await.clone());
    let history_snapshot = state.cluster_config_history.read().await.clone();
    state
        .submit_metadata_command(MetadataCommand::SetSecurityAndHistory {
            security: security_snapshot,
            history: history_snapshot,
        })
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "元数据 Raft 提交失败 / metadata raft commit failed: {err}"
            ))
        })?;

    state
        .append_audit(
            &auth.username,
            "cluster.config.apply",
            &format!("cluster/config/{}", snapshot.version),
            "success",
            Some(reason),
            json!({
                "etag": snapshot.etag,
                "previous_version": previous_version,
                "security": cluster_config_security_payload(&security),
                "warnings": validation.warnings,
            }),
        )
        .await;
    state
        .push_event(
            "cluster.config.apply",
            "cluster-config-service",
            json!({
                "version": snapshot.version,
                "etag": snapshot.etag,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn rollback_cluster_config(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ClusterConfigRollbackRequest>,
) -> Result<Json<ApiEnvelope<ClusterConfigSnapshot>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;

    let reason = require_non_empty_reason(body.reason)?;
    let requested_version = body.version.trim().to_string();
    if requested_version.is_empty() {
        return Err(AppError::bad_request(
            "版本不能为空 / version cannot be empty",
        ));
    }

    let (current_version, target) = {
        let history = state.cluster_config_history.read().await;
        let current = history.first().ok_or_else(|| {
            AppError::internal("集群配置历史为空 / cluster config history is empty")
        })?;
        let target = history
            .iter()
            .find(|item| item.version == requested_version)
            .cloned()
            .ok_or_else(|| {
                AppError::not_found("集群配置版本不存在 / cluster config version not found")
            })?;
        (current.version.clone(), target)
    };

    if current_version == target.version {
        return Err(AppError::bad_request(
            "cluster config version is already active",
        ));
    }

    let normalized = canonicalize_json_value(&target.payload);
    let security = apply_cluster_config_runtime_security(&state, &normalized).await?;
    let snapshot_payload = cluster_config_payload_with_security(&normalized, &security);
    let snapshot = ClusterConfigSnapshot {
        version: format!("cfg-{}", Uuid::new_v4().simple()),
        updated_at: Utc::now(),
        updated_by: auth.username.clone(),
        source: format!("rollback:{}", target.version),
        reason: Some(reason.clone()),
        etag: cluster_config_etag(&snapshot_payload)?,
        payload: snapshot_payload,
    };

    append_cluster_config_history_snapshot(&state, snapshot.clone()).await?;
    let security_snapshot = Box::new(state.security.read().await.clone());
    let history_snapshot = state.cluster_config_history.read().await.clone();
    state
        .submit_metadata_command(MetadataCommand::SetSecurityAndHistory {
            security: security_snapshot,
            history: history_snapshot,
        })
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "元数据 Raft 提交失败 / metadata raft commit failed: {err}"
            ))
        })?;

    state
        .append_audit(
            &auth.username,
            "cluster.config.rollback",
            &format!("cluster/config/{}", snapshot.version),
            "success",
            Some(reason),
            json!({
                "rollback_to": target.version,
                "rollback_source": target.source,
                "etag": snapshot.etag,
                "security": cluster_config_security_payload(&security),
            }),
        )
        .await;
    state
        .push_event(
            "cluster.config.rollback",
            "cluster-config-service",
            json!({
                "version": snapshot.version,
                "rollback_to": target.version,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn export_cluster_config(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Response, AppError> {
    auth.require(Permission::ClusterRead)?;
    let current = state
        .cluster_config_history
        .read()
        .await
        .first()
        .cloned()
        .ok_or_else(|| AppError::internal("集群配置历史为空 / cluster config history is empty"))?;
    let body = serde_json::to_string_pretty(&current.payload).map_err(|_| {
        AppError::internal("序列化集群配置导出失败 / failed to serialize cluster config export")
    })?;
    let filename = format!("rustio-cluster-config-{}.json", current.version);
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| AppError::internal("构建导出响应失败 / failed to build export response"))?;
    Ok((
        StatusCode::OK,
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            ),
            (CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

pub(crate) const CLUSTER_BACKUP_FORMAT_VERSION: &str = "cluster-backup.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ClusterBackupBundle {
    pub(crate) format_version: String,
    pub(crate) exported_at: DateTime<Utc>,
    pub(crate) cluster_id: String,
    pub(crate) commit_index: u64,
    pub(crate) snapshot: MetadataRaftSyncRequest,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ClusterBackupRestoreRequest {
    pub(crate) reason: Option<String>,
    pub(crate) backup: ClusterBackupBundle,
    #[serde(default = "default_true")]
    pub(crate) rewrite_cluster_id: bool,
    #[serde(default = "default_true")]
    pub(crate) rewrite_peer_id: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterBackupRestoreResult {
    pub(crate) format_version: String,
    pub(crate) restored_at: DateTime<Utc>,
    pub(crate) cluster_id: String,
    pub(crate) peer_id: String,
    pub(crate) commit_index: u64,
    pub(crate) reason: String,
}

pub(crate) async fn export_cluster_backup(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Response, AppError> {
    auth.require(Permission::ClusterRead)?;
    let snapshot = state
        .export_metadata_raft_sync_request("cluster-backup-export")
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "导出集群备份失败 / failed to export cluster backup: {err}"
            ))
        })?;
    let bundle = ClusterBackupBundle {
        format_version: CLUSTER_BACKUP_FORMAT_VERSION.to_string(),
        exported_at: Utc::now(),
        cluster_id: snapshot.cluster_id.clone(),
        commit_index: snapshot.entry.index,
        snapshot,
    };
    let body = serde_json::to_string_pretty(&bundle).map_err(|err| {
        AppError::internal(format!(
            "序列化集群备份失败 / failed to serialize cluster backup: {err}"
        ))
    })?;
    let filename = format!("rustio-cluster-backup-{}.json", bundle.commit_index);
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| AppError::internal("构建备份响应失败 / failed to build backup response"))?;
    Ok((
        StatusCode::OK,
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            ),
            (CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

pub(crate) async fn restore_cluster_backup(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ClusterBackupRestoreRequest>,
) -> Result<Json<ApiEnvelope<ClusterBackupRestoreResult>>, AppError> {
    auth.require(Permission::ClusterWrite)?;
    ensure_confirm_header(&headers)?;
    let reason = require_non_empty_reason(body.reason)?;
    if body.backup.format_version.trim() != CLUSTER_BACKUP_FORMAT_VERSION {
        return Err(AppError::bad_request(format!(
            "不支持的集群备份格式 {} / unsupported cluster backup format {}",
            body.backup.format_version, body.backup.format_version
        )));
    }

    let raft_status = state.metadata_raft_status().await;
    let mut snapshot = body.backup.snapshot.clone();
    if body.rewrite_cluster_id {
        snapshot.cluster_id = raft_status.cluster_id.clone();
    }
    let local_peer_id =
        std::env::var("RUSTIO_METADATA_RAFT_NODE_ID").unwrap_or_else(|_| "meta-1".to_string());
    if body.rewrite_peer_id {
        snapshot.peer_id = local_peer_id.clone();
    }
    let response = state
        .apply_remote_metadata_raft_sync(snapshot)
        .await
        .map_err(|err| {
            AppError::internal(format!(
                "恢复集群备份失败 / failed to restore cluster backup: {err}"
            ))
        })?;
    if !response.success {
        return Err(AppError::bad_request(format!(
            "集群备份恢复被拒绝：{} / cluster backup restore rejected: {}",
            response
                .reason
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            response.reason.unwrap_or_else(|| "unknown".to_string())
        )));
    }

    let remote_tiers = state.remote_tiers.read().await.clone();
    AppState::persist_remote_tiers_snapshot(&state.data_dir, &remote_tiers).map_err(|err| {
        AppError::internal(format!(
            "持久化远端层快照失败 / failed to persist remote tier snapshot: {err}"
        ))
    })?;

    state
        .append_audit(
            &auth.username,
            "cluster.backup.restore",
            "cluster/backup",
            "success",
            Some(reason.clone()),
            json!({
                "format_version": CLUSTER_BACKUP_FORMAT_VERSION,
                "commit_index": response.match_index,
                "cluster_id": raft_status.cluster_id,
                "peer_id": local_peer_id,
            }),
        )
        .await;
    Ok(wrap(ClusterBackupRestoreResult {
        format_version: CLUSTER_BACKUP_FORMAT_VERSION.to_string(),
        restored_at: Utc::now(),
        cluster_id: state.metadata_raft_status().await.cluster_id,
        peer_id: local_peer_id,
        commit_index: response.match_index,
        reason,
    }))
}
