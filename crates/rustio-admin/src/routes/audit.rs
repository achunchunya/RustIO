//! 审计事件查询与导出

use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct AuditQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) category: Option<String>,
    pub(crate) actor: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) action_prefix: Option<String>,
    pub(crate) resource: Option<String>,
    pub(crate) resource_prefix: Option<String>,
    pub(crate) outcome: Option<String>,
    pub(crate) keyword: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) detail_key: Option<String>,
    pub(crate) detail_value: Option<String>,
    pub(crate) from: Option<String>,
    pub(crate) to: Option<String>,
}

pub(crate) fn json_lookup_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        let key = segment.trim();
        if key.is_empty() {
            return None;
        }
        current = current.get(key)?;
    }
    Some(current)
}

pub(crate) fn json_value_contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => flag.to_string().contains(needle),
        Value::Number(number) => number.to_string().contains(needle),
        Value::String(text) => text.to_ascii_lowercase().contains(needle),
        Value::Array(items) => items.iter().any(|item| json_value_contains(item, needle)),
        Value::Object(map) => map.iter().any(|(key, value)| {
            key.to_ascii_lowercase().contains(needle) || json_value_contains(value, needle)
        }),
    }
}

pub(crate) async fn list_audit_events(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ApiEnvelope<Vec<rustio_core::AuditEvent>>>, AppError> {
    auth.require(Permission::AuditRead)?;
    let limit = query.limit.unwrap_or(200).clamp(1, 2000);
    let category_filter = query
        .category
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let actor_filter = query.actor.as_ref().map(|value| value.to_ascii_lowercase());
    let action_filter = query
        .action
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let action_prefix_filter = query
        .action_prefix
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let resource_filter = query
        .resource
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let resource_prefix_filter = query
        .resource_prefix
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let outcome_filter = query
        .outcome
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let keyword_filter = query
        .keyword
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let reason_filter = query
        .reason
        .as_ref()
        .map(|value| value.to_ascii_lowercase());
    let detail_key_filter = query
        .detail_key
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let detail_value_filter = query
        .detail_value
        .as_ref()
        .map(|value| value.to_ascii_lowercase());

    let from = query
        .from
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| {
            AppError::bad_request(
                "from 时间戳无效，应为 RFC3339 / invalid 'from' timestamp, expected RFC3339",
            )
        })?
        .map(|value| value.with_timezone(&Utc));
    let to = query
        .to
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| {
            AppError::bad_request(
                "to 时间戳无效，应为 RFC3339 / invalid 'to' timestamp, expected RFC3339",
            )
        })?
        .map(|value| value.with_timezone(&Utc));

    let audits = state.audits.read().await;
    let mut events = audits
        .iter()
        .filter(|event| {
            if let Some(filter) = &category_filter {
                if audit_category(&event.action) != filter {
                    return false;
                }
            }
            if let Some(filter) = &actor_filter {
                if !event.actor.to_ascii_lowercase().contains(filter) {
                    return false;
                }
            }
            if let Some(filter) = &action_filter {
                if !event.action.to_ascii_lowercase().contains(filter) {
                    return false;
                }
            }
            if let Some(filter) = &action_prefix_filter {
                if !event.action.to_ascii_lowercase().starts_with(filter) {
                    return false;
                }
            }
            if let Some(filter) = &resource_filter {
                if !event.resource.to_ascii_lowercase().contains(filter) {
                    return false;
                }
            }
            if let Some(filter) = &resource_prefix_filter {
                if !event.resource.to_ascii_lowercase().starts_with(filter) {
                    return false;
                }
            }
            if let Some(filter) = &outcome_filter {
                if event.outcome.to_ascii_lowercase() != *filter {
                    return false;
                }
            }
            if let Some(filter) = &reason_filter {
                let reason = event
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if !reason.contains(filter) {
                    return false;
                }
            }
            if let Some(filter) = &detail_key_filter {
                let Some(detail) = json_lookup_path(&event.details, filter) else {
                    return false;
                };
                if let Some(value_filter) = &detail_value_filter {
                    if !json_value_contains(detail, value_filter) {
                        return false;
                    }
                }
            } else if let Some(value_filter) = &detail_value_filter {
                if !json_value_contains(&event.details, value_filter) {
                    return false;
                }
            }
            if let Some(filter) = &keyword_filter {
                let in_reason = event
                    .reason
                    .as_ref()
                    .map(|value| value.to_ascii_lowercase().contains(filter))
                    .unwrap_or(false);
                let details = event.details.to_string().to_ascii_lowercase();
                if !event.actor.to_ascii_lowercase().contains(filter)
                    && !event.action.to_ascii_lowercase().contains(filter)
                    && !event.resource.to_ascii_lowercase().contains(filter)
                    && !event.outcome.to_ascii_lowercase().contains(filter)
                    && !in_reason
                    && !details.contains(filter)
                    && !json_value_contains(&event.details, filter)
                {
                    return false;
                }
            }
            if let Some(from_at) = from {
                if event.timestamp < from_at {
                    return false;
                }
            }
            if let Some(to_at) = to {
                if event.timestamp > to_at {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect::<Vec<_>>();

    events.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp));
    events.truncate(limit);
    Ok(wrap(events))
}

pub(crate) async fn export_audit_events(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<impl IntoResponse, AppError> {
    auth.require(Permission::AuditRead)?;
    let body = serde_json::to_string_pretty(&state.audits.read().await.clone()).map_err(|err| {
        AppError::internal(format!(
            "序列化审计导出失败 / failed to serialize audit export: {err}"
        ))
    })?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        body,
    ))
}

pub(crate) async fn list_jobs(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<JobStatus>>>, AppError> {
    auth.require(Permission::JobsRead)?;
    Ok(wrap(state.jobs.read().await.clone()))
}
