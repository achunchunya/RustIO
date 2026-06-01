//! 告警规则、通道、静默、升级、历史

use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct AlertRuleRequest {
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) metric: String,
    pub(crate) condition: String,
    pub(crate) threshold: f64,
    pub(crate) window_minutes: u32,
    pub(crate) severity: String,
    pub(crate) enabled: bool,
    pub(crate) channels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AlertChannelRequest {
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) endpoint: String,
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub(crate) payload_template: Option<String>,
    #[serde(default)]
    pub(crate) header_template: Option<HashMap<String, String>>,
}

pub(crate) fn normalize_alert_condition(value: &str) -> Result<String, AppError> {
    let normalized = value.trim();
    match normalized {
        ">" | ">=" | "<" | "<=" | "=" | "!=" => Ok(normalized.to_string()),
        _ => Err(AppError::bad_request(
            "condition 必须是 >, >=, <, <=, =, != 之一 / condition must be one of: >, >=, <, <=, =, !=",
        )),
    }
}

pub(crate) fn normalize_alert_severity(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "info" | "warning" | "critical" => Ok(normalized),
        _ => Err(AppError::bad_request(
            "severity 必须是 info、warning 或 critical / severity must be info, warning, or critical",
        )),
    }
}

pub(crate) fn normalize_alert_channel_kind(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "webhook"
        | "email"
        | "slack"
        | "nats"
        | "redis"
        | "elasticsearch"
        | "kafka"
        | "rabbitmq" => Ok(normalized),
        _ => Err(AppError::bad_request(
            "channel kind 必须是 webhook、email、slack、nats、redis、elasticsearch、kafka 或 rabbitmq / channel kind must be webhook, email, slack, nats, redis, elasticsearch, kafka, or rabbitmq",
        )),
    }
}

pub(crate) fn normalize_alert_channel_headers(
    headers: Option<HashMap<String, String>>,
) -> Result<HashMap<String, String>, AppError> {
    let mut normalized = HashMap::new();
    for (key, value) in headers.unwrap_or_default() {
        let key = key.trim();
        if key.is_empty() {
            return Err(AppError::bad_request(
                "通道请求头名称不能为空 / channel header name cannot be empty",
            ));
        }
        normalized.insert(key.to_string(), value.trim().to_string());
    }
    Ok(normalized)
}

pub(crate) async fn ensure_alert_channels_exist(
    state: &AppState,
    channel_ids: &[String],
) -> Result<(), AppError> {
    if channel_ids.is_empty() {
        return Err(AppError::bad_request(
            "告警规则 channels 至少包含一个通道 ID / alert rule channels must contain at least one channel id",
        ));
    }

    let channels = state.alert_channels.read().await;
    for channel_id in channel_ids {
        if !channels.iter().any(|channel| channel.id == *channel_id) {
            return Err(AppError::bad_request(format!(
                "告警通道不存在: {} / alert channel not found: {}",
                channel_id, channel_id
            )));
        }
    }
    Ok(())
}

pub(crate) fn default_alert_channel_status(channel: &AlertChannel) -> (String, Option<String>) {
    if !channel.enabled {
        return (
            "paused".to_string(),
            Some(bilingual_text("通知渠道已禁用", "channel is disabled")),
        );
    }
    if channel.endpoint.trim().is_empty() {
        return (
            "degraded".to_string(),
            Some(bilingual_text(
                "通知渠道地址为空",
                "channel endpoint is empty",
            )),
        );
    }
    ("healthy".to_string(), None)
}

pub(crate) async fn list_alert_rules(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<AlertRule>>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    let mut rules = state.alert_rules.read().await.clone();
    rules.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(wrap(rules))
}

pub(crate) async fn create_alert_rule(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<AlertRuleRequest>,
) -> Result<Json<ApiEnvelope<AlertRule>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "规则名称不能为空 / rule name cannot be empty",
        ));
    }
    if body.metric.trim().is_empty() {
        return Err(AppError::bad_request(
            "指标不能为空 / metric cannot be empty",
        ));
    }
    if !body.threshold.is_finite() {
        return Err(AppError::bad_request(
            "threshold 必须是有限数值 / threshold must be a finite number",
        ));
    }
    if body.window_minutes == 0 {
        return Err(AppError::bad_request(
            "window_minutes 必须大于 0 / window_minutes must be > 0",
        ));
    }
    let condition = normalize_alert_condition(&body.condition)?;
    let severity = normalize_alert_severity(&body.severity)?;
    ensure_alert_channels_exist(&state, &body.channels).await?;

    let id = body
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("rule-{}", Uuid::new_v4().simple()));
    let mut rules = state.alert_rules.write().await;
    if rules.iter().any(|rule| rule.id == id) {
        return Err(AppError::bad_request(
            "告警规则 ID 已存在 / alert rule id already exists",
        ));
    }

    let rule = AlertRule {
        id: id.clone(),
        name: body.name,
        metric: body.metric,
        condition,
        threshold: body.threshold,
        window_minutes: body.window_minutes,
        severity,
        enabled: body.enabled,
        channels: body.channels,
        last_triggered_at: None,
    };
    rules.push(rule.clone());
    drop(rules);

    state
        .append_audit(
            &auth.username,
            "alerts.rule.create",
            &format!("alerts/rules/{}", rule.id),
            "success",
            None,
            json!({
                "metric": rule.metric,
                "severity": rule.severity,
            }),
        )
        .await;
    Ok(wrap(rule))
}

pub(crate) async fn update_alert_rule(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<AlertRuleRequest>,
) -> Result<Json<ApiEnvelope<AlertRule>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "规则名称不能为空 / rule name cannot be empty",
        ));
    }
    if body.metric.trim().is_empty() {
        return Err(AppError::bad_request(
            "指标不能为空 / metric cannot be empty",
        ));
    }
    if !body.threshold.is_finite() {
        return Err(AppError::bad_request(
            "threshold 必须是有限数值 / threshold must be a finite number",
        ));
    }
    if body.window_minutes == 0 {
        return Err(AppError::bad_request(
            "window_minutes 必须大于 0 / window_minutes must be > 0",
        ));
    }
    let condition = normalize_alert_condition(&body.condition)?;
    let severity = normalize_alert_severity(&body.severity)?;
    ensure_alert_channels_exist(&state, &body.channels).await?;

    let mut rules = state.alert_rules.write().await;
    let rule = rules
        .iter_mut()
        .find(|rule| rule.id == id)
        .ok_or_else(|| AppError::not_found("告警规则不存在 / alert rule not found"))?;
    rule.name = body.name;
    rule.metric = body.metric;
    rule.condition = condition;
    rule.threshold = body.threshold;
    rule.window_minutes = body.window_minutes;
    rule.severity = severity;
    rule.enabled = body.enabled;
    rule.channels = body.channels;
    let snapshot = rule.clone();
    drop(rules);

    state
        .append_audit(
            &auth.username,
            "alerts.rule.update",
            &format!("alerts/rules/{}", snapshot.id),
            "success",
            None,
            json!({
                "metric": snapshot.metric,
                "severity": snapshot.severity,
                "enabled": snapshot.enabled,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn delete_alert_rule(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let mut rules = state.alert_rules.write().await;
    let before = rules.len();
    rules.retain(|rule| rule.id != id);
    if before == rules.len() {
        return Err(AppError::not_found("告警规则不存在 / alert rule not found"));
    }
    drop(rules);
    {
        let mut silences = state.alert_silences.write().await;
        for silence in silences.iter_mut() {
            silence.rule_ids.retain(|rule_id| rule_id != &id);
        }
        silences.retain(|silence| !silence.rule_ids.is_empty());
    }

    state
        .append_audit(
            &auth.username,
            "alerts.rule.delete",
            &format!("alerts/rules/{id}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "id": id })))
}

pub(crate) async fn list_alert_channels(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<AlertChannel>>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    let mut channels = state.alert_channels.read().await.clone();
    channels.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(wrap(channels))
}

pub(crate) async fn create_alert_channel(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<AlertChannelRequest>,
) -> Result<Json<ApiEnvelope<AlertChannel>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "通道名称不能为空 / channel name cannot be empty",
        ));
    }
    if body.endpoint.trim().is_empty() {
        return Err(AppError::bad_request(
            "通道 endpoint 不能为空 / channel endpoint cannot be empty",
        ));
    }

    let kind = normalize_alert_channel_kind(&body.kind)?;
    let headers = normalize_alert_channel_headers(body.headers)?;
    let payload_template = normalize_optional_text(body.payload_template);
    let header_template = normalize_alert_channel_headers(body.header_template)?;
    let id = body
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("channel-{}", Uuid::new_v4().simple()));

    let mut channels = state.alert_channels.write().await;
    if channels.iter().any(|channel| channel.id == id) {
        return Err(AppError::bad_request(
            "告警通道 ID 已存在 / alert channel id already exists",
        ));
    }

    let mut channel = AlertChannel {
        id: id.clone(),
        name: body.name,
        kind,
        endpoint: body.endpoint,
        headers,
        payload_template,
        header_template,
        enabled: body.enabled,
        status: "unknown".to_string(),
        last_checked_at: Utc::now(),
        error: None,
    };
    let (status, error) = default_alert_channel_status(&channel);
    channel.status = status;
    channel.error = error;
    channels.push(channel.clone());
    drop(channels);

    state
        .append_audit(
            &auth.username,
            "alerts.channel.create",
            &format!("alerts/channels/{}", channel.id),
            "success",
            None,
            json!({
                "channel_id": channel.id,
                "kind": channel.kind,
            }),
        )
        .await;
    Ok(wrap(channel))
}

pub(crate) async fn update_alert_channel(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<AlertChannelRequest>,
) -> Result<Json<ApiEnvelope<AlertChannel>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "通道名称不能为空 / channel name cannot be empty",
        ));
    }
    if body.endpoint.trim().is_empty() {
        return Err(AppError::bad_request(
            "通道 endpoint 不能为空 / channel endpoint cannot be empty",
        ));
    }
    let kind = normalize_alert_channel_kind(&body.kind)?;
    let headers = normalize_alert_channel_headers(body.headers)?;
    let payload_template = normalize_optional_text(body.payload_template);
    let header_template = normalize_alert_channel_headers(body.header_template)?;

    let mut channels = state.alert_channels.write().await;
    let channel = channels
        .iter_mut()
        .find(|channel| channel.id == id)
        .ok_or_else(|| AppError::not_found("告警通道不存在 / alert channel not found"))?;
    channel.name = body.name;
    channel.kind = kind;
    channel.endpoint = body.endpoint;
    channel.headers = headers;
    channel.payload_template = payload_template;
    channel.header_template = header_template;
    channel.enabled = body.enabled;
    channel.last_checked_at = Utc::now();
    let (status, error) = default_alert_channel_status(channel);
    channel.status = status;
    channel.error = error;
    let snapshot = channel.clone();
    drop(channels);

    state
        .append_audit(
            &auth.username,
            "alerts.channel.update",
            &format!("alerts/channels/{}", snapshot.id),
            "success",
            None,
            json!({
                "channel_id": snapshot.id,
                "kind": snapshot.kind,
                "enabled": snapshot.enabled,
                "status": snapshot.status,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn delete_alert_channel(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::SecurityWrite)?;

    let referenced_rules = state
        .alert_rules
        .read()
        .await
        .iter()
        .filter(|rule| rule.channels.iter().any(|channel_id| channel_id == &id))
        .map(|rule| rule.id.clone())
        .collect::<Vec<_>>();
    let referenced_escalations = state
        .alert_escalations
        .read()
        .await
        .iter()
        .filter(|policy| policy.channels.iter().any(|channel_id| channel_id == &id))
        .map(|policy| policy.id.clone())
        .collect::<Vec<_>>();
    if !referenced_rules.is_empty() || !referenced_escalations.is_empty() {
        let mut refs = Vec::new();
        if !referenced_rules.is_empty() {
            refs.push(format!("rules={}", referenced_rules.join(",")));
        }
        if !referenced_escalations.is_empty() {
            refs.push(format!("escalations={}", referenced_escalations.join(",")));
        }
        return Err(AppError::bad_request(format!(
            "通知渠道仍被引用: {} / alert channel is still referenced: {}",
            refs.join(";"),
            refs.join(";")
        )));
    }

    let mut channels = state.alert_channels.write().await;
    let before = channels.len();
    channels.retain(|channel| channel.id != id);
    if before == channels.len() {
        return Err(AppError::not_found(
            "告警通道不存在 / alert channel not found",
        ));
    }
    drop(channels);

    state
        .append_audit(
            &auth.username,
            "alerts.channel.delete",
            &format!("alerts/channels/{id}"),
            "success",
            None,
            json!({
                "channel_id": id,
            }),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "id": id })))
}

pub(crate) async fn test_alert_channel(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<AlertChannel>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let channel_before = state
        .alert_channels
        .read()
        .await
        .iter()
        .find(|channel| channel.id == id)
        .cloned()
        .ok_or_else(|| AppError::not_found("告警通道不存在 / alert channel not found"))?;
    let now = Utc::now();
    let payload = json!({
        "kind": "channel-test",
        "channel_id": channel_before.id,
        "channel_name": channel_before.name,
        "triggered_by": auth.username.clone(),
        "triggered_at": now,
    });
    let delivery_result = state
        .dispatch_alert_channel_message(&channel_before, &payload)
        .await;

    let mut channels = state.alert_channels.write().await;
    let channel = channels
        .iter_mut()
        .find(|channel| channel.id == id)
        .ok_or_else(|| AppError::not_found("告警通道不存在 / alert channel not found"))?;
    channel.last_checked_at = now;
    match &delivery_result {
        Ok(_) => {
            channel.status = "healthy".to_string();
            channel.error = None;
        }
        Err(err) if !channel.enabled => {
            channel.status = "paused".to_string();
            channel.error = Some(err.clone());
        }
        Err(err) => {
            channel.status = "degraded".to_string();
            channel.error = Some(err.clone());
        }
    }
    let snapshot = channel.clone();
    drop(channels);
    let history_message = match &delivery_result {
        Ok(_) => format!(
            "通知渠道 {} 测试成功 / alert channel {} test succeeded",
            snapshot.name, snapshot.name
        ),
        Err(err) => format!(
            "通知渠道 {} 测试失败：{} / alert channel {} test failed: {}",
            snapshot.name, err, snapshot.name, err
        ),
    };

    state
        .append_audit(
            &auth.username,
            "alerts.channel.test",
            &format!("alerts/channels/{}", snapshot.id),
            if delivery_result.is_ok() {
                "success"
            } else {
                "failure"
            },
            None,
            json!({
                "channel_id": snapshot.id,
                "status": snapshot.status,
                "delivery_success": delivery_result.is_ok(),
                "error": delivery_result.as_ref().err(),
            }),
        )
        .await;
    state
        .push_event(
            "alerts.channel.tested",
            "alerts-service",
            json!({
                "id": snapshot.id,
                "status": snapshot.status,
                "delivery_success": delivery_result.is_ok(),
                "error": delivery_result.as_ref().err(),
            }),
        )
        .await;
    state.alert_history.write().await.push(AlertHistoryEntry {
        id: format!("history-{}", Uuid::new_v4().simple()),
        rule_id: None,
        rule_name: None,
        severity: "info".to_string(),
        status: "test".to_string(),
        message: history_message,
        triggered_at: Utc::now(),
        source: "channel-tester".to_string(),
        assignee: None,
        claimed_at: None,
        acknowledged_by: None,
        acknowledged_at: None,
        resolved_by: None,
        resolved_at: None,
        details: json!({
            "channel_id": snapshot.id,
            "status": snapshot.status,
            "delivery_success": delivery_result.is_ok(),
            "error": delivery_result.err(),
        }),
    });
    Ok(wrap(snapshot))
}

#[derive(Debug, Deserialize)]
pub(crate) struct AlertSilenceRequest {
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) starts_at: String,
    pub(crate) ends_at: String,
    pub(crate) reason: String,
    pub(crate) enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AlertEscalationRequest {
    pub(crate) id: Option<String>,
    pub(crate) name: String,
    pub(crate) severity: String,
    pub(crate) wait_minutes: u32,
    pub(crate) channels: Vec<String>,
    pub(crate) enabled: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AlertHistoryQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) severity: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) rule_id: Option<String>,
    pub(crate) source: Option<String>,
}

pub(crate) fn parse_rfc3339_utc(value: &str, field: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(value)
        .map(|date_time| date_time.with_timezone(&Utc))
        .map_err(|_| {
            AppError::bad_request(format!(
                "{} 不是合法 RFC3339 时间戳 / invalid {field}, expected RFC3339 timestamp",
                field
            ))
        })
}

pub(crate) async fn ensure_alert_rules_exist(
    state: &AppState,
    rule_ids: &[String],
) -> Result<(), AppError> {
    if rule_ids.is_empty() {
        return Err(AppError::bad_request(
            "静默规则 rule_ids 至少包含一个规则 ID / silence rule_ids must contain at least one rule id",
        ));
    }

    let rules = state.alert_rules.read().await;
    for rule_id in rule_ids {
        if !rules.iter().any(|rule| rule.id == *rule_id) {
            return Err(AppError::bad_request(format!(
                "告警规则不存在: {} / alert rule not found: {}",
                rule_id, rule_id
            )));
        }
    }
    Ok(())
}

pub(crate) async fn list_alert_silences(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<AlertSilence>>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    let mut silences = state.alert_silences.read().await.clone();
    silences.sort_by_key(|entry| std::cmp::Reverse(entry.starts_at));
    Ok(wrap(silences))
}

pub(crate) async fn create_alert_silence(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<AlertSilenceRequest>,
) -> Result<Json<ApiEnvelope<AlertSilence>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "静默名称不能为空 / silence name cannot be empty",
        ));
    }
    if body.reason.trim().is_empty() {
        return Err(AppError::bad_request(
            "静默原因不能为空 / silence reason cannot be empty",
        ));
    }
    ensure_alert_rules_exist(&state, &body.rule_ids).await?;

    let starts_at = parse_rfc3339_utc(&body.starts_at, "starts_at")?;
    let ends_at = parse_rfc3339_utc(&body.ends_at, "ends_at")?;
    if ends_at <= starts_at {
        return Err(AppError::bad_request(
            "ends_at must be greater than starts_at",
        ));
    }

    let id = body
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("silence-{}", Uuid::new_v4().simple()));
    let mut silences = state.alert_silences.write().await;
    if silences.iter().any(|silence| silence.id == id) {
        return Err(AppError::bad_request(
            "告警静默 ID 已存在 / alert silence id already exists",
        ));
    }

    let silence = AlertSilence {
        id: id.clone(),
        name: body.name,
        rule_ids: body.rule_ids,
        starts_at,
        ends_at,
        reason: body.reason,
        created_by: auth.username.clone(),
        enabled: body.enabled,
    };
    silences.push(silence.clone());
    drop(silences);

    state
        .append_audit(
            &auth.username,
            "alerts.silence.create",
            &format!("alerts/silences/{}", silence.id),
            "success",
            None,
            json!({
                "rule_ids": silence.rule_ids,
                "starts_at": silence.starts_at,
                "ends_at": silence.ends_at,
            }),
        )
        .await;
    Ok(wrap(silence))
}

pub(crate) async fn delete_alert_silence(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let mut silences = state.alert_silences.write().await;
    let before = silences.len();
    silences.retain(|silence| silence.id != id);
    if before == silences.len() {
        return Err(AppError::not_found(
            "告警静默不存在 / alert silence not found",
        ));
    }
    drop(silences);

    state
        .append_audit(
            &auth.username,
            "alerts.silence.delete",
            &format!("alerts/silences/{id}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "id": id })))
}

pub(crate) async fn list_alert_escalations(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
) -> Result<Json<ApiEnvelope<Vec<AlertEscalationPolicy>>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    let mut escalations = state.alert_escalations.read().await.clone();
    escalations.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(wrap(escalations))
}

pub(crate) async fn create_alert_escalation(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<AlertEscalationRequest>,
) -> Result<Json<ApiEnvelope<AlertEscalationPolicy>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "升级策略名称不能为空 / escalation name cannot be empty",
        ));
    }
    if body.wait_minutes == 0 {
        return Err(AppError::bad_request(
            "wait_minutes 必须大于 0 / wait_minutes must be > 0",
        ));
    }
    let severity = normalize_alert_severity(&body.severity)?;
    ensure_alert_channels_exist(&state, &body.channels).await?;

    let id = body
        .id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("escalation-{}", Uuid::new_v4().simple()));
    let mut escalations = state.alert_escalations.write().await;
    if escalations.iter().any(|policy| policy.id == id) {
        return Err(AppError::bad_request(
            "告警升级策略 ID 已存在 / alert escalation id already exists",
        ));
    }

    let policy = AlertEscalationPolicy {
        id: id.clone(),
        name: body.name,
        severity,
        wait_minutes: body.wait_minutes,
        channels: body.channels,
        enabled: body.enabled,
    };
    escalations.push(policy.clone());
    drop(escalations);

    state
        .append_audit(
            &auth.username,
            "alerts.escalation.create",
            &format!("alerts/escalations/{}", policy.id),
            "success",
            None,
            json!({
                "severity": policy.severity,
                "wait_minutes": policy.wait_minutes,
            }),
        )
        .await;
    Ok(wrap(policy))
}

pub(crate) async fn update_alert_escalation(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<AlertEscalationRequest>,
) -> Result<Json<ApiEnvelope<AlertEscalationPolicy>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    if body.name.trim().is_empty() {
        return Err(AppError::bad_request(
            "升级策略名称不能为空 / escalation name cannot be empty",
        ));
    }
    if body.wait_minutes == 0 {
        return Err(AppError::bad_request(
            "wait_minutes 必须大于 0 / wait_minutes must be > 0",
        ));
    }
    let severity = normalize_alert_severity(&body.severity)?;
    ensure_alert_channels_exist(&state, &body.channels).await?;

    let mut escalations = state.alert_escalations.write().await;
    let policy = escalations
        .iter_mut()
        .find(|policy| policy.id == id)
        .ok_or_else(|| AppError::not_found("告警升级策略不存在 / alert escalation not found"))?;
    policy.name = body.name;
    policy.severity = severity;
    policy.wait_minutes = body.wait_minutes;
    policy.channels = body.channels;
    policy.enabled = body.enabled;
    let snapshot = policy.clone();
    drop(escalations);

    state
        .append_audit(
            &auth.username,
            "alerts.escalation.update",
            &format!("alerts/escalations/{}", snapshot.id),
            "success",
            None,
            json!({
                "severity": snapshot.severity,
                "wait_minutes": snapshot.wait_minutes,
                "enabled": snapshot.enabled,
            }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn delete_alert_escalation(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let mut escalations = state.alert_escalations.write().await;
    let before = escalations.len();
    escalations.retain(|policy| policy.id != id);
    if before == escalations.len() {
        return Err(AppError::not_found(
            "告警升级策略不存在 / alert escalation not found",
        ));
    }
    drop(escalations);

    state
        .append_audit(
            &auth.username,
            "alerts.escalation.delete",
            &format!("alerts/escalations/{id}"),
            "success",
            None,
            json!({}),
        )
        .await;
    Ok(wrap(json!({ "deleted": true, "id": id })))
}

pub(crate) async fn simulate_alert_rule_trigger(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<AlertHistoryEntry>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let history = state
        .evaluate_alert_rule_now(&id, &auth.username)
        .await
        .map_err(|err| {
            if err.contains("不存在 /") {
                AppError::not_found(err)
            } else {
                AppError::bad_request(err)
            }
        })?;
    let rule_id = history.rule_id.clone().unwrap_or(id);
    let delivery_enqueued = state
        .enqueue_alert_deliveries(&history)
        .await
        .map_err(AppError::bad_request)?;

    state
        .append_audit(
            &auth.username,
            "alerts.rule.evaluate",
            &format!("alerts/rules/{rule_id}"),
            "success",
            None,
            json!({
                "status": history.status,
                "message": history.message,
                "trigger_mode": "manual-evaluation",
                "delivery_enqueued": delivery_enqueued,
            }),
        )
        .await;
    state
        .push_event(
            "alerts.rule.evaluated",
            "alerts-service",
            json!({
                "rule_id": rule_id,
                "status": history.status,
                "severity": history.severity,
                "trigger_mode": "manual-evaluation",
                "delivery_enqueued": delivery_enqueued,
            }),
        )
        .await;

    Ok(wrap(history))
}

pub(crate) async fn list_alert_history(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<AlertHistoryQuery>,
) -> Result<Json<ApiEnvelope<Vec<AlertHistoryEntry>>>, AppError> {
    auth.require(Permission::SecurityRead)?;
    let limit = query.limit.unwrap_or(200).clamp(1, 2000);
    let severity_filter = query
        .severity
        .as_ref()
        .map(|value| value.trim().to_ascii_lowercase());
    let status_filter = query
        .status
        .as_ref()
        .map(|value| value.trim().to_ascii_lowercase());
    let source_filter = query
        .source
        .as_ref()
        .map(|value| value.trim().to_ascii_lowercase());
    let rule_id_filter = query.rule_id.as_ref().map(|value| value.trim().to_string());

    let mut history = state
        .alert_history
        .read()
        .await
        .iter()
        .filter(|entry| {
            if let Some(filter) = &severity_filter {
                if entry.severity.to_ascii_lowercase() != *filter {
                    return false;
                }
            }
            if let Some(filter) = &status_filter {
                if entry.status.to_ascii_lowercase() != *filter {
                    return false;
                }
            }
            if let Some(filter) = &source_filter {
                if !entry.source.to_ascii_lowercase().contains(filter) {
                    return false;
                }
            }
            if let Some(filter) = &rule_id_filter {
                if entry.rule_id.as_deref() != Some(filter.as_str()) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect::<Vec<_>>();
    history.sort_by_key(|entry| std::cmp::Reverse(entry.triggered_at));
    history.truncate(limit);
    Ok(wrap(history))
}

pub(crate) async fn claim_alert_history_entry(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<AlertHistoryEntry>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let now = Utc::now();

    let mut history = state.alert_history.write().await;
    let entry = history
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| AppError::not_found("告警历史记录不存在 / alert history entry not found"))?;
    entry.assignee = Some(auth.username.clone());
    entry.claimed_at = Some(now);
    let snapshot = entry.clone();
    drop(history);

    state
        .append_audit(
            &auth.username,
            "alerts.history.claim",
            &format!("alerts/history/{id}"),
            "success",
            None,
            json!({
                "assignee": snapshot.assignee,
            }),
        )
        .await;
    state
        .push_event(
            "alerts.history.claimed",
            "alerts-service",
            json!({ "id": id, "assignee": snapshot.assignee }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn ack_alert_history_entry(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<AlertHistoryEntry>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let now = Utc::now();

    let mut history = state.alert_history.write().await;
    let entry = history
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| AppError::not_found("告警历史记录不存在 / alert history entry not found"))?;
    entry.acknowledged_by = Some(auth.username.clone());
    entry.acknowledged_at = Some(now);
    if entry.status == "firing" || entry.status == "suppressed" {
        entry.status = "acknowledged".to_string();
    }
    let snapshot = entry.clone();
    drop(history);

    state
        .append_audit(
            &auth.username,
            "alerts.history.ack",
            &format!("alerts/history/{id}"),
            "success",
            None,
            json!({
                "status": snapshot.status,
                "acknowledged_by": snapshot.acknowledged_by,
            }),
        )
        .await;
    state
        .push_event(
            "alerts.history.acknowledged",
            "alerts-service",
            json!({ "id": id, "status": snapshot.status }),
        )
        .await;
    Ok(wrap(snapshot))
}

pub(crate) async fn resolve_alert_history_entry(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(id): Path<String>,
) -> Result<Json<ApiEnvelope<AlertHistoryEntry>>, AppError> {
    auth.require(Permission::SecurityWrite)?;
    let now = Utc::now();

    let mut history = state.alert_history.write().await;
    let entry = history
        .iter_mut()
        .find(|entry| entry.id == id)
        .ok_or_else(|| AppError::not_found("告警历史记录不存在 / alert history entry not found"))?;
    entry.status = "resolved".to_string();
    if entry.acknowledged_at.is_none() {
        entry.acknowledged_by = Some(auth.username.clone());
        entry.acknowledged_at = Some(now);
    }
    entry.resolved_by = Some(auth.username.clone());
    entry.resolved_at = Some(now);
    let snapshot = entry.clone();
    drop(history);

    state
        .append_audit(
            &auth.username,
            "alerts.history.resolve",
            &format!("alerts/history/{id}"),
            "success",
            None,
            json!({
                "status": snapshot.status,
                "resolved_by": snapshot.resolved_by,
            }),
        )
        .await;
    state
        .push_event(
            "alerts.history.resolved",
            "alerts-service",
            json!({ "id": id, "status": snapshot.status }),
        )
        .await;
    Ok(wrap(snapshot))
}
