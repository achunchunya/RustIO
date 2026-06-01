//! 告警规则评估与多通道投递（SMTP/NATS/Redis）

use super::*;

impl AppState {
    pub(crate) fn replication_root_dir(&self) -> PathBuf {
        self.data_dir.join(".rustio_replication")
    }

    pub(crate) fn replication_object_space_root(&self, site_id: &str, bucket: &str) -> PathBuf {
        self.data_dir
            .join(".rustio_sites")
            .join(site_id)
            .join("data")
            .join(bucket)
    }

    pub fn next_replication_checkpoint(&self) -> u64 {
        self.replication_sequence.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) fn replication_item_supersedable(status: &str) -> bool {
        matches!(status, "pending" | "failed" | "dead_letter")
    }

    pub(crate) fn replication_operation_priority(operation: &str) -> u8 {
        if operation.eq_ignore_ascii_case("delete") {
            0
        } else {
            1
        }
    }

    pub(crate) fn replication_backlog_alert_source(site: &str) -> String {
        format!("replication-backlog-sla-watchdog:{site}")
    }

    pub(crate) fn replication_backlog_alert_site(source: &str) -> Option<&str> {
        source.strip_prefix("replication-backlog-sla-watchdog:")
    }

    pub(crate) fn replication_backlog_alert_breach_hash(details: &Value) -> Option<&str> {
        details.get("breach_hash").and_then(Value::as_str)
    }

    pub(crate) fn alert_rule_condition_matches(
        value: f64,
        condition: &str,
        threshold: f64,
    ) -> Result<bool, String> {
        if !value.is_finite() {
            return Err(bilingual_runtime_error(
                "告警指标值无效",
                "alert metric value is not finite",
            ));
        }
        if !threshold.is_finite() {
            return Err(bilingual_runtime_error(
                "告警阈值无效",
                "alert threshold is not finite",
            ));
        }
        match condition {
            ">" => Ok(value > threshold),
            ">=" => Ok(value >= threshold),
            "<" => Ok(value < threshold),
            "<=" => Ok(value <= threshold),
            "=" => Ok((value - threshold).abs() <= f64::EPSILON),
            "!=" => Ok((value - threshold).abs() > f64::EPSILON),
            _ => Err(bilingual_runtime_error(
                "告警条件不支持",
                format!("alert condition is unsupported: {condition}"),
            )),
        }
    }

    pub(crate) async fn alert_rule_metric_value(&self, metric: &str) -> Result<f64, String> {
        match metric {
            "cluster.capacity.used_ratio" => {
                let nodes = self.nodes.read().await;
                let total = nodes
                    .iter()
                    .map(|node| node.capacity_total_bytes)
                    .sum::<u64>();
                let used = nodes
                    .iter()
                    .map(|node| node.capacity_used_bytes.min(node.capacity_total_bytes))
                    .sum::<u64>();
                if total == 0 {
                    return Err(bilingual_runtime_error(
                        "集群容量总量为 0，无法计算使用率",
                        "cluster capacity total is 0, cannot compute used ratio",
                    ));
                }
                Ok(used as f64 / total as f64)
            }
            "replication.lag.seconds" => {
                let sites = self.site_replications.read().await;
                Ok(sites
                    .iter()
                    .map(|site| site.lag_seconds)
                    .max()
                    .unwrap_or_default() as f64)
            }
            _ => Err(bilingual_runtime_error(
                "告警指标不支持",
                format!("alert metric unsupported: {metric}"),
            )),
        }
    }

    pub(crate) async fn evaluate_alert_rule_once(
        &self,
        rule: AlertRule,
        now: DateTime<Utc>,
        record_stable_state: bool,
        evaluated_by: &str,
    ) -> Result<Option<AlertHistoryEntry>, String> {
        let value = self.alert_rule_metric_value(&rule.metric).await?;
        let matched = Self::alert_rule_condition_matches(value, &rule.condition, rule.threshold)?;
        let silence = self
            .alert_silences
            .read()
            .await
            .iter()
            .find(|silence| {
                silence.enabled
                    && silence.rule_ids.iter().any(|rule_id| rule_id == &rule.id)
                    && now >= silence.starts_at
                    && now <= silence.ends_at
            })
            .cloned();
        let is_silenced = silence.is_some();
        if matched {
            let mut rules = self.alert_rules.write().await;
            if let Some(existing) = rules.iter_mut().find(|item| item.id == rule.id) {
                existing.last_triggered_at = Some(now);
            }
            drop(rules);
        }

        let firing_message = bilingual_runtime_error(
            &format!(
                "规则 {} 触发：指标 {} 当前值 {:.6} {} 阈值 {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} fired: metric {} value {:.6} {} threshold {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let recovered_message = bilingual_runtime_error(
            &format!(
                "规则 {} 已恢复：指标 {} 当前值 {:.6} 未命中条件 {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} recovered: metric {} value {:.6} no longer matches {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let stable_message = bilingual_runtime_error(
            &format!(
                "规则 {} 当前健康：指标 {} 当前值 {:.6} 未命中条件 {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} is healthy: metric {} value {:.6} does not match {} {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let suppressed_message = bilingual_runtime_error(
            &format!(
                "规则 {} 命中但处于静默窗口：指标 {} 当前值 {:.6} {} 阈值 {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
            format!(
                "rule {} matched but is silenced: metric {} value {:.6} {} threshold {:.6}",
                rule.name, rule.metric, value, rule.condition, rule.threshold
            ),
        );
        let source = "rule-engine".to_string();
        let mut history = self.alert_history.write().await;
        let active_firing = history
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.rule_id.as_deref() == Some(rule.id.as_str())
                    && entry.status == "firing"
                    && entry.resolved_at.is_none()
            })
            .map(|(index, entry)| (index, entry.triggered_at))
            .max_by_key(|(_, triggered_at)| *triggered_at)
            .map(|(index, _)| index);

        if matched && !is_silenced {
            let details = json!({
                "metric": rule.metric,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "value": value,
                "matched": true,
                "silenced": false,
                "evaluator": evaluated_by,
            });
            if let Some(index) = active_firing {
                if let Some(entry) = history.get_mut(index) {
                    entry.rule_name = Some(rule.name.clone());
                    entry.severity = rule.severity.clone();
                    entry.message = firing_message;
                    entry.details = details;
                    return Ok(Some(entry.clone()));
                }
            }
            let entry = AlertHistoryEntry {
                id: format!("history-{}", Uuid::new_v4().simple()),
                rule_id: Some(rule.id.clone()),
                rule_name: Some(rule.name.clone()),
                severity: rule.severity.clone(),
                status: "firing".to_string(),
                message: firing_message,
                triggered_at: now,
                source,
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: None,
                resolved_at: None,
                details,
            };
            history.push(entry.clone());
            return Ok(Some(entry));
        }

        if matched && is_silenced {
            let suppress_window = Duration::minutes(rule.window_minutes.max(1) as i64);
            let suppressed_recent = history
                .iter()
                .filter(|entry| {
                    entry.rule_id.as_deref() == Some(rule.id.as_str())
                        && entry.status == "suppressed"
                })
                .map(|entry| entry.triggered_at)
                .max()
                .map(|last| now.signed_duration_since(last) < suppress_window)
                .unwrap_or(false);
            if suppressed_recent {
                return Ok(None);
            }
            let entry = AlertHistoryEntry {
                id: format!("history-{}", Uuid::new_v4().simple()),
                rule_id: Some(rule.id.clone()),
                rule_name: Some(rule.name.clone()),
                severity: rule.severity.clone(),
                status: "suppressed".to_string(),
                message: suppressed_message,
                triggered_at: now,
                source,
                assignee: None,
                claimed_at: None,
                acknowledged_by: None,
                acknowledged_at: None,
                resolved_by: Some("system".to_string()),
                resolved_at: Some(now),
                details: json!({
                    "metric": rule.metric,
                    "condition": rule.condition,
                    "threshold": rule.threshold,
                    "window_minutes": rule.window_minutes,
                    "value": value,
                    "matched": true,
                    "silenced": true,
                    "silence_id": silence.as_ref().map(|item| item.id.clone()),
                    "silence_name": silence.as_ref().map(|item| item.name.clone()),
                    "evaluator": evaluated_by,
                }),
            };
            history.push(entry.clone());
            return Ok(Some(entry));
        }

        let mut resolved = None::<AlertHistoryEntry>;
        for entry in history.iter_mut().filter(|entry| {
            entry.rule_id.as_deref() == Some(rule.id.as_str())
                && entry.status == "firing"
                && entry.resolved_at.is_none()
        }) {
            entry.status = "resolved".to_string();
            entry.resolved_by = Some("system".to_string());
            entry.resolved_at = Some(now);
            entry.message = recovered_message.clone();
            entry.details = json!({
                "metric": rule.metric,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "value": value,
                "matched": false,
                "silenced": false,
                "evaluator": evaluated_by,
            });
            if resolved
                .as_ref()
                .map(|current| entry.triggered_at > current.triggered_at)
                .unwrap_or(true)
            {
                resolved = Some(entry.clone());
            }
        }
        if resolved.is_some() {
            return Ok(resolved);
        }
        if !record_stable_state {
            return Ok(None);
        }

        let entry = AlertHistoryEntry {
            id: format!("history-{}", Uuid::new_v4().simple()),
            rule_id: Some(rule.id.clone()),
            rule_name: Some(rule.name.clone()),
            severity: rule.severity,
            status: "resolved".to_string(),
            message: stable_message,
            triggered_at: now,
            source,
            assignee: None,
            claimed_at: None,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: Some(evaluated_by.to_string()),
            resolved_at: Some(now),
            details: json!({
                "metric": rule.metric,
                "condition": rule.condition,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "value": value,
                "matched": false,
                "silenced": false,
                "evaluator": evaluated_by,
                "stable_snapshot": true,
            }),
        };
        history.push(entry.clone());
        Ok(Some(entry))
    }

    pub async fn evaluate_alert_rule_now(
        &self,
        rule_id: &str,
        evaluated_by: &str,
    ) -> Result<AlertHistoryEntry, String> {
        let now = Utc::now();
        let rule = self
            .alert_rules
            .read()
            .await
            .iter()
            .find(|rule| rule.id == rule_id)
            .cloned()
            .ok_or_else(|| bilingual_runtime_error("告警规则不存在", "alert rule not found"))?;
        if !rule.enabled {
            return Err(bilingual_runtime_error(
                "告警规则已禁用",
                "alert rule is disabled",
            ));
        }
        self.evaluate_alert_rule_once(rule, now, true, evaluated_by)
            .await?
            .ok_or_else(|| {
                bilingual_runtime_error(
                    "告警规则评估未产生状态变更",
                    "alert rule evaluation produced no transition",
                )
            })
    }

    pub(crate) async fn process_alert_rules_once(&self) -> Result<usize, String> {
        let now = Utc::now();
        let rules = self
            .alert_rules
            .read()
            .await
            .iter()
            .filter(|rule| rule.enabled)
            .cloned()
            .collect::<Vec<_>>();
        let mut transitions = 0usize;
        let mut first_error = None::<String>;
        for rule in rules {
            match self
                .evaluate_alert_rule_once(rule, now, false, "system")
                .await
            {
                Ok(Some(entry)) => {
                    transitions += 1;
                    if let Err(err) = self.enqueue_alert_deliveries(&entry).await {
                        if first_error.is_none() {
                            first_error = Some(err);
                        }
                    }
                    self.push_event(
                        "alerts.rule.evaluated",
                        "alerts-service",
                        json!({
                            "rule_id": entry.rule_id,
                            "status": entry.status,
                            "severity": entry.severity,
                        }),
                    )
                    .await;
                }
                Ok(None) => {}
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }
        if transitions == 0 {
            if let Some(err) = first_error {
                return Err(err);
            }
        }
        Ok(transitions)
    }

    pub(crate) fn alert_delivery_retry_delay(attempts: u32) -> std::time::Duration {
        let base = Self::alert_delivery_retry_base_interval();
        let max = Self::alert_delivery_retry_max_interval();
        let exponent = attempts.saturating_sub(1).min(10);
        let factor = 1u64 << exponent;
        let delay_ms = (base.as_millis() as u64).saturating_mul(factor);
        std::time::Duration::from_millis(delay_ms.min(max.as_millis() as u64))
    }

    pub(crate) fn alert_delivery_spool_path(&self, kind: &str) -> PathBuf {
        self.data_dir
            .join(".rustio_alerts")
            .join(format!("{kind}.ndjson"))
    }

    pub(crate) fn alert_delivery_write_spool(
        &self,
        kind: &str,
        payload: &Value,
    ) -> Result<(), String> {
        let path = self.alert_delivery_spool_path(kind);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                bilingual_runtime_error(
                    "创建告警投递落盘目录失败",
                    format!("create alert spool dir failed: {err}"),
                )
            })?;
        }
        let line = serde_json::to_string(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化告警投递内容失败",
                format!("serialize alert delivery payload failed: {err}"),
            )
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| {
                bilingual_runtime_error(
                    "打开告警投递落盘文件失败",
                    format!("open alert spool file failed: {err}"),
                )
            })?;
        file.write_all(format!("{line}\n").as_bytes())
            .map_err(|err| {
                bilingual_runtime_error(
                    "写入告警投递落盘文件失败",
                    format!("write alert spool file failed: {err}"),
                )
            })?;
        Ok(())
    }

    pub(crate) fn alert_delivery_sanitize_header(value: &str) -> String {
        value
            .chars()
            .filter(|ch| *ch != '\r' && *ch != '\n')
            .collect::<String>()
            .trim()
            .to_string()
    }

    pub(crate) fn alert_delivery_parse_smtp_endpoint(
        endpoint: &str,
    ) -> Option<(String, String, AlertSmtpTransport)> {
        let (raw, transport) = if let Some(raw) = endpoint.strip_prefix("smtp+starttls://") {
            (raw, AlertSmtpTransport::StartTls)
        } else if let Some(raw) = endpoint.strip_prefix("smtps://") {
            (raw, AlertSmtpTransport::Tls)
        } else if let Some(raw) = endpoint.strip_prefix("smtp://") {
            let transport = if Self::alert_delivery_smtp_tls_default() {
                AlertSmtpTransport::Tls
            } else if Self::alert_delivery_smtp_starttls_default() {
                AlertSmtpTransport::StartTls
            } else {
                AlertSmtpTransport::Plain
            };
            (raw, transport)
        } else {
            return None;
        };
        let (server, recipient) = raw.split_once('/')?;
        let server = server.trim();
        let recipient = recipient.trim().trim_start_matches('/');
        if server.is_empty() || recipient.is_empty() {
            return None;
        }
        Some((server.to_string(), recipient.to_string(), transport))
    }

    pub(crate) fn alert_delivery_parse_smtp_server_transport(
        raw: &str,
    ) -> (String, AlertSmtpTransport) {
        if let Some(server) = raw.strip_prefix("smtp+starttls://") {
            return (server.trim().to_string(), AlertSmtpTransport::StartTls);
        }
        if let Some(server) = raw.strip_prefix("smtps://") {
            return (server.trim().to_string(), AlertSmtpTransport::Tls);
        }
        if let Some(server) = raw.strip_prefix("smtp://") {
            let transport = if Self::alert_delivery_smtp_tls_default() {
                AlertSmtpTransport::Tls
            } else if Self::alert_delivery_smtp_starttls_default() {
                AlertSmtpTransport::StartTls
            } else {
                AlertSmtpTransport::Plain
            };
            return (server.trim().to_string(), transport);
        }
        if Self::alert_delivery_smtp_tls_default() {
            (raw.trim().to_string(), AlertSmtpTransport::Tls)
        } else if Self::alert_delivery_smtp_starttls_default() {
            (raw.trim().to_string(), AlertSmtpTransport::StartTls)
        } else {
            (raw.trim().to_string(), AlertSmtpTransport::Plain)
        }
    }

    pub(crate) fn alert_delivery_parse_smtp_server_auth(
        server: &str,
    ) -> (String, Option<String>, Option<String>) {
        let Some((auth, host)) = server.rsplit_once('@') else {
            return (server.trim().to_string(), None, None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return (server.trim().to_string(), None, None);
        }
        let Some((username, password)) = auth.split_once(':') else {
            return (host, Some(auth.trim().to_string()), None);
        };
        let username = username.trim().to_string();
        let password = password.trim().to_string();
        (
            host,
            if username.is_empty() {
                None
            } else {
                Some(username)
            },
            if password.is_empty() {
                None
            } else {
                Some(password)
            },
        )
    }

    pub(crate) fn alert_delivery_parse_nats_endpoint(
        endpoint: &str,
    ) -> Option<(String, Option<String>, bool)> {
        let (raw, tls) = if let Some(raw) = endpoint.strip_prefix("natss://") {
            (raw, true)
        } else if let Some(raw) = endpoint.strip_prefix("nats://") {
            (raw, Self::alert_delivery_nats_tls_default())
        } else {
            return None;
        };
        let (server, subject) = if let Some((server, subject)) = raw.split_once('/') {
            (server.trim(), Some(subject.trim().trim_start_matches('/')))
        } else {
            (raw.trim(), None)
        };
        if server.is_empty() {
            return None;
        }
        let subject = subject.and_then(|value| {
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        Some((server.to_string(), subject, tls))
    }

    pub(crate) fn alert_delivery_parse_nats_server_auth(
        server: &str,
    ) -> (String, Option<String>, Option<String>, Option<String>) {
        let Some((auth, host)) = server.rsplit_once('@') else {
            return (server.trim().to_string(), None, None, None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return (server.trim().to_string(), None, None, None);
        }
        if let Some((username, password)) = auth.split_once(':') {
            let username = username.trim().to_string();
            let password = password.trim().to_string();
            return (
                host,
                if username.is_empty() {
                    None
                } else {
                    Some(username)
                },
                if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                None,
            );
        }
        let token = auth.trim().to_string();
        (
            host,
            None,
            None,
            if token.is_empty() { None } else { Some(token) },
        )
    }

    pub(crate) fn alert_delivery_parse_redis_endpoint(
        endpoint: &str,
    ) -> Option<(String, Option<String>, bool)> {
        let (raw, tls) = if let Some(raw) = endpoint.strip_prefix("rediss://") {
            (raw, true)
        } else if let Some(raw) = endpoint.strip_prefix("redis://") {
            (raw, Self::alert_delivery_redis_tls_default())
        } else {
            return None;
        };
        let (server, channel) = if let Some((server, channel)) = raw.split_once('/') {
            (server.trim(), Some(channel.trim().trim_start_matches('/')))
        } else {
            (raw.trim(), None)
        };
        if server.is_empty() {
            return None;
        }
        let channel = channel.and_then(|value| {
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        Some((server.to_string(), channel, tls))
    }

    pub(crate) fn alert_delivery_parse_redis_server_auth(
        server: &str,
    ) -> (String, Option<String>, Option<String>) {
        let Some((auth, host)) = server.rsplit_once('@') else {
            return (server.trim().to_string(), None, None);
        };
        let host = host.trim().to_string();
        if host.is_empty() {
            return (server.trim().to_string(), None, None);
        }
        if let Some((username, password)) = auth.split_once(':') {
            let username = username.trim().to_string();
            let password = password.trim().to_string();
            return (
                host,
                if username.is_empty() {
                    None
                } else {
                    Some(username)
                },
                if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
            );
        }
        let password = auth.trim().to_string();
        (
            host,
            None,
            if password.is_empty() {
                None
            } else {
                Some(password)
            },
        )
    }

    pub(crate) fn alert_delivery_server_name(server: &str) -> Option<String> {
        let host = if server.starts_with('[') {
            let end = server.find(']')?;
            server[1..end].to_string()
        } else {
            server
                .split(':')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }

    pub(crate) fn alert_delivery_tls_connector() -> Result<TlsConnector, String> {
        static TLS_PROVIDER_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        TLS_PROVIDER_INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        let mut root_store = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        if let Some(path) = Self::alert_delivery_tls_ca_file() {
            let pem = std::fs::read(&path).map_err(|err| {
                bilingual_runtime_error(
                    "读取告警 TLS CA 证书文件失败",
                    format!("read alert tls ca certificate file failed: {err}"),
                )
            })?;
            let mut reader = std::io::Cursor::new(pem);
            let mut loaded = 0usize;
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|err| {
                    bilingual_runtime_error(
                        "解析告警 TLS CA 证书失败",
                        format!("parse alert tls ca certificate failed: {err}"),
                    )
                })?;
                root_store.add(cert).map_err(|err| {
                    bilingual_runtime_error(
                        "加载告警 TLS CA 证书失败",
                        format!("load alert tls ca certificate failed: {err}"),
                    )
                })?;
                loaded += 1;
            }
            if loaded == 0 {
                return Err(bilingual_runtime_error(
                    "告警 TLS CA 证书文件中没有可用证书",
                    format!(
                        "alert tls ca certificate file does not contain usable certificates: {path}"
                    ),
                ));
            }
        }
        if native.errors.iter().any(|_| true) && root_store.is_empty() {
            return Err(bilingual_runtime_error(
                "加载系统根证书失败",
                "load system root certificates failed",
            ));
        }
        if root_store.is_empty() {
            return Err(bilingual_runtime_error(
                "系统根证书为空",
                "system root certificates are empty",
            ));
        }
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }

    pub(crate) async fn alert_delivery_tls_wrap(
        server: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, String> {
        let connector = Self::alert_delivery_tls_connector()?;
        let server_name_raw = Self::alert_delivery_server_name(server).ok_or_else(|| {
            bilingual_runtime_error(
                "TLS 服务器名无效",
                format!("invalid tls server name: {server}"),
            )
        })?;
        let server_name: ServerName<'static> = ServerName::try_from(server_name_raw.clone())
            .map_err(|_| {
                bilingual_runtime_error(
                    "TLS 服务器名无效",
                    format!("invalid tls server name: {server_name_raw}"),
                )
            })?;
        timeout(
            Self::alert_delivery_http_timeout(),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| bilingual_runtime_error("TLS 握手超时", "tls handshake timed out"))?
        .map_err(|err| {
            bilingual_runtime_error("TLS 握手失败", format!("tls handshake failed: {err}"))
        })
    }

    pub(crate) async fn alert_delivery_smtp_read_response<T>(
        reader: &mut BufReader<T>,
    ) -> Result<(u16, String), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let mut merged = String::new();
        let code = loop {
            let mut line = String::new();
            let size = timeout(timeout_duration, reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    bilingual_runtime_error("读取 SMTP 响应超时", "read smtp response timed out")
                })?
                .map_err(|err| {
                    bilingual_runtime_error(
                        "读取 SMTP 响应失败",
                        format!("read smtp response failed: {err}"),
                    )
                })?;
            if size == 0 {
                return Err(bilingual_runtime_error(
                    "SMTP 连接提前关闭",
                    "smtp connection closed unexpectedly",
                ));
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if !merged.is_empty() {
                merged.push('\n');
            }
            merged.push_str(trimmed);
            let bytes = trimmed.as_bytes();
            if bytes.len() < 3
                || !bytes[0].is_ascii_digit()
                || !bytes[1].is_ascii_digit()
                || !bytes[2].is_ascii_digit()
            {
                return Err(bilingual_runtime_error(
                    "SMTP 响应格式错误",
                    format!("smtp response malformed: {trimmed}"),
                ));
            }
            let parsed = std::str::from_utf8(&bytes[0..3])
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| {
                    bilingual_runtime_error(
                        "SMTP 响应码解析失败",
                        format!("smtp response code parse failed: {trimmed}"),
                    )
                })?;
            let continued = bytes.get(3) == Some(&b'-');
            if !continued {
                break parsed;
            }
        };
        Ok((code, merged))
    }

    pub(crate) async fn alert_delivery_smtp_command<T>(
        reader: &mut BufReader<T>,
        command: &str,
        expected_codes: &[u16],
    ) -> Result<String, String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        timeout(
            timeout_duration,
            reader.get_mut().write_all(command.as_bytes()),
        )
        .await
        .map_err(|_| {
            bilingual_runtime_error(
                "写入 SMTP 命令超时",
                format!("write smtp command timed out: {}", command.trim()),
            )
        })?
        .map_err(|err| {
            bilingual_runtime_error(
                "写入 SMTP 命令失败",
                format!("write smtp command failed: {err}"),
            )
        })?;
        timeout(timeout_duration, reader.get_mut().flush())
            .await
            .map_err(|_| {
                bilingual_runtime_error("刷新 SMTP 命令超时", "flush smtp command timed out")
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "刷新 SMTP 命令失败",
                    format!("flush smtp command failed: {err}"),
                )
            })?;
        let (code, response) = Self::alert_delivery_smtp_read_response(reader).await?;
        if expected_codes.contains(&code) {
            Ok(response)
        } else {
            Err(bilingual_runtime_error(
                "SMTP 返回错误状态码",
                format!(
                    "smtp command {} failed with code {} response={}",
                    command.trim(),
                    code,
                    response
                ),
            ))
        }
    }

    pub(crate) async fn alert_delivery_smtp_auth_and_send<T>(
        reader: &mut BufReader<T>,
        ehlo_response: &str,
        from: &str,
        to: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if let (Some(username), Some(password)) = (username, password) {
            let username_clean = Self::alert_delivery_sanitize_header(username);
            let password_clean = Self::alert_delivery_sanitize_header(password);
            if username_clean.is_empty() || password_clean.is_empty() {
                return Err(bilingual_runtime_error(
                    "SMTP 认证信息无效",
                    "smtp auth username/password is empty",
                ));
            }
            let auth_plain = BASE64.encode(format!("\0{username_clean}\0{password_clean}"));
            let plain_command = format!("AUTH PLAIN {auth_plain}\r\n");
            let plain_result =
                Self::alert_delivery_smtp_command(reader, &plain_command, &[235, 250]).await;
            if plain_result.is_err() {
                if !ehlo_response.to_ascii_uppercase().contains("AUTH") {
                    return Err(bilingual_runtime_error(
                        "SMTP 服务端不支持认证",
                        "smtp server does not advertise auth capability",
                    ));
                }
                let _ = Self::alert_delivery_smtp_command(reader, "AUTH LOGIN\r\n", &[334]).await?;
                let user_line = format!("{}\r\n", BASE64.encode(username_clean));
                let _ = Self::alert_delivery_smtp_command(reader, &user_line, &[334]).await?;
                let pass_line = format!("{}\r\n", BASE64.encode(password_clean));
                let _ = Self::alert_delivery_smtp_command(reader, &pass_line, &[235]).await?;
            }
        }
        let from_clean = Self::alert_delivery_sanitize_header(from);
        let to_clean = Self::alert_delivery_sanitize_header(to);
        let _ = Self::alert_delivery_smtp_command(
            reader,
            &format!("MAIL FROM:<{from_clean}>\r\n"),
            &[250],
        )
        .await?;
        let _ = Self::alert_delivery_smtp_command(
            reader,
            &format!("RCPT TO:<{to_clean}>\r\n"),
            &[250, 251],
        )
        .await?;
        let _ = Self::alert_delivery_smtp_command(reader, "DATA\r\n", &[354]).await?;
        let subject = Self::alert_delivery_sanitize_header(&format!(
            "RustIO alert {}",
            payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("event")
        ));
        let body = serde_json::to_string_pretty(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 SMTP 告警消息失败",
                format!("serialize smtp payload failed: {err}"),
            )
        })?;
        let message = format!(
            "From: <{from_clean}>\r\nTo: <{to_clean}>\r\nSubject: {subject}\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{body}\r\n.\r\n"
        );
        timeout(
            Self::alert_delivery_http_timeout(),
            reader.get_mut().write_all(message.as_bytes()),
        )
        .await
        .map_err(|_| bilingual_runtime_error("写入 SMTP 消息超时", "write smtp message timed out"))?
        .map_err(|err| {
            bilingual_runtime_error(
                "写入 SMTP 消息失败",
                format!("write smtp message failed: {err}"),
            )
        })?;
        timeout(
            Self::alert_delivery_http_timeout(),
            reader.get_mut().flush(),
        )
        .await
        .map_err(|_| bilingual_runtime_error("刷新 SMTP 消息超时", "flush smtp message timed out"))?
        .map_err(|err| {
            bilingual_runtime_error(
                "刷新 SMTP 消息失败",
                format!("flush smtp message failed: {err}"),
            )
        })?;
        let (data_code, data_response) = Self::alert_delivery_smtp_read_response(reader).await?;
        if data_code != 250 {
            return Err(bilingual_runtime_error(
                "SMTP DATA 提交失败",
                format!(
                    "smtp data commit expected 250 got {} response={data_response}",
                    data_code
                ),
            ));
        }
        let _ = Self::alert_delivery_smtp_command(reader, "QUIT\r\n", &[221]).await;
        Ok(())
    }

    pub(crate) async fn alert_delivery_send_smtp(
        server: &str,
        from: &str,
        to: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        transport: AlertSmtpTransport,
    ) -> Result<(), String> {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let stream = timeout(timeout_duration, TcpStream::connect(server))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    "连接 SMTP 服务器超时",
                    format!("connect smtp server timed out: {server}"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "连接 SMTP 服务器失败",
                    format!("connect smtp server failed: {err}"),
                )
            })?;

        if transport == AlertSmtpTransport::Tls {
            let tls = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut reader = BufReader::new(tls);
            let (greet_code, greet) = Self::alert_delivery_smtp_read_response(&mut reader).await?;
            if greet_code != 220 {
                return Err(bilingual_runtime_error(
                    "SMTP 欢迎响应异常",
                    format!(
                        "smtp greeting expected 220 got {} response={greet}",
                        greet_code
                    ),
                ));
            }
            let ehlo_response =
                Self::alert_delivery_smtp_command(&mut reader, "EHLO rustio.local\r\n", &[250])
                    .await?;
            return Self::alert_delivery_smtp_auth_and_send(
                &mut reader,
                &ehlo_response,
                from,
                to,
                payload,
                username,
                password,
            )
            .await;
        }

        let mut reader = BufReader::new(stream);
        let (greet_code, greet) = Self::alert_delivery_smtp_read_response(&mut reader).await?;
        if greet_code != 220 {
            return Err(bilingual_runtime_error(
                "SMTP 欢迎响应异常",
                format!(
                    "smtp greeting expected 220 got {} response={greet}",
                    greet_code
                ),
            ));
        }
        let mut ehlo_response =
            Self::alert_delivery_smtp_command(&mut reader, "EHLO rustio.local\r\n", &[250]).await?;
        if transport == AlertSmtpTransport::StartTls {
            if !ehlo_response.to_ascii_uppercase().contains("STARTTLS") {
                return Err(bilingual_runtime_error(
                    "SMTP 服务端不支持 STARTTLS",
                    "smtp server does not advertise STARTTLS",
                ));
            }
            let _ = Self::alert_delivery_smtp_command(&mut reader, "STARTTLS\r\n", &[220]).await?;
            let stream = reader.into_inner();
            let tls = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut tls_reader = BufReader::new(tls);
            ehlo_response =
                Self::alert_delivery_smtp_command(&mut tls_reader, "EHLO rustio.local\r\n", &[250])
                    .await?;
            return Self::alert_delivery_smtp_auth_and_send(
                &mut tls_reader,
                &ehlo_response,
                from,
                to,
                payload,
                username,
                password,
            )
            .await;
        }
        Self::alert_delivery_smtp_auth_and_send(
            &mut reader,
            &ehlo_response,
            from,
            to,
            payload,
            username,
            password,
        )
        .await
    }

    pub(crate) async fn alert_delivery_nats_publish<T>(
        reader: &mut BufReader<T>,
        subject: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
        tls: bool,
    ) -> Result<(), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let mut info = String::new();
        let _ = timeout(timeout_duration, reader.read_line(&mut info)).await;

        let payload_raw = serde_json::to_string(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 NATS 告警消息失败",
                format!("serialize nats payload failed: {err}"),
            )
        })?;
        let mut connect_payload = json!({
            "verbose": false,
            "pedantic": false,
            "tls_required": tls,
        });
        if let Some(token) = token {
            let token = token.trim();
            if token.is_empty() {
                return Err(bilingual_runtime_error(
                    "NATS token 为空",
                    "nats token is empty",
                ));
            }
            connect_payload["auth_token"] = Value::String(token.to_string());
        } else if let (Some(username), Some(password)) = (username, password) {
            let username = username.trim();
            let password = password.trim();
            if username.is_empty() || password.is_empty() {
                return Err(bilingual_runtime_error(
                    "NATS 用户名或密码为空",
                    "nats username or password is empty",
                ));
            }
            connect_payload["user"] = Value::String(username.to_string());
            connect_payload["pass"] = Value::String(password.to_string());
        }
        let connect_raw = serde_json::to_string(&connect_payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 NATS CONNECT 载荷失败",
                format!("serialize nats connect payload failed: {err}"),
            )
        })?;
        let connect_line = format!("CONNECT {connect_raw}\r\n");
        let publish_line = format!(
            "PUB {} {}\r\n{}\r\nPING\r\n",
            subject,
            payload_raw.len(),
            payload_raw
        );
        timeout(
            timeout_duration,
            reader
                .get_mut()
                .write_all(format!("{connect_line}{publish_line}").as_bytes()),
        )
        .await
        .map_err(|_| bilingual_runtime_error("写入 NATS 消息超时", "write nats message timed out"))?
        .map_err(|err| {
            bilingual_runtime_error(
                "写入 NATS 消息失败",
                format!("write nats message failed: {err}"),
            )
        })?;
        timeout(timeout_duration, reader.get_mut().flush())
            .await
            .map_err(|_| {
                bilingual_runtime_error("刷新 NATS 消息超时", "flush nats message timed out")
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "刷新 NATS 消息失败",
                    format!("flush nats message failed: {err}"),
                )
            })?;

        for _ in 0..4 {
            let mut line = String::new();
            let size = timeout(timeout_duration, reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    bilingual_runtime_error("读取 NATS 响应超时", "read nats response timed out")
                })?
                .map_err(|err| {
                    bilingual_runtime_error(
                        "读取 NATS 响应失败",
                        format!("read nats response failed: {err}"),
                    )
                })?;
            if size == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("PONG") {
                return Ok(());
            }
            if trimmed.starts_with("-ERR") {
                return Err(bilingual_runtime_error(
                    "NATS 返回错误响应",
                    format!("nats responded with error: {trimmed}"),
                ));
            }
        }
        Err(bilingual_runtime_error(
            "NATS 未返回确认响应",
            "nats did not return acknowledge response",
        ))
    }

    pub(crate) async fn alert_delivery_send_nats(
        server: &str,
        subject: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
        tls: bool,
    ) -> Result<(), String> {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let stream = timeout(timeout_duration, TcpStream::connect(server))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    "连接 NATS 服务器超时",
                    format!("connect nats server timed out: {server}"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "连接 NATS 服务器失败",
                    format!("connect nats server failed: {err}"),
                )
            })?;
        if tls {
            let tls_stream = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut reader = BufReader::new(tls_stream);
            return Self::alert_delivery_nats_publish(
                &mut reader,
                subject,
                payload,
                username,
                password,
                token,
                true,
            )
            .await;
        }
        let mut reader = BufReader::new(stream);
        Self::alert_delivery_nats_publish(
            &mut reader,
            subject,
            payload,
            username,
            password,
            token,
            false,
        )
        .await
    }

    pub(crate) fn alert_delivery_redis_command(parts: &[&str]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
        for part in parts {
            output.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
            output.extend_from_slice(part.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
        output
    }

    pub(crate) async fn alert_delivery_redis_run_command<T>(
        reader: &mut BufReader<T>,
        command: &[&str],
        error_prefix_zh: &str,
        error_prefix_en: &str,
    ) -> Result<String, String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let payload = Self::alert_delivery_redis_command(command);
        timeout(timeout_duration, reader.get_mut().write_all(&payload))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: write timed out"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: write failed: {err}"),
                )
            })?;
        timeout(timeout_duration, reader.get_mut().flush())
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: flush timed out"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: flush failed: {err}"),
                )
            })?;

        let mut line = String::new();
        let size = timeout(timeout_duration, reader.read_line(&mut line))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: read timed out"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    error_prefix_zh,
                    format!("{error_prefix_en}: read failed: {err}"),
                )
            })?;
        if size == 0 {
            return Err(bilingual_runtime_error(
                error_prefix_zh,
                format!("{error_prefix_en}: empty response"),
            ));
        }
        let trimmed = line.trim();
        if trimmed.starts_with('-') {
            return Err(bilingual_runtime_error(
                error_prefix_zh,
                format!("{error_prefix_en}: {trimmed}"),
            ));
        }
        Ok(trimmed.to_string())
    }

    pub(crate) async fn alert_delivery_redis_publish<T>(
        reader: &mut BufReader<T>,
        channel: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), String>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if username.is_some() && password.is_none() {
            return Err(bilingual_runtime_error(
                "Redis 认证配置不完整",
                "redis auth requires both username and password when username is specified",
            ));
        }

        if let Some(password) = password {
            let password = password.trim();
            if password.is_empty() {
                return Err(bilingual_runtime_error(
                    "Redis 密码为空",
                    "redis password is empty",
                ));
            }
            if let Some(username) = username {
                let username = username.trim();
                if username.is_empty() {
                    return Err(bilingual_runtime_error(
                        "Redis 用户名为空",
                        "redis username is empty",
                    ));
                }
                let response = Self::alert_delivery_redis_run_command(
                    reader,
                    &["AUTH", username, password],
                    "Redis 认证失败",
                    "redis auth failed",
                )
                .await?;
                if response != "+OK" {
                    return Err(bilingual_runtime_error(
                        "Redis 认证返回异常",
                        format!("redis auth returned unexpected response: {response}"),
                    ));
                }
            } else {
                let response = Self::alert_delivery_redis_run_command(
                    reader,
                    &["AUTH", password],
                    "Redis 认证失败",
                    "redis auth failed",
                )
                .await?;
                if response != "+OK" {
                    return Err(bilingual_runtime_error(
                        "Redis 认证返回异常",
                        format!("redis auth returned unexpected response: {response}"),
                    ));
                }
            }
        }

        let payload_raw = serde_json::to_string(payload).map_err(|err| {
            bilingual_runtime_error(
                "序列化 Redis 通知载荷失败",
                format!("serialize redis payload failed: {err}"),
            )
        })?;
        let response = Self::alert_delivery_redis_run_command(
            reader,
            &["PUBLISH", channel, &payload_raw],
            "Redis 发布失败",
            "redis publish failed",
        )
        .await?;
        if !response.starts_with(':') {
            return Err(bilingual_runtime_error(
                "Redis 发布返回异常",
                format!("redis publish returned unexpected response: {response}"),
            ));
        }
        Ok(())
    }

    pub(crate) async fn alert_delivery_send_redis(
        server: &str,
        channel: &str,
        payload: &Value,
        username: Option<&str>,
        password: Option<&str>,
        tls: bool,
    ) -> Result<(), String> {
        let timeout_duration = Self::alert_delivery_http_timeout();
        let stream = timeout(timeout_duration, TcpStream::connect(server))
            .await
            .map_err(|_| {
                bilingual_runtime_error(
                    "连接 Redis 服务器超时",
                    format!("connect redis server timed out: {server}"),
                )
            })?
            .map_err(|err| {
                bilingual_runtime_error(
                    "连接 Redis 服务器失败",
                    format!("connect redis server failed: {err}"),
                )
            })?;
        if tls {
            let tls_stream = Self::alert_delivery_tls_wrap(server, stream).await?;
            let mut reader = BufReader::new(tls_stream);
            return Self::alert_delivery_redis_publish(
                &mut reader,
                channel,
                payload,
                username,
                password,
            )
            .await;
        }
        let mut reader = BufReader::new(stream);
        Self::alert_delivery_redis_publish(&mut reader, channel, payload, username, password).await
    }

    pub(crate) fn alert_delivery_template_value(
        payload: &Value,
        expression: &str,
    ) -> Option<String> {
        let expression = expression
            .trim()
            .trim_start_matches("payload.")
            .trim_start_matches("$.")
            .trim_start_matches('.');
        if expression.is_empty() {
            return Some(String::new());
        }
        let mut current = payload;
        for segment in expression.split('.') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            current = match current {
                Value::Object(map) => map.get(segment)?,
                _ => return None,
            };
        }
        match current {
            Value::Null => Some(String::new()),
            Value::String(value) => Some(value.clone()),
            Value::Bool(value) => Some(value.to_string()),
            Value::Number(value) => Some(value.to_string()),
            Value::Array(_) | Value::Object(_) => serde_json::to_string(current).ok(),
        }
    }

    pub(crate) fn alert_delivery_render_template(
        template: &str,
        payload: &Value,
    ) -> Result<String, String> {
        let mut rendered = String::new();
        let mut remaining = template;
        while let Some(start) = remaining.find("{{") {
            rendered.push_str(&remaining[..start]);
            let placeholder = &remaining[start + 2..];
            let Some(end) = placeholder.find("}}") else {
                return Err(bilingual_runtime_error(
                    "通知模板占位符未闭合",
                    "alert template contains an unclosed placeholder",
                ));
            };
            let expression = placeholder[..end].trim();
            let value =
                Self::alert_delivery_template_value(payload, expression).unwrap_or_default();
            rendered.push_str(&value);
            remaining = &placeholder[end + 2..];
        }
        rendered.push_str(remaining);
        Ok(rendered)
    }

    pub(crate) fn alert_delivery_render_headers(
        channel: &AlertChannel,
        payload: &Value,
    ) -> Result<Vec<(String, String)>, String> {
        let mut headers = channel
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        for (key, template) in &channel.header_template {
            headers.push((
                key.clone(),
                Self::alert_delivery_render_template(template, payload)?,
            ));
        }
        Ok(headers)
    }

    pub(crate) fn alert_delivery_render_http_body(
        channel: &AlertChannel,
        payload: &Value,
    ) -> Result<(String, Vec<u8>), String> {
        let kind = channel.kind.trim().to_ascii_lowercase();
        let rendered_template = match channel.payload_template.as_deref() {
            Some(template) => Some(Self::alert_delivery_render_template(template, payload)?),
            None => None,
        };
        match kind.as_str() {
            "kafka" => {
                let value = match rendered_template {
                    Some(rendered) => {
                        serde_json::from_str::<Value>(&rendered).unwrap_or(Value::String(rendered))
                    }
                    None => payload.clone(),
                };
                let body = serde_json::to_vec(&json!({ "records": [{ "value": value }] }))
                    .map_err(|err| {
                        bilingual_runtime_error(
                            "序列化 Kafka 通知载荷失败",
                            format!("serialize kafka payload failed: {err}"),
                        )
                    })?;
                Ok(("application/vnd.kafka.json.v2+json".to_string(), body))
            }
            "rabbitmq" => {
                let routing_key = reqwest::Url::parse(channel.endpoint.trim())
                    .ok()
                    .and_then(|url| {
                        url.query_pairs()
                            .find(|(key, _)| key == "routing_key")
                            .map(|(_, value)| value.to_string())
                    })
                    .unwrap_or_else(|| "rustio.alerts".to_string());
                let payload_string = match rendered_template {
                    Some(rendered) => rendered,
                    None => serde_json::to_string(payload).map_err(|err| {
                        bilingual_runtime_error(
                            "序列化 RabbitMQ 通知载荷失败",
                            format!("serialize rabbitmq payload failed: {err}"),
                        )
                    })?,
                };
                let body = serde_json::to_vec(&json!({
                    "properties": {},
                    "routing_key": routing_key,
                    "payload": payload_string,
                    "payload_encoding": "string",
                }))
                .map_err(|err| {
                    bilingual_runtime_error(
                        "序列化 RabbitMQ 发布载荷失败",
                        format!("serialize rabbitmq publish payload failed: {err}"),
                    )
                })?;
                Ok(("application/json".to_string(), body))
            }
            _ => {
                if let Some(rendered) = rendered_template {
                    let content_type = if serde_json::from_str::<Value>(&rendered).is_ok() {
                        "application/json".to_string()
                    } else {
                        "text/plain; charset=utf-8".to_string()
                    };
                    return Ok((content_type, rendered.into_bytes()));
                }
                let body = serde_json::to_vec(payload).map_err(|err| {
                    bilingual_runtime_error(
                        "序列化 HTTP 通知载荷失败",
                        format!("serialize http payload failed: {err}"),
                    )
                })?;
                Ok(("application/json".to_string(), body))
            }
        }
    }

    pub async fn dispatch_alert_channel_message(
        &self,
        channel: &AlertChannel,
        payload: &Value,
    ) -> Result<(), String> {
        if !channel.enabled {
            return Err(bilingual_runtime_error(
                "通知渠道已禁用",
                format!("alert channel {} is disabled", channel.id),
            ));
        }
        let endpoint = channel.endpoint.trim();
        if endpoint.is_empty() {
            return Err(bilingual_runtime_error(
                "通知渠道地址为空",
                format!("alert channel {} endpoint is empty", channel.id),
            ));
        }
        let kind = channel.kind.trim().to_ascii_lowercase();
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            let client = Client::builder()
                .timeout(Self::alert_delivery_http_timeout())
                .build()
                .map_err(|err| {
                    bilingual_runtime_error(
                        "创建告警投递客户端失败",
                        format!("build alert delivery client failed: {err}"),
                    )
                })?;
            let (content_type, body) = Self::alert_delivery_render_http_body(channel, payload)?;
            let mut request = client.post(endpoint).body(body);
            let mut content_type_present = false;
            for (key, value) in Self::alert_delivery_render_headers(channel, payload)? {
                if key.eq_ignore_ascii_case("content-type") {
                    content_type_present = true;
                }
                request = request.header(&key, value);
            }
            if !content_type_present {
                request = request.header("content-type", content_type);
            }
            let response = request.send().await.map_err(|err| {
                bilingual_runtime_error(
                    "发送告警通知失败",
                    format!("alert channel {} request failed: {err}", channel.id),
                )
            })?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let summary = Self::replication_remote_response_summary(&body);
                return Err(bilingual_runtime_error(
                    "告警通道返回非成功状态",
                    format!(
                        "alert channel {} responded {} body={summary}",
                        channel.id, status
                    ),
                ));
            }
            return Ok(());
        }

        match kind.as_str() {
            "email" => {
                if let Some((server, recipient, transport)) =
                    Self::alert_delivery_parse_smtp_endpoint(endpoint)
                {
                    let from = Self::alert_delivery_smtp_from();
                    let (server, endpoint_username, endpoint_password) =
                        Self::alert_delivery_parse_smtp_server_auth(&server);
                    let username = endpoint_username.or_else(Self::alert_delivery_smtp_username);
                    let password = endpoint_password.or_else(Self::alert_delivery_smtp_password);
                    if username.is_some() ^ password.is_some() {
                        return Err(bilingual_runtime_error(
                            "SMTP 认证配置不完整",
                            "smtp auth requires both username and password",
                        ));
                    }
                    return Self::alert_delivery_send_smtp(
                        &server,
                        &from,
                        &recipient,
                        payload,
                        username.as_deref(),
                        password.as_deref(),
                        transport,
                    )
                    .await;
                }
                if endpoint.contains('@') {
                    if let Some(server) = Self::alert_delivery_smtp_server() {
                        let from = Self::alert_delivery_smtp_from();
                        let (server_with_auth, transport) =
                            Self::alert_delivery_parse_smtp_server_transport(&server);
                        let (server, endpoint_username, endpoint_password) =
                            Self::alert_delivery_parse_smtp_server_auth(&server_with_auth);
                        let username =
                            endpoint_username.or_else(Self::alert_delivery_smtp_username);
                        let password =
                            endpoint_password.or_else(Self::alert_delivery_smtp_password);
                        if username.is_some() ^ password.is_some() {
                            return Err(bilingual_runtime_error(
                                "SMTP 认证配置不完整",
                                "smtp auth requires both username and password",
                            ));
                        }
                        return Self::alert_delivery_send_smtp(
                            &server,
                            &from,
                            endpoint,
                            payload,
                            username.as_deref(),
                            password.as_deref(),
                            transport,
                        )
                        .await;
                    }
                    return self.alert_delivery_write_spool("email", payload);
                }
                Err(bilingual_runtime_error(
                    "邮件通知地址无效",
                    format!("email endpoint is invalid: {}", channel.endpoint),
                ))
            }
            "nats" => {
                let Some((server, subject_opt, tls)) =
                    Self::alert_delivery_parse_nats_endpoint(endpoint)
                else {
                    return Err(bilingual_runtime_error(
                        "NATS 通知地址无效",
                        format!("nats endpoint is invalid: {}", channel.endpoint),
                    ));
                };
                let subject = subject_opt.unwrap_or_else(Self::alert_delivery_nats_default_subject);
                let (server, endpoint_username, endpoint_password, endpoint_token) =
                    Self::alert_delivery_parse_nats_server_auth(&server);
                let token = endpoint_token.or_else(Self::alert_delivery_nats_token);
                let username = endpoint_username.or_else(Self::alert_delivery_nats_username);
                let password = endpoint_password.or_else(Self::alert_delivery_nats_password);
                if token.is_some() && (username.is_some() || password.is_some()) {
                    return Err(bilingual_runtime_error(
                        "NATS 认证配置冲突",
                        "nats auth cannot use token and username/password together",
                    ));
                }
                if username.is_some() ^ password.is_some() {
                    return Err(bilingual_runtime_error(
                        "NATS 认证配置不完整",
                        "nats auth requires both username and password",
                    ));
                }
                Self::alert_delivery_send_nats(
                    &server,
                    &subject,
                    payload,
                    username.as_deref(),
                    password.as_deref(),
                    token.as_deref(),
                    tls,
                )
                .await
            }
            "redis" => {
                let Some((server, channel_opt, tls)) =
                    Self::alert_delivery_parse_redis_endpoint(endpoint)
                else {
                    return Err(bilingual_runtime_error(
                        "Redis 通知地址无效",
                        format!("redis endpoint is invalid: {}", channel.endpoint),
                    ));
                };
                let channel_name =
                    channel_opt.unwrap_or_else(Self::alert_delivery_redis_default_channel);
                let (server, endpoint_username, endpoint_password) =
                    Self::alert_delivery_parse_redis_server_auth(&server);
                let username = endpoint_username.or_else(Self::alert_delivery_redis_username);
                let password = endpoint_password.or_else(Self::alert_delivery_redis_password);
                if username.is_some() && password.is_none() {
                    return Err(bilingual_runtime_error(
                        "Redis 认证配置不完整",
                        "redis auth requires password when username is specified",
                    ));
                }
                Self::alert_delivery_send_redis(
                    &server,
                    &channel_name,
                    payload,
                    username.as_deref(),
                    password.as_deref(),
                    tls,
                )
                .await
            }
            "webhook" | "slack" | "elasticsearch" | "kafka" | "rabbitmq" => {
                Err(bilingual_runtime_error(
                    "通知渠道地址协议无效",
                    format!(
                        "channel {} kind {} requires http(s) endpoint",
                        channel.id, kind
                    ),
                ))
            }
            _ => Err(bilingual_runtime_error(
                "通知渠道类型不支持",
                format!("unsupported alert channel kind: {}", channel.kind),
            )),
        }
    }

    pub(crate) fn notification_event_matches(rule_event: &str, event_name: &str) -> bool {
        let rule_event = rule_event.trim();
        if rule_event.is_empty() {
            return false;
        }
        if rule_event.eq_ignore_ascii_case(event_name) {
            return true;
        }
        if let Some(prefix) = rule_event.strip_suffix('*') {
            return event_name.starts_with(prefix);
        }
        false
    }

    pub(crate) fn notification_key_matches(rule: &BucketNotificationRule, key: &str) -> bool {
        let prefix_matches = rule
            .prefix
            .as_deref()
            .map(|prefix| key.starts_with(prefix))
            .unwrap_or(true);
        let suffix_matches = rule
            .suffix
            .as_deref()
            .map(|suffix| key.ends_with(suffix))
            .unwrap_or(true);
        prefix_matches && suffix_matches
    }

    pub(crate) fn notification_target_channel_id(target: &str) -> Option<String> {
        target
            .strip_prefix("arn:rustio:alert-channel:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    pub(crate) fn notification_target_kind(target: &str) -> Option<String> {
        let normalized = target.trim();
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            return Some("webhook".to_string());
        }
        if normalized.starts_with("redis://") || normalized.starts_with("rediss://") {
            return Some("redis".to_string());
        }
        if normalized.starts_with("nats://") || normalized.starts_with("natss://") {
            return Some("nats".to_string());
        }
        if normalized.starts_with("smtp://")
            || normalized.starts_with("smtp+starttls://")
            || normalized.starts_with("smtps://")
            || normalized.contains('@')
        {
            return Some("email".to_string());
        }
        None
    }

    pub(crate) async fn enqueue_bucket_notification_deliveries(
        &self,
        bucket: &str,
        key: &str,
        event_name: &str,
        object_meta: Option<&S3ObjectMeta>,
        origin: &str,
    ) -> Result<usize, String> {
        let rules = self
            .bucket_notifications
            .read()
            .await
            .get(bucket)
            .cloned()
            .unwrap_or_default();
        if rules.is_empty() {
            return Ok(0);
        }

        let channels = self.alert_channels.read().await.clone();
        let now = Utc::now();
        let mut queue = self.alert_delivery_queue.write().await;
        let mut enqueued = 0usize;

        for rule in rules.into_iter().filter(|rule| {
            rule.enabled
                && Self::notification_event_matches(&rule.event, event_name)
                && Self::notification_key_matches(rule, key)
        }) {
            let target = rule.target.trim();
            if target.is_empty() {
                continue;
            }

            let resolved_channel = if let Some(channel) = channels
                .iter()
                .find(|channel| channel.id == target)
                .cloned()
            {
                channel
            } else if let Some(channel_id) = Self::notification_target_channel_id(target) {
                let Some(channel) = channels
                    .iter()
                    .find(|channel| channel.id == channel_id)
                    .cloned()
                else {
                    return Err(bilingual_runtime_error(
                        "桶通知目标渠道不存在",
                        format!("bucket notification target channel not found: {target}"),
                    ));
                };
                channel
            } else {
                let kind = Self::notification_target_kind(target).ok_or_else(|| {
                    bilingual_runtime_error(
                        "桶通知目标不支持",
                        format!("bucket notification target is unsupported: {target}"),
                    )
                })?;
                AlertChannel {
                    id: format!("bucket-notification-{}", sha256_hex(target.as_bytes())),
                    name: format!("bucket-notification:{bucket}:{}", rule.id),
                    kind,
                    endpoint: target.to_string(),
                    headers: HashMap::new(),
                    payload_template: None,
                    header_template: HashMap::new(),
                    enabled: true,
                    status: "unknown".to_string(),
                    last_checked_at: now,
                    error: None,
                }
            };

            let idempotency_key = format!(
                "bucket-notification:{}:{}:{}:{}:{}",
                bucket, key, event_name, rule.id, resolved_channel.id
            );
            if queue.iter().any(|item| {
                item.idempotency_key == idempotency_key
                    && matches!(item.status.as_str(), "pending" | "in_progress" | "done")
            }) {
                continue;
            }

            let payload = json!({
                "kind": "bucket-notification",
                "bucket": bucket,
                "key": key,
                "event": event_name,
                "origin": origin,
                "rule_id": rule.id,
                "rule_event": rule.event,
                "target": rule.target,
                "triggered_at": now,
                "object": object_meta.map(|meta| json!({
                    "version_id": meta.version_id,
                    "size": meta.size,
                    "etag": meta.etag,
                    "delete_marker": meta.delete_marker,
                    "created_at": meta.created_at,
                })),
            });

            queue.push(AlertDeliveryItem {
                id: format!("alert-delivery-{}", Uuid::new_v4().simple()),
                history_id: format!("bucket-notification-{}", Uuid::new_v4().simple()),
                rule_id: None,
                channel_id: resolved_channel.id,
                channel_kind: resolved_channel.kind,
                endpoint: resolved_channel.endpoint,
                status: "pending".to_string(),
                attempts: 0,
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now,
                last_attempt_at: None,
                next_attempt_at: now,
                payload,
                idempotency_key,
            });
            enqueued += 1;
        }

        Ok(enqueued)
    }

    pub async fn emit_bucket_object_event(
        &self,
        bucket: &str,
        key: &str,
        event_name: &str,
        object_meta: Option<&S3ObjectMeta>,
        origin: &str,
    ) -> Result<usize, String> {
        let enqueued = self
            .enqueue_bucket_notification_deliveries(bucket, key, event_name, object_meta, origin)
            .await?;
        self.push_event(
            "bucket.notification.enqueued",
            "bucket-notification-worker",
            json!({
                "bucket": bucket,
                "key": key,
                "event": event_name,
                "origin": origin,
                "enqueued": enqueued,
            }),
        )
        .await;
        Ok(enqueued)
    }

    pub(crate) async fn mark_alert_channel_delivery_result(
        &self,
        channel_id: &str,
        success: bool,
        last_error: Option<String>,
    ) {
        let mut channels = self.alert_channels.write().await;
        let Some(channel) = channels.iter_mut().find(|channel| channel.id == channel_id) else {
            return;
        };
        channel.last_checked_at = Utc::now();
        if !channel.enabled {
            channel.status = "paused".to_string();
            channel.error = Some(bilingual_runtime_error(
                "通知渠道已禁用",
                format!("alert channel {} is disabled", channel.id),
            ));
            return;
        }
        if success {
            channel.status = "healthy".to_string();
            channel.error = None;
        } else {
            channel.status = "degraded".to_string();
            channel.error = Some(last_error.unwrap_or_else(|| {
                bilingual_runtime_error("告警投递失败", "alert delivery failed")
            }));
        }
    }

    pub async fn enqueue_alert_deliveries(
        &self,
        entry: &AlertHistoryEntry,
    ) -> Result<usize, String> {
        if !matches!(entry.status.as_str(), "firing" | "resolved") {
            return Ok(0);
        }
        let Some(rule_id) = entry.rule_id.as_ref() else {
            return Ok(0);
        };
        let rules = self.alert_rules.read().await;
        let Some(rule) = rules.iter().find(|rule| rule.id == *rule_id).cloned() else {
            return Ok(0);
        };
        drop(rules);
        let escalations = self.alert_escalations.read().await.clone();
        let channels = self.alert_channels.read().await.clone();

        let mut channel_ids = Vec::<String>::new();
        for channel_id in &rule.channels {
            if !channel_ids.iter().any(|item| item == channel_id) {
                channel_ids.push(channel_id.clone());
            }
        }
        for escalation in escalations.iter().filter(|escalation| {
            escalation.enabled && escalation.severity.eq_ignore_ascii_case(&entry.severity)
        }) {
            for channel_id in &escalation.channels {
                if !channel_ids.iter().any(|item| item == channel_id) {
                    channel_ids.push(channel_id.clone());
                }
            }
        }
        if channel_ids.is_empty() {
            return Ok(0);
        }

        let now = Utc::now();
        let mut queue = self.alert_delivery_queue.write().await;
        let mut enqueued = 0usize;
        for channel_id in channel_ids {
            let Some(channel) = channels.iter().find(|channel| channel.id == channel_id) else {
                continue;
            };
            let idempotency_key = format!("{}:{}", entry.id, channel.id);
            if queue.iter().any(|item| {
                item.idempotency_key == idempotency_key
                    && matches!(item.status.as_str(), "pending" | "in_progress" | "done")
            }) {
                continue;
            }
            if let Some(existing) = queue
                .iter_mut()
                .find(|item| item.idempotency_key == idempotency_key)
            {
                existing.status = "pending".to_string();
                existing.attempts = 0;
                existing.last_error.clear();
                existing.lease_owner = None;
                existing.lease_until = None;
                existing.last_attempt_at = None;
                existing.next_attempt_at = now;
                existing.payload = json!({
                    "history_id": entry.id,
                    "rule_id": entry.rule_id,
                    "rule_name": entry.rule_name,
                    "severity": entry.severity,
                    "status": entry.status,
                    "message": entry.message,
                    "triggered_at": entry.triggered_at,
                    "details": entry.details,
                    "channel_id": channel.id,
                    "channel_kind": channel.kind,
                });
                enqueued += 1;
                continue;
            }
            queue.push(AlertDeliveryItem {
                id: format!("alert-delivery-{}", Uuid::new_v4().simple()),
                history_id: entry.id.clone(),
                rule_id: entry.rule_id.clone(),
                channel_id: channel.id.clone(),
                channel_kind: channel.kind.clone(),
                endpoint: channel.endpoint.clone(),
                status: "pending".to_string(),
                attempts: 0,
                last_error: String::new(),
                lease_owner: None,
                lease_until: None,
                queued_at: now,
                last_attempt_at: None,
                next_attempt_at: now,
                payload: json!({
                    "history_id": entry.id,
                    "rule_id": entry.rule_id,
                    "rule_name": entry.rule_name,
                    "severity": entry.severity,
                    "status": entry.status,
                    "message": entry.message,
                    "triggered_at": entry.triggered_at,
                    "details": entry.details,
                    "channel_id": channel.id,
                    "channel_kind": channel.kind,
                }),
                idempotency_key,
            });
            enqueued += 1;
        }
        Ok(enqueued)
    }

    pub(crate) async fn process_alert_delivery_item(
        &self,
        item: &AlertDeliveryItem,
    ) -> Result<(), String> {
        let channels = self.alert_channels.read().await;
        let channel = channels
            .iter()
            .find(|channel| channel.id == item.channel_id)
            .cloned()
            .ok_or_else(|| {
                bilingual_runtime_error(
                    "通知渠道不存在",
                    format!("alert channel {} not found", item.channel_id),
                )
            })?;
        drop(channels);
        self.dispatch_alert_channel_message(&channel, &item.payload)
            .await
    }

    pub(crate) async fn process_alert_delivery_queue_once(&self, worker_id: &str) -> usize {
        let now = Utc::now();
        let lease_until = now
            + Duration::from_std(Self::alert_delivery_lease_interval())
                .unwrap_or_else(|_| Duration::seconds(1));
        let picked_item = {
            let mut queue = self.alert_delivery_queue.write().await;
            let mut picked_index = None::<usize>;
            let mut picked_time = None::<DateTime<Utc>>;
            for (index, item) in queue.iter().enumerate() {
                let lease_expired = item.lease_until.map(|value| value <= now).unwrap_or(true);
                let ready = matches!(item.status.as_str(), "pending" | "failed")
                    || (item.status == "in_progress" && lease_expired);
                if !ready {
                    continue;
                }
                if item.next_attempt_at > now {
                    continue;
                }
                if picked_time
                    .map(|value| item.next_attempt_at < value)
                    .unwrap_or(true)
                {
                    picked_index = Some(index);
                    picked_time = Some(item.next_attempt_at);
                }
            }
            let Some(index) = picked_index else {
                return 0;
            };
            let Some(entry) = queue.get_mut(index) else {
                return 0;
            };
            entry.status = "in_progress".to_string();
            entry.attempts += 1;
            entry.last_attempt_at = Some(now);
            entry.lease_owner = Some(worker_id.to_string());
            entry.lease_until = Some(lease_until);
            entry.clone()
        };

        let result = self.process_alert_delivery_item(&picked_item).await;
        let max_attempts = Self::alert_delivery_max_attempts();
        let mut channel_success = false;
        let mut channel_error = None::<String>;
        {
            let mut queue = self.alert_delivery_queue.write().await;
            if let Some(entry) = queue.iter_mut().find(|entry| entry.id == picked_item.id) {
                match result {
                    Ok(_) => {
                        entry.status = "done".to_string();
                        entry.last_error.clear();
                        entry.lease_owner = None;
                        entry.lease_until = None;
                        entry.next_attempt_at = now;
                        channel_success = true;
                    }
                    Err(err) => {
                        let error = bilingual_runtime_error(
                            "告警投递失败",
                            format!(
                                "alert delivery to channel {} failed: {err}",
                                entry.channel_id
                            ),
                        );
                        channel_error = Some(error.clone());
                        if entry.attempts >= max_attempts {
                            entry.status = "dead_letter".to_string();
                            entry.lease_owner = None;
                            entry.lease_until = None;
                            entry.last_error = bilingual_runtime_error(
                                "告警投递达到最大重试次数，进入死信队列",
                                format!(
                                    "alert delivery reached max attempts {} and moved to dead-letter: {}",
                                    max_attempts, error
                                ),
                            );
                        } else {
                            entry.status = "failed".to_string();
                            entry.lease_owner = None;
                            entry.lease_until = None;
                            entry.last_error = error.clone();
                            let retry_delay = Self::alert_delivery_retry_delay(entry.attempts);
                            entry.next_attempt_at = now
                                + Duration::from_std(retry_delay)
                                    .unwrap_or_else(|_| Duration::seconds(1));
                        }
                    }
                }
            } else {
                return 0;
            }
        }
        self.mark_alert_channel_delivery_result(
            &picked_item.channel_id,
            channel_success,
            channel_error,
        )
        .await;
        1
    }
}
