export type ApiEnvelope<T> = {
  data: T;
  request_id: string;
};

export type LoginResponse = {
  access_token: string;
  refresh_token: string;
  session_id: string;
  role: string;
  permissions: string[];
  expires_at: string;
  refresh_expires_at: string;
};

export type AuthProviderInfo = {
  id: string;
  enabled: boolean;
  configured: boolean;
  supports_username_password: boolean;
  supports_browser_redirect: boolean;
  supports_id_token: boolean;
  authorize_url?: string | null;
  missing_requirements: string[];
};

export type ClusterHealth = {
  status: string;
  nodes_online: number;
  nodes_total: number;
  timestamp: string;
};

export type SystemMetricsSummary = {
  generated_at: string;
  cluster_status: string;
  tenants_total: number;
  nodes: SystemNodeMetricsSummary;
  storage: SystemStorageMetricsSummary;
  raft: SystemRaftMetricsSummary;
  replication: SystemReplicationMetricsSummary;
  alerts: SystemAlertMetricsSummary;
  iam: SystemIamMetricsSummary;
  audit: SystemAuditMetricsSummary;
  kms: SystemKmsMetricsSummary;
  security: SystemSecurityMetricsSummary;
  jobs: SystemJobMetricsSummary;
  sessions: SystemSessionMetricsSummary;
};

export type SystemNodeMetricsSummary = {
  total: number;
  online: number;
  offline: number;
  zones_total: number;
};

export type SystemStorageMetricsSummary = {
  capacity_total_bytes: number;
  capacity_used_bytes: number;
  capacity_free_bytes: number;
  utilization_ratio: number;
  disks_total: number;
  disks_online: number;
  disks_degraded: number;
  ec_data_shards: number;
  ec_parity_shards: number;
  shard_files_total: number;
  shard_bytes_total: number;
  shard_healthy_total: number;
  shard_missing_total: number;
  shard_corrupted_total: number;
  governance: SystemStorageGovernanceMetricsSummary;
  disks: SystemStorageDiskMetricsSummary[];
};

export type SystemStorageGovernanceMetricsSummary = {
  last_scan_at?: string | null;
  last_heal_at?: string | null;
  pending_objects: number;
  running_objects: number;
  failed_objects: number;
  retrying_objects: number;
  last_scan_result: string;
  last_heal_duration_seconds: number;
  scan_runs_total: number;
  scan_failures_total: number;
  heal_objects_total: number;
  heal_failures_total: number;
  object_lock_buckets: number;
  retention_buckets: number;
  legal_hold_buckets: number;
  retained_objects: number;
  legal_hold_objects: number;
};

export type SystemStorageDiskMetricsSummary = {
  disk_id: string;
  path: string;
  online: boolean;
  status: string;
  manifests_total: number;
  shard_files: number;
  shard_bytes: number;
  shard_healthy: number;
  shard_missing: number;
  shard_corrupted: number;
  heal_pressure: number;
  last_anomaly_at?: string | null;
};

export type SystemRaftMetricsSummary = {
  cluster_id: string;
  leader_id: string;
  leader_present: boolean;
  term: number;
  commit_index: number;
  quorum: number;
  online_peers: number;
  quorum_available: boolean;
  membership_phase: string;
  last_error?: string | null;
};

export type SystemReplicationMetricsSummary = {
  rules_total: number;
  sites_total: number;
  sites_healthy: number;
  checkpoints_total: number;
  max_lag_seconds: number;
  backlog_total: number;
  backlog_pending: number;
  backlog_in_progress: number;
  backlog_failed: number;
  backlog_dead_letter: number;
  backlog_done: number;
  backlog_retryable: number;
  backlog_sla_firing_sites: number;
  sites: SystemReplicationSiteMetricsSummary[];
};

export type SystemReplicationSiteMetricsSummary = {
  site_id: string;
  endpoint?: string | null;
  state: string;
  lag_seconds: number;
  backlog_total: number;
  backlog_pending: number;
  backlog_failed: number;
  backlog_dead_letter: number;
  backlog_sla_status: string;
  firing_alerts: number;
};

export type SystemAlertMetricsSummary = {
  rules_total: number;
  channels_total: number;
  channels_enabled: number;
  channels_healthy: number;
  firing_alerts: number;
  history_total: number;
  delivery_queued: number;
  delivery_in_progress: number;
  delivery_failed: number;
  delivery_done: number;
  last_delivery_error?: string | null;
};

export type SystemIamMetricsSummary = {
  users_total: number;
  users_enabled: number;
  groups_total: number;
  policies_total: number;
  service_accounts_total: number;
  service_accounts_enabled: number;
};

export type SystemAuditMetricsSummary = {
  events_total: number;
  auth_events_total: number;
  iam_events_total: number;
  kms_events_total: number;
  alert_events_total: number;
  replication_events_total: number;
  job_events_total: number;
  failed_outcomes_total: number;
  latest_event_at?: string | null;
};

export type SystemKmsMetricsSummary = {
  endpoint_configured: boolean;
  healthy: boolean;
  last_error?: string | null;
  last_checked_at?: string | null;
  last_success_at?: string | null;
  rotation_status: string;
  rotation_last_started_at?: string | null;
  rotation_last_completed_at?: string | null;
  rotation_last_success_at?: string | null;
  rotation_last_failure_reason?: string | null;
  rotation_scanned: number;
  rotation_rotated: number;
  rotation_skipped: number;
  rotation_failed: number;
  retry_recommended: boolean;
};

export type SystemSecurityMetricsSummary = {
  oidc_enabled: boolean;
  ldap_enabled: boolean;
  kms_endpoint_configured: boolean;
  kms_healthy: boolean;
  sse_mode: string;
};

export type SystemJobMetricsSummary = {
  total: number;
  running: number;
  pending: number;
  completed: number;
  failed: number;
  cancelled: number;
  idle: number;
  other: number;
  retrying: number;
  scan: number;
  scrub: number;
  heal: number;
  rebuild: number;
  async_total: number;
  async_pending: number;
  async_in_progress: number;
  async_completed: number;
  async_failed: number;
  async_dead_letter: number;
  async_retryable: number;
  kinds: SystemJobKindMetricsSummary[];
};

export type SystemJobKindMetricsSummary = {
  kind: string;
  total: number;
  pending: number;
  in_progress: number;
  completed: number;
  failed: number;
  dead_letter: number;
  retryable: number;
};

export type SystemSessionMetricsSummary = {
  service_accounts_total: number;
  service_accounts_enabled: number;
  admin_sessions_total: number;
  admin_sessions_active: number;
  admin_sessions_expiring_24h: number;
  sts_sessions_total: number;
  sts_sessions_active: number;
  sts_sessions_expiring_24h: number;
};

export type ClusterNode = {
  id: string;
  hostname: string;
  zone: string;
  online: boolean;
  capacity_total_bytes: number;
  capacity_used_bytes: number;
  last_heartbeat: string;
};

export type ClusterQuota = {
  tenant: string;
  hard_limit_bytes: number;
  used_bytes: number;
};

export type TenantSpec = {
  id: string;
  display_name: string;
  owner_group: string;
  enabled: boolean;
  status: string;
  hard_limit_bytes: number;
  used_bytes: number;
  created_at: string;
  updated_at: string;
  labels: Record<string, string>;
};

export type IamUser = {
  username: string;
  display_name: string;
  role: string;
  enabled: boolean;
  created_at: string;
};

export type IamGroup = {
  name: string;
  members: string[];
};

export type IamPolicy = {
  name: string;
  document: Record<string, unknown>;
  attached_to: string[];
};

export type ServiceAccount = {
  access_key: string;
  secret_key?: string;
  owner: string;
  created_at: string;
  status: string;
};

export type StsSession = {
  session_id: string;
  principal: string;
  access_key?: string;
  secret_key?: string;
  session_token?: string;
  provider?: string;
  role_arn?: string | null;
  session_name?: string | null;
  session_policy?: Record<string, unknown> | null;
  subject?: string | null;
  audience?: string | null;
  status?: string;
  issued_at: string;
  expires_at: string;
};

export type ConsoleSession = {
  session_id: string;
  principal: string;
  role: string;
  permissions: string[];
  provider: string;
  status: string;
  issued_at: string;
  access_expires_at: string;
  refresh_expires_at: string;
  last_refreshed_at?: string | null;
  revoked_at?: string | null;
  revoked_reason?: string | null;
};

export type DiagnosticReport = {
  id: string;
  created_at: string;
  generated_by: string;
  summary: string;
};

export type ClusterConfigSnapshot = {
  version: string;
  updated_at: string;
  updated_by: string;
  source: string;
  reason?: string | null;
  etag: string;
  payload: Record<string, unknown>;
};

export type ClusterConfigValidationResult = {
  valid: boolean;
  errors: string[];
  warnings: string[];
};

export type BucketSpec = {
  name: string;
  tenant_id: string;
  versioning: boolean;
  object_lock: boolean;
  ilm_policy?: string;
  replication_policy?: string;
};

export type BucketObjectLockConfig = {
  enabled: boolean;
  mode: string;
  default_retention_days: number;
};

export type BucketRetentionConfig = {
  enabled: boolean;
  mode: string;
  duration_days: number;
};

export type BucketLegalHoldConfig = {
  enabled: boolean;
};

export type BucketNotificationRule = {
  id: string;
  event: string;
  target: string;
  prefix?: string;
  suffix?: string;
  enabled: boolean;
};

export type BucketLifecycleRule = {
  id: string;
  prefix?: string;
  status: string;
  expiration_days?: number;
  noncurrent_expiration_days?: number;
  transition_days?: number;
  transition_tier?: string;
  noncurrent_transition_days?: number;
  noncurrent_transition_tier?: string;
};

export type BucketAclConfig = {
  acl: string;
};

export type BucketPublicAccessBlockConfig = {
  block_public_acls: boolean;
  ignore_public_acls: boolean;
  block_public_policy: boolean;
  restrict_public_buckets: boolean;
};

export type BucketCorsRule = {
  id: string;
  allowed_origins: string[];
  allowed_methods: string[];
  allowed_headers: string[];
  expose_headers: string[];
  max_age_seconds?: number;
};

export type BucketTag = {
  key: string;
  value: string;
};

export type BucketEncryptionConfig = {
  enabled: boolean;
  algorithm: string;
  kms_key_id?: string;
};

export type BucketObjectEntry = {
  key: string;
  size: number;
  etag: string;
  last_modified: string;
  version_id?: string;
  retention_until?: string;
  legal_hold?: boolean;
};

export type BucketObjectVersionEntry = {
  key: string;
  version_id: string;
  size: number;
  etag: string;
  last_modified: string;
  delete_marker: boolean;
  legal_hold: boolean;
  retention_until?: string;
  is_latest: boolean;
};

export type ReplicationStatus = {
  rule_id: string;
  source_bucket: string;
  target_site: string;
  rule_name?: string | null;
  endpoint?: string | null;
  prefix?: string | null;
  priority: number;
  replicate_existing: boolean;
  sync_deletes: boolean;
  lag_seconds: number;
  status: string;
};

export type SiteReplicationStatus = {
  site_id: string;
  endpoint: string;
  role: string;
  preferred_primary: boolean;
  state: string;
  lag_seconds: number;
  managed_buckets: number;
  last_sync_at: string;
  last_error?: string | null;
};

export type ReplicationBacklogItem = {
  id: string;
  source_bucket: string;
  target_site: string;
  object_key: string;
  rule_id?: string | null;
  priority?: number;
  operation?: string;
  checkpoint?: number;
  idempotency_key?: string;
  version_id?: string | null;
  attempts: number;
  status: string;
  last_error: string;
  lease_owner?: string | null;
  lease_until?: string | null;
  queued_at: string;
  last_attempt_at: string;
};

export type SecurityConfig = {
  oidc_enabled: boolean;
  ldap_enabled: boolean;
  oidc_discovery_url: string;
  oidc_issuer: string;
  oidc_client_id: string;
  oidc_jwks_url: string;
  oidc_allowed_algs: string;
  oidc_username_claim: string;
  oidc_groups_claim: string;
  oidc_role_claim: string;
  oidc_default_role: string;
  oidc_group_role_map: string;
  ldap_url: string;
  ldap_bind_dn: string;
  ldap_user_base_dn: string;
  ldap_user_filter: string;
  ldap_group_base_dn: string;
  ldap_group_filter: string;
  ldap_group_attribute: string;
  ldap_group_name_attribute: string;
  ldap_default_role: string;
  ldap_group_role_map: string;
  kms_endpoint: string;
  kms_healthy: boolean;
  kms_last_error?: string | null;
  kms_last_checked_at?: string | null;
  kms_last_success_at?: string | null;
  kms_rotation_status: string;
  kms_rotation_last_started_at?: string | null;
  kms_rotation_last_completed_at?: string | null;
  kms_rotation_last_success_at?: string | null;
  kms_rotation_last_failure_reason?: string | null;
  kms_rotation_scanned: number;
  kms_rotation_rotated: number;
  kms_rotation_skipped: number;
  kms_rotation_failed: number;
  kms_rotation_failed_objects: string[];
  sse_mode: string;
};

export type KmsRotationResult = {
  status: string;
  scanned: number;
  rotated: number;
  skipped: number;
  failed: number;
  failed_objects: string[];
  failure_reason?: string | null;
  retry_recommended: boolean;
  started_at: string;
  completed_at: string;
};

export type AlertRule = {
  id: string;
  name: string;
  metric: string;
  condition: string;
  threshold: number;
  window_minutes: number;
  severity: string;
  enabled: boolean;
  channels: string[];
  last_triggered_at?: string | null;
};

export type AlertChannel = {
  id: string;
  name: string;
  kind: string;
  endpoint: string;
  enabled: boolean;
  status: string;
  last_checked_at: string;
  error?: string | null;
};

export type AlertSilence = {
  id: string;
  name: string;
  rule_ids: string[];
  starts_at: string;
  ends_at: string;
  reason: string;
  created_by: string;
  enabled: boolean;
};

export type AlertEscalationPolicy = {
  id: string;
  name: string;
  severity: string;
  wait_minutes: number;
  channels: string[];
  enabled: boolean;
};

export type AlertHistoryEntry = {
  id: string;
  rule_id?: string | null;
  rule_name?: string | null;
  severity: string;
  status: string;
  message: string;
  triggered_at: string;
  source: string;
  assignee?: string | null;
  claimed_at?: string | null;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  resolved_by?: string | null;
  resolved_at?: string | null;
  details: Record<string, unknown>;
};

export type AuditEvent = {
  id: string;
  actor: string;
  action: string;
  resource: string;
  outcome: string;
  reason?: string;
  timestamp: string;
  details: Record<string, unknown>;
};

export type JobStatus = {
  id: string;
  kind: string;
  status: string;
  priority: number;
  bucket?: string | null;
  object_key?: string | null;
  site_id?: string | null;
  idempotency_key: string;
  attempt: number;
  lease_owner?: string | null;
  lease_until?: string | null;
  checkpoint?: number | null;
  last_error?: string | null;
  payload?: Record<string, unknown> | null;
  progress: number;
  created_at: string;
  updated_at: string;
  key?: string | null;
  version_id?: string | null;
  target?: string | null;
  affected_disks: string[];
  missing_shards: number;
  corrupted_shards: number;
  started_at?: string | null;
  finished_at?: string | null;
  attempts: number;
  max_attempts: number;
  next_attempt_at?: string | null;
  error?: string | null;
  dedupe_key?: string | null;
  source?: string | null;
  details?: Record<string, unknown> | null;
};

export type AsyncJobStatus = {
  job_id: string;
  kind: string;
  status: string;
  priority: number;
  bucket?: string | null;
  object_key?: string | null;
  site_id?: string | null;
  idempotency_key: string;
  attempt: number;
  lease_owner?: string | null;
  lease_until?: string | null;
  checkpoint?: number | null;
  last_error?: string | null;
  progress: number;
  retryable: boolean;
  terminal: boolean;
  created_at: string;
  updated_at: string;
};

export type AsyncJobKindSummary = {
  kind: string;
  total: number;
  pending: number;
  in_progress: number;
  completed: number;
  failed: number;
  dead_letter: number;
  retryable: number;
};

export type AsyncJobSummary = {
  generated_at: string;
  total: number;
  pending: number;
  in_progress: number;
  completed: number;
  failed: number;
  dead_letter: number;
  retryable: number;
  kinds: AsyncJobKindSummary[];
};

export type AsyncJobPage = {
  items: AsyncJobStatus[];
  next_cursor?: string | null;
};

export type AsyncJobBulkOperationResult = {
  matched: number;
  updated: number;
  removed: number;
  skipped: number;
  remaining: number;
};

export type RuntimeEvent = {
  topic: string;
  source: string;
  timestamp: string;
  payload: Record<string, unknown>;
};
