import { ApiClient } from './client';
import type {
  AsyncJobBulkOperationResult,
  AsyncJobPage,
  AsyncJobStatus,
  AsyncJobSummary,
  AuthProviderInfo,
  BucketAclConfig,
  AlertChannel,
  AlertEscalationPolicy,
  AlertHistoryEntry,
  AlertRule,
  AlertSilence,
  AuditEvent,
  BucketCorsRule,
  BucketEncryptionConfig,
  BucketLegalHoldConfig,
  BucketLifecycleRule,
  BucketNotificationRule,
  BucketObjectEntry,
  BucketObjectVersionEntry,
  BucketObjectLockConfig,
  BucketRetentionConfig,
  BucketSpec,
  CreateBucketPayload,
  BucketGovernanceUpdate,
  BucketPublicAccessBlockConfig,
  BucketTag,
  BucketUsageStats,
  ClusterHealth,
  ClusterNode,
  ClusterPeerInfo,
  ClusterGroup,
  AddClusterMemberRequest,
  RemoveClusterMemberRequest,
  DecommissionRequest,
  ClusterBackupRestoreResult,
  SystemInfo,
  SystemCapabilities,
  SystemStorageDiskMetricsSummary,
  ArchitectureTopology,
  ArchitectureAlignmentReport,
  SystemMetricsSummary,
  ClusterConfigSnapshot,
  ClusterConfigValidationResult,
  ClusterQuota,
  ConsoleSession,
  TenantSpec,
  DiagnosticReport,
  IamGroup,
  IamPolicy,
  IamUser,
  JobStatus,
  BatchRunStatus,
  BatchRunRequest,
  KmsRotationResult,
  LoginResponse,
  ReplicationBacklogItem,
  ReplicationBacklogPage,
  ReplicationBacklogMetrics,
  ReplicationBacklogBatchResult,
  ReplicationBacklogQuery,
  ReplicationStatus,
  SiteReplicationStatus,
  SiteReplicationDriftReport,
  SiteReplicationBootstrapRequest,
  SiteReplicationJoinRequest,
  ServiceAccount,
  StsSession,
  SecurityConfig,
  SystemKmsMetricsSummary,
  MetadataRaftStatus,
  MetadataRaftAddPeerRequest,
  MetadataRaftRemovePeerRequest,
  RemoteTierConfig,
  RotateRemoteTierSecretRequest,
  StorageInventoryQuery,
  StorageInventoryEntry,
  StorageArchiveReport,
  StorageArchivePrewarmRequest,
  StorageArchivePrewarmResult,
  StorageGovernanceStatusResponse,
  StorageMaintenanceRequest,
  ClusterRebalanceRequest,
  IdentityDomainView
} from '../types';

const encodeObjectKey = (key: string) => key.split('/').map(encodeURIComponent).join('/');
const appendVersionQuery = (versionId?: string) =>
  versionId ? `?version_id=${encodeURIComponent(versionId)}` : '';

export const authService = {
  providers: (client: ApiClient) => client.get<AuthProviderInfo[]>('/api/v1/auth/providers'),
  login: (
    client: ApiClient,
    payload: {
      username: string;
      password: string;
      provider?: string;
      id_token?: string;
    }
  ) => client.post<LoginResponse>('/api/v1/auth/login', payload),
  refresh: (client: ApiClient, refreshToken: string) =>
    client.post<LoginResponse>('/api/v1/auth/refresh', { refresh_token: refreshToken }),
  logout: (client: ApiClient) =>
    client.post<{ logged_out: boolean; session_id: string }>('/api/v1/auth/logout'),
  changePassword: (
    client: ApiClient,
    payload: { current_password: string; new_password: string }
  ) => client.post<{ changed: boolean }>('/api/v1/auth/password', payload),
  currentSession: (client: ApiClient) =>
    client.get<ConsoleSession>('/api/v1/auth/session/current'),
  redeemOidcSession: (client: ApiClient, requestId: string) =>
    client.get<LoginResponse>(`/api/v1/auth/oidc/session/${encodeURIComponent(requestId)}`)
};

export const clusterService = {
  health: (client: ApiClient) => client.get<ClusterHealth>('/api/v1/cluster/health'),
  nodes: (client: ApiClient) => client.get<ClusterNode[]>('/api/v1/cluster/nodes'),
  quotas: (client: ApiClient) => client.get<ClusterQuota[]>('/api/v1/cluster/quotas'),
  tenants: (client: ApiClient) => client.get<TenantSpec[]>('/api/v1/cluster/tenants'),
  createTenant: (
    client: ApiClient,
    payload: {
      id: string;
      display_name: string;
      owner_group: string;
      hard_limit_bytes: number;
      labels?: Record<string, string>;
    }
  ) => client.post<TenantSpec>('/api/v1/cluster/tenants', payload),
  updateTenant: (
    client: ApiClient,
    id: string,
    payload: {
      display_name?: string;
      owner_group?: string;
      hard_limit_bytes?: number;
      labels?: Record<string, string>;
    }
  ) => client.put<TenantSpec>(`/api/v1/cluster/tenants/${encodeURIComponent(id)}`, payload),
  suspendTenant: (client: ApiClient, id: string, reason: string) =>
    client.post<TenantSpec>(`/api/v1/cluster/tenants/${encodeURIComponent(id)}/suspend`, { reason }, true),
  resumeTenant: (client: ApiClient, id: string, reason: string) =>
    client.post<TenantSpec>(`/api/v1/cluster/tenants/${encodeURIComponent(id)}/resume`, { reason }, true),
  deleteTenant: (client: ApiClient, id: string, reason: string) =>
    client.post<{ deleted: boolean; id: string }>(
      `/api/v1/cluster/tenants/${encodeURIComponent(id)}/delete`,
      { reason },
      true
    ),
  setNodeOffline: (client: ApiClient, id: string, reason: string) =>
    client.post(`/api/v1/cluster/nodes/${id}/offline`, { reason }, true),
  setNodeOnline: (client: ApiClient, id: string, reason: string) =>
    client.post(`/api/v1/cluster/nodes/${id}/online`, { reason }, true),

  // 新增:拓扑与分组
  peers: (client: ApiClient) => client.get<ClusterPeerInfo[]>('/api/v1/cluster/peers'),
  groups: (client: ApiClient) => client.get<ClusterGroup[]>('/api/v1/cluster/groups'),
  addMember: (client: ApiClient, payload: AddClusterMemberRequest) =>
    client.post<ClusterPeerInfo[]>('/api/v1/cluster/membership/add', payload, true),
  removeMember: (client: ApiClient, payload: RemoveClusterMemberRequest) =>
    client.post<ClusterPeerInfo[]>('/api/v1/cluster/membership/remove', payload, true),
  decommissionNode: (client: ApiClient, payload: DecommissionRequest) =>
    client.post<Record<string, unknown>>('/api/v1/cluster/membership/decommission', payload, true),

  // 诊断(扩展)
  diagnostics: (client: ApiClient) => client.get<DiagnosticReport[]>('/api/v1/cluster/diagnostics'),
  createDiagnostic: (client: ApiClient, query?: {
    redact_sensitive?: boolean;
    audit_limit?: number;
    job_limit?: number;
    backlog_limit?: number;
    kind?: string;
    incident_id?: string;
    severity?: string;
    incident_summary?: string;
  }) => {
    const params = new URLSearchParams();
    if (query) {
      if (typeof query.redact_sensitive === 'boolean') params.set('redact_sensitive', String(query.redact_sensitive));
      if (query.audit_limit) params.set('audit_limit', String(query.audit_limit));
      if (query.job_limit) params.set('job_limit', String(query.job_limit));
      if (query.backlog_limit) params.set('backlog_limit', String(query.backlog_limit));
      if (query.kind) params.set('kind', query.kind);
      if (query.incident_id) params.set('incident_id', query.incident_id);
      if (query.severity) params.set('severity', query.severity);
      if (query.incident_summary) params.set('incident_summary', query.incident_summary);
    }
    const qs = params.toString();
    return client.post<DiagnosticReport>(`/api/v1/cluster/diagnostics${qs ? `?${qs}` : ''}`);
  },
  getDiagnostic: (client: ApiClient, id: string) =>
    client.get<Record<string, unknown>>(`/api/v1/cluster/diagnostics/${encodeURIComponent(id)}`),
  downloadDiagnostic: (client: ApiClient, id: string) =>
    client.getBlob(`/api/v1/cluster/diagnostics/${encodeURIComponent(id)}/download`),

  // 备份/恢复(裸文件流)
  exportBackup: (client: ApiClient) => client.getBlob('/api/v1/cluster/backup/export'),
  restoreBackup: (client: ApiClient, payload: {
    reason: string;
    backup: Record<string, unknown>;
    rewrite_cluster_id?: boolean;
    rewrite_peer_id?: boolean;
  }) => client.post<ClusterBackupRestoreResult>('/api/v1/cluster/backup/restore', payload, true),

  // 配置
  configCurrent: (client: ApiClient) =>
    client.get<ClusterConfigSnapshot>('/api/v1/cluster/config/current'),
  configHistory: (client: ApiClient, limit = 20) =>
    client.get<ClusterConfigSnapshot[]>(`/api/v1/cluster/config/history?limit=${limit}`),
  validateConfig: (client: ApiClient, payload: Record<string, unknown>) =>
    client.post<ClusterConfigValidationResult>('/api/v1/cluster/config/validate', { payload }),
  applyConfig: (client: ApiClient, payload: Record<string, unknown>, reason: string) =>
    client.post<ClusterConfigSnapshot>('/api/v1/cluster/config/apply', { payload, reason }, true),
  rollbackConfig: (client: ApiClient, version: string, reason: string) =>
    client.post<ClusterConfigSnapshot>(
      '/api/v1/cluster/config/rollback',
      { version, reason },
      true
    ),
  exportConfig: (client: ApiClient) => client.getText('/api/v1/cluster/config/export')
};

export const systemService = {
  info: (client: ApiClient) => client.get<SystemInfo>('/api/v1/system/info'),
  capabilities: (client: ApiClient) => client.get<SystemCapabilities>('/api/v1/system/capabilities'),
  topology: (client: ApiClient) => client.get<ArchitectureTopology>('/api/v1/system/topology'),
  alignment: (client: ApiClient) => client.get<ArchitectureAlignmentReport>('/api/v1/system/alignment'),
  metricsSummary: (client: ApiClient) =>
    client.get<SystemMetricsSummary>('/api/v1/system/metrics/summary'),
  storageDisks: (client: ApiClient) =>
    client.get<SystemStorageDiskMetricsSummary[]>('/api/v1/system/storage/disks'),
  prometheusMetrics: (client: ApiClient) => client.getText('/metrics'),

  // Raft 管理
  raftStatus: (client: ApiClient) => client.get<MetadataRaftStatus>('/api/v1/system/raft/status'),
  raftReadIndex: (client: ApiClient) => client.get<Record<string, unknown>>('/api/v1/system/raft/read-index'),
  raftAddPeer: (client: ApiClient, payload: MetadataRaftAddPeerRequest) =>
    client.post<MetadataRaftStatus>('/api/v1/system/raft/peers', payload, true),
  raftElect: (client: ApiClient, id: string, reason: string) =>
    client.post<MetadataRaftStatus>(`/api/v1/system/raft/elect/${encodeURIComponent(id)}`, { reason }, true),
  raftTransfer: (client: ApiClient, id: string, reason: string) =>
    client.post<MetadataRaftStatus>(`/api/v1/system/raft/transfer/${encodeURIComponent(id)}`, { reason }, true),
  raftPeerOffline: (client: ApiClient, id: string, reason: string) =>
    client.post<MetadataRaftStatus>(`/api/v1/system/raft/peers/${encodeURIComponent(id)}/offline`, { reason }, true),
  raftPeerOnline: (client: ApiClient, id: string, reason: string) =>
    client.post<MetadataRaftStatus>(`/api/v1/system/raft/peers/${encodeURIComponent(id)}/online`, { reason }, true),
  raftRemovePeer: (client: ApiClient, id: string, payload: MetadataRaftRemovePeerRequest) =>
    client.post<MetadataRaftStatus>(`/api/v1/system/raft/peers/${encodeURIComponent(id)}/remove`, payload, true),
  raftMembershipAbort: (client: ApiClient, reason: string) =>
    client.post<MetadataRaftStatus>('/api/v1/system/raft/peers/membership/abort', { reason }, true),
  raftMembershipFinalize: (client: ApiClient, reason: string) =>
    client.post<MetadataRaftStatus>('/api/v1/system/raft/peers/membership/finalize', { reason }, true)
};

export const identityService = {
  domains: (client: ApiClient) => client.get<IdentityDomainView[]>('/api/v1/identity/domains')
};

export const iamService = {
  users: (client: ApiClient) => client.get<IamUser[]>('/api/v1/iam/users'),
  groups: (client: ApiClient) => client.get<IamGroup[]>('/api/v1/iam/groups'),
  policies: (client: ApiClient) => client.get<IamPolicy[]>('/api/v1/iam/policies'),
  serviceAccounts: (client: ApiClient) =>
    client.get<ServiceAccount[]>('/api/v1/iam/service-accounts'),
  stsSessions: (client: ApiClient) => client.get<StsSession[]>('/api/v1/iam/sts/sessions'),
  consoleSessions: (client: ApiClient) => client.get<ConsoleSession[]>('/api/v1/auth/sessions'),
  createUser: (
    client: ApiClient,
    payload: { username: string; password: string; display_name: string; role: string }
  ) => client.post<IamUser>('/api/v1/iam/users', payload),
  enableUser: (client: ApiClient, username: string) =>
    client.post<IamUser>(`/api/v1/iam/users/${encodeURIComponent(username)}/enable`),
  disableUser: (client: ApiClient, username: string) =>
    client.post<IamUser>(`/api/v1/iam/users/${encodeURIComponent(username)}/disable`),
  resetUserPassword: (
    client: ApiClient,
    username: string,
    payload: { new_password: string }
  ) =>
    client.post<{ reset: boolean; username: string; revoked_console_sessions: number }>(
      `/api/v1/iam/users/${encodeURIComponent(username)}/password`,
      payload
    ),
  deleteUser: (client: ApiClient, username: string) =>
    client.delete<{
      deleted: boolean;
      username: string;
      cascaded_groups: number;
      cascaded_policies: number;
      cascaded_service_accounts: number;
      cascaded_sts_sessions: number;
      cascaded_console_sessions: number;
    }>(`/api/v1/iam/users/${encodeURIComponent(username)}`),
  createGroup: (client: ApiClient, payload: { name: string }) =>
    client.post<IamGroup>('/api/v1/iam/groups', payload),
  addGroupMember: (client: ApiClient, group: string, payload: { username: string }) =>
    client.post<IamGroup>(`/api/v1/iam/groups/${encodeURIComponent(group)}/members`, payload),
  removeGroupMember: (client: ApiClient, group: string, username: string) =>
    client.delete<IamGroup>(
      `/api/v1/iam/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(username)}`
    ),
  createPolicy: (client: ApiClient, payload: { name: string; document: Record<string, unknown> }) =>
    client.post<IamPolicy>('/api/v1/iam/policies', payload),
  attachPolicy: (client: ApiClient, name: string, payload: { principal: string }) =>
    client.post<IamPolicy>(`/api/v1/iam/policies/${encodeURIComponent(name)}/attach`, payload),
  detachPolicy: (client: ApiClient, name: string, payload: { principal: string }) =>
    client.post<IamPolicy>(`/api/v1/iam/policies/${encodeURIComponent(name)}/detach`, payload),
  createServiceAccount: (client: ApiClient, payload: { owner: string }) =>
    client.post<ServiceAccount>('/api/v1/iam/service-accounts', payload),
  deleteServiceAccount: (client: ApiClient, accessKey: string) =>
    client.delete<{ deleted: boolean; access_key: string }>(
      `/api/v1/iam/service-accounts/${encodeURIComponent(accessKey)}`
    ),
  createStsSession: (client: ApiClient, payload: { principal: string; ttl_minutes: number; session_policy?: Record<string, unknown> }) =>
    client.post<StsSession>('/api/v1/iam/sts/sessions', payload),
  deleteStsSession: (client: ApiClient, sessionId: string) =>
    client.delete<{ deleted: boolean; session_id: string }>(
      `/api/v1/iam/sts/sessions/${encodeURIComponent(sessionId)}`
    ),
  deleteConsoleSession: (client: ApiClient, sessionId: string) =>
    client.delete<{ revoked: boolean; already_revoked: boolean; session_id: string }>(
      `/api/v1/auth/sessions/${encodeURIComponent(sessionId)}`
    )
};

export const bucketService = {
  buckets: (client: ApiClient) => client.get<BucketSpec[]>('/api/v1/buckets'),
  usage: (client: ApiClient) => client.get<BucketUsageStats[]>('/api/v1/buckets/usage'),
  createBucket: (client: ApiClient, payload: CreateBucketPayload) =>
    client.post<BucketSpec>('/api/v1/buckets', payload),
  deleteBucket: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(`/api/v1/buckets/${encodeURIComponent(name)}`),
  objects: (client: ApiClient, name: string, prefix = '') =>
    client.get<BucketObjectEntry[]>(
      `/api/v1/buckets/${encodeURIComponent(name)}/objects?prefix=${encodeURIComponent(prefix)}`
    ),
  objectVersions: (client: ApiClient, name: string, key: string) =>
    client.get<BucketObjectVersionEntry[]>(
      `/api/v1/buckets/${encodeURIComponent(name)}/objects/versions?key=${encodeURIComponent(key)}`
    ),
  deleteObject: (client: ApiClient, name: string, key: string, versionId?: string) =>
    client.delete<{ deleted: boolean; key: string; version_id?: string; delete_marker?: boolean }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/objects/${encodeObjectKey(key)}${appendVersionQuery(versionId)}`
    ),
  uploadObject: (client: ApiClient, name: string, key: string, file: Blob) =>
    client.putBinary<{ bucket: string; key: string; size: number; version_id?: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/objects/${encodeObjectKey(key)}`,
      file
    ),
  downloadObject: (client: ApiClient, name: string, key: string, versionId?: string) =>
    client.getBlob(
      `/api/v1/buckets/${encodeURIComponent(name)}/objects/${encodeObjectKey(key)}${appendVersionQuery(versionId)}`
    ),
  updateGovernance: (client: ApiClient, name: string, payload: BucketGovernanceUpdate) =>
    client.patch<BucketSpec>(`/api/v1/buckets/${encodeURIComponent(name)}/governance`, payload),
  objectLock: (client: ApiClient, name: string) =>
    client.get<BucketObjectLockConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/object-lock`),
  updateObjectLock: (client: ApiClient, name: string, payload: BucketObjectLockConfig) =>
    client.put<BucketObjectLockConfig>(
      `/api/v1/buckets/${encodeURIComponent(name)}/object-lock`,
      payload
    ),
  retention: (client: ApiClient, name: string) =>
    client.get<BucketRetentionConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/retention`),
  updateRetention: (client: ApiClient, name: string, payload: BucketRetentionConfig) =>
    client.put<BucketRetentionConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/retention`, payload),
  legalHold: (client: ApiClient, name: string) =>
    client.get<BucketLegalHoldConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/legal-hold`),
  updateLegalHold: (client: ApiClient, name: string, payload: BucketLegalHoldConfig) =>
    client.put<BucketLegalHoldConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/legal-hold`, payload),
  acl: (client: ApiClient, name: string) =>
    client.get<BucketAclConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/acl`),
  updateAcl: (client: ApiClient, name: string, payload: BucketAclConfig) =>
    client.put<BucketAclConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/acl`, payload),
  publicAccessBlock: (client: ApiClient, name: string) =>
    client.get<BucketPublicAccessBlockConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/public-access-block`),
  updatePublicAccessBlock: (client: ApiClient, name: string, payload: BucketPublicAccessBlockConfig) =>
    client.put<BucketPublicAccessBlockConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/public-access-block`, payload),
  deletePublicAccessBlock: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/public-access-block`
    ),
  notifications: (client: ApiClient, name: string) =>
    client.get<BucketNotificationRule[]>(`/api/v1/buckets/${encodeURIComponent(name)}/notifications`),
  updateNotifications: (client: ApiClient, name: string, payload: BucketNotificationRule[]) =>
    client.put<BucketNotificationRule[]>(`/api/v1/buckets/${encodeURIComponent(name)}/notifications`, payload),
  lifecycle: (client: ApiClient, name: string) =>
    client.get<BucketLifecycleRule[]>(`/api/v1/buckets/${encodeURIComponent(name)}/lifecycle`),
  updateLifecycle: (client: ApiClient, name: string, payload: BucketLifecycleRule[]) =>
    client.put<BucketLifecycleRule[]>(`/api/v1/buckets/${encodeURIComponent(name)}/lifecycle`, payload),
  deleteLifecycle: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/lifecycle`
    ),
  policy: (client: ApiClient, name: string) =>
    client.get<Record<string, unknown>>(`/api/v1/buckets/${encodeURIComponent(name)}/policy`),
  updatePolicy: (client: ApiClient, name: string, payload: Record<string, unknown>) =>
    client.put<Record<string, unknown>>(`/api/v1/buckets/${encodeURIComponent(name)}/policy`, payload),
  deletePolicy: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/policy`
    ),
  cors: (client: ApiClient, name: string) =>
    client.get<BucketCorsRule[]>(`/api/v1/buckets/${encodeURIComponent(name)}/cors`),
  updateCors: (client: ApiClient, name: string, payload: BucketCorsRule[]) =>
    client.put<BucketCorsRule[]>(`/api/v1/buckets/${encodeURIComponent(name)}/cors`, payload),
  deleteCors: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/cors`
    ),
  tags: (client: ApiClient, name: string) =>
    client.get<BucketTag[]>(`/api/v1/buckets/${encodeURIComponent(name)}/tags`),
  updateTags: (client: ApiClient, name: string, payload: BucketTag[]) =>
    client.put<BucketTag[]>(`/api/v1/buckets/${encodeURIComponent(name)}/tags`, payload),
  deleteTags: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/tags`
    ),
  encryption: (client: ApiClient, name: string) =>
    client.get<BucketEncryptionConfig>(`/api/v1/buckets/${encodeURIComponent(name)}/encryption`),
  updateEncryption: (client: ApiClient, name: string, payload: BucketEncryptionConfig) =>
    client.put<BucketEncryptionConfig>(
      `/api/v1/buckets/${encodeURIComponent(name)}/encryption`,
      payload
    ),
  deleteEncryption: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/encryption`
    ),
  updateReplication: (
    client: ApiClient,
    name: string,
    payload: {
      rule_id?: string;
      target_site: string;
      rule_name?: string;
      endpoint?: string;
      prefix?: string;
      suffix?: string;
      tags?: BucketTag[];
      priority?: number;
      replicate_existing?: boolean;
      sync_deletes?: boolean;
      enabled: boolean;
    }
  ) => client.post<ReplicationStatus>(`/api/v1/buckets/${encodeURIComponent(name)}/replication`, payload),
  deleteReplication: (client: ApiClient, name: string, ruleId: string) =>
    client.delete<{ deleted: boolean; rule_id: string }>(
      `/api/v1/buckets/${encodeURIComponent(name)}/replication/${encodeURIComponent(ruleId)}`
    ),
  replications: (client: ApiClient) => client.get<ReplicationStatus[]>('/api/v1/buckets/replication/status')
};

export const replicationService = {
  listSites: (client: ApiClient) => client.get<SiteReplicationStatus[]>('/api/v1/replication/sites'),
  bootstrapSite: (client: ApiClient, payload: SiteReplicationBootstrapRequest) =>
    client.post<JobStatus>('/api/v1/replication/sites/bootstrap', payload, true),
  joinSite: (client: ApiClient, siteId: string, payload: SiteReplicationJoinRequest) =>
    client.post<JobStatus>(`/api/v1/replication/sites/${encodeURIComponent(siteId)}/join`, payload, true),
  failoverSite: (client: ApiClient, siteId: string, reason: string) =>
    client.post<JobStatus>(
      `/api/v1/replication/sites/${encodeURIComponent(siteId)}/failover`,
      { reason },
      true
    ),
  failbackSite: (client: ApiClient, siteId: string, reason: string) =>
    client.post<JobStatus>(
      `/api/v1/replication/sites/${encodeURIComponent(siteId)}/failback`,
      { reason },
      true
    ),
  resyncSite: (client: ApiClient, siteId: string, reason: string) =>
    client.post<JobStatus>(
      `/api/v1/replication/sites/${encodeURIComponent(siteId)}/resync`,
      { reason },
      true
    ),
  reconcileSite: (client: ApiClient, siteId: string, reason: string) =>
    client.post<JobStatus>(
      `/api/v1/replication/sites/${encodeURIComponent(siteId)}/reconcile`,
      { reason },
      true
    ),
  reconcilePreview: (client: ApiClient, siteId: string) =>
    client.get<SiteReplicationDriftReport>(`/api/v1/replication/sites/${encodeURIComponent(siteId)}/reconcile-preview`),
  siteDrift: (client: ApiClient, siteId: string) =>
    client.get<SiteReplicationDriftReport>(`/api/v1/replication/sites/${encodeURIComponent(siteId)}/drift`)
};

export const securityService = {
  config: (client: ApiClient) => client.get<SecurityConfig>('/api/v1/security/config'),
  kmsStatus: (client: ApiClient) => client.get<SystemKmsMetricsSummary>('/api/v1/security/kms/status'),
  updateConfig: (client: ApiClient, payload: Partial<SecurityConfig>) =>
    client.patch<SecurityConfig>('/api/v1/security/config', payload),
  rotateKms: (client: ApiClient, reason: string) =>
    client.post<KmsRotationResult>('/api/v1/security/kms/rotate', { reason }, true),
  retryKmsRotation: (client: ApiClient, reason: string) =>
    client.post<KmsRotationResult>('/api/v1/security/kms/rotate/retry', { reason }, true)
};

export const alertService = {
  rules: (client: ApiClient) => client.get<AlertRule[]>('/api/v1/alerts/rules'),
  createRule: (
    client: ApiClient,
    payload: {
      id?: string;
      name: string;
      metric: string;
      condition: string;
      threshold: number;
      window_minutes: number;
      severity: string;
      enabled: boolean;
      channels: string[];
    }
  ) => client.post<AlertRule>('/api/v1/alerts/rules', payload),
  updateRule: (
    client: ApiClient,
    id: string,
    payload: {
      id?: string;
      name: string;
      metric: string;
      condition: string;
      threshold: number;
      window_minutes: number;
      severity: string;
      enabled: boolean;
      channels: string[];
    }
  ) => client.put<AlertRule>(`/api/v1/alerts/rules/${encodeURIComponent(id)}`, payload),
  deleteRule: (client: ApiClient, id: string) =>
    client.delete<{ deleted: boolean; id: string }>(`/api/v1/alerts/rules/${encodeURIComponent(id)}`),
  simulateRule: (client: ApiClient, id: string) =>
    client.post<AlertHistoryEntry>(`/api/v1/alerts/rules/${encodeURIComponent(id)}/simulate`),

  channels: (client: ApiClient) => client.get<AlertChannel[]>('/api/v1/alerts/channels'),
  createChannel: (
    client: ApiClient,
    payload: {
      id?: string;
      name: string;
      kind: string;
      endpoint: string;
      enabled: boolean;
      headers?: Record<string, string>;
      payload_template?: string;
      header_template?: Record<string, string>;
    }
  ) => client.post<AlertChannel>('/api/v1/alerts/channels', payload),
  updateChannel: (
    client: ApiClient,
    id: string,
    payload: {
      id?: string;
      name: string;
      kind: string;
      endpoint: string;
      enabled: boolean;
      headers?: Record<string, string>;
      payload_template?: string;
      header_template?: Record<string, string>;
    }
  ) => client.put<AlertChannel>(`/api/v1/alerts/channels/${encodeURIComponent(id)}`, payload),
  deleteChannel: (client: ApiClient, id: string) =>
    client.delete<{ deleted: boolean; id: string }>(`/api/v1/alerts/channels/${encodeURIComponent(id)}`),
  testChannel: (client: ApiClient, id: string) =>
    client.post<AlertChannel>(`/api/v1/alerts/channels/${encodeURIComponent(id)}/test`),

  silences: (client: ApiClient) => client.get<AlertSilence[]>('/api/v1/alerts/silences'),
  createSilence: (
    client: ApiClient,
    payload: {
      id?: string;
      name: string;
      rule_ids: string[];
      starts_at: string;
      ends_at: string;
      reason: string;
      enabled: boolean;
    }
  ) => client.post<AlertSilence>('/api/v1/alerts/silences', payload),
  deleteSilence: (client: ApiClient, id: string) =>
    client.delete<{ deleted: boolean; id: string }>(`/api/v1/alerts/silences/${encodeURIComponent(id)}`),

  escalations: (client: ApiClient) => client.get<AlertEscalationPolicy[]>('/api/v1/alerts/escalations'),
  createEscalation: (
    client: ApiClient,
    payload: {
      id?: string;
      name: string;
      severity: string;
      wait_minutes: number;
      channels: string[];
      enabled: boolean;
    }
  ) => client.post<AlertEscalationPolicy>('/api/v1/alerts/escalations', payload),
  updateEscalation: (
    client: ApiClient,
    id: string,
    payload: {
      id?: string;
      name: string;
      severity: string;
      wait_minutes: number;
      channels: string[];
      enabled: boolean;
    }
  ) => client.put<AlertEscalationPolicy>(`/api/v1/alerts/escalations/${encodeURIComponent(id)}`, payload),
  deleteEscalation: (client: ApiClient, id: string) =>
    client.delete<{ deleted: boolean; id: string }>(
      `/api/v1/alerts/escalations/${encodeURIComponent(id)}`
    ),

  history: (
    client: ApiClient,
    params: {
      limit?: number;
      severity?: string;
      status?: string;
      rule_id?: string;
      source?: string;
    } = {}
  ) => {
    const query = new URLSearchParams();
    query.set('limit', String(params.limit ?? 200));
    if (params.severity) query.set('severity', params.severity);
    if (params.status) query.set('status', params.status);
    if (params.rule_id) query.set('rule_id', params.rule_id);
    if (params.source) query.set('source', params.source);
    return client.get<AlertHistoryEntry[]>(`/api/v1/alerts/history?${query.toString()}`);
  },
  claimHistory: (client: ApiClient, id: string) =>
    client.post<AlertHistoryEntry>(`/api/v1/alerts/history/${encodeURIComponent(id)}/claim`),
  ackHistory: (client: ApiClient, id: string) =>
    client.post<AlertHistoryEntry>(`/api/v1/alerts/history/${encodeURIComponent(id)}/ack`),
  resolveHistory: (client: ApiClient, id: string) =>
    client.post<AlertHistoryEntry>(`/api/v1/alerts/history/${encodeURIComponent(id)}/resolve`)
};

export const auditService = {
  events: (
    client: ApiClient,
    params: {
      limit?: number;
      category?: string;
      actor?: string;
      action?: string;
      action_prefix?: string;
      resource?: string;
      resource_prefix?: string;
      outcome?: string;
      keyword?: string;
      reason?: string;
      detail_key?: string;
      detail_value?: string;
      from?: string;
      to?: string;
    } = {}
  ) => {
    const query = new URLSearchParams();
    query.set('limit', String(params.limit ?? 100));
    if (params.category) query.set('category', params.category);
    if (params.actor) query.set('actor', params.actor);
    if (params.action) query.set('action', params.action);
    if (params.action_prefix) query.set('action_prefix', params.action_prefix);
    if (params.resource) query.set('resource', params.resource);
    if (params.resource_prefix) query.set('resource_prefix', params.resource_prefix);
    if (params.outcome) query.set('outcome', params.outcome);
    if (params.keyword) query.set('keyword', params.keyword);
    if (params.reason) query.set('reason', params.reason);
    if (params.detail_key) query.set('detail_key', params.detail_key);
    if (params.detail_value) query.set('detail_value', params.detail_value);
    if (params.from) query.set('from', params.from);
    if (params.to) query.set('to', params.to);
    return client.get<AuditEvent[]>(`/api/v1/audit/events?${query.toString()}`);
  },
  exportEvents: (client: ApiClient) => client.getText('/api/v1/audit/export')
};

/** 构建带 query 的存储库存/归档过滤串 */
const buildInventoryQuery = (query: StorageInventoryQuery = {}, format?: 'json' | 'csv') => {
  const params = new URLSearchParams();
  if (query.bucket) params.set('bucket', query.bucket);
  if (query.prefix) params.set('prefix', query.prefix);
  if (typeof query.current_only === 'boolean') params.set('current_only', String(query.current_only));
  if (typeof query.noncurrent_only === 'boolean') params.set('noncurrent_only', String(query.noncurrent_only));
  if (typeof query.remote_only === 'boolean') params.set('remote_only', String(query.remote_only));
  if (query.tier) params.set('tier', query.tier);
  if (query.restore_state) params.set('restore_state', query.restore_state);
  if (typeof query.restored_only === 'boolean') params.set('restored_only', String(query.restored_only));
  if (typeof query.restore_expiring_within_minutes === 'number') {
    params.set('restore_expiring_within_minutes', String(query.restore_expiring_within_minutes));
  }
  if (typeof query.limit === 'number') params.set('limit', String(query.limit));
  if (format) params.set('format', format);
  const qs = params.toString();
  return qs ? `?${qs}` : '';
};

export const storageService = {
  // 分层管理
  listTiers: (client: ApiClient) => client.get<RemoteTierConfig[]>('/api/v1/storage/tiers'),
  updateTiers: (client: ApiClient, tiers: RemoteTierConfig[]) =>
    client.put<RemoteTierConfig[]>('/api/v1/storage/tiers', tiers),
  deleteTier: (client: ApiClient, name: string) =>
    client.delete<{ deleted: boolean; name: string }>(`/api/v1/storage/tiers/${encodeURIComponent(name)}`),
  checkTierHealth: (client: ApiClient, name: string) =>
    client.post<RemoteTierConfig>(`/api/v1/storage/tiers/${encodeURIComponent(name)}/health-check`),
  rotateTierSecret: (client: ApiClient, name: string, payload: RotateRemoteTierSecretRequest) =>
    client.post<RemoteTierConfig>(`/api/v1/storage/tiers/${encodeURIComponent(name)}/rotate-secret`, payload),

  // 库存
  listInventory: (client: ApiClient, query: StorageInventoryQuery = {}) =>
    client.get<StorageInventoryEntry[]>(`/api/v1/storage/inventory${buildInventoryQuery(query)}`),
  exportInventory: (client: ApiClient, query: StorageInventoryQuery = {}, format: 'json' | 'csv' = 'json') =>
    client.getBlob(`/api/v1/storage/inventory/export${buildInventoryQuery(query, format)}`),

  // 归档
  archiveReport: (client: ApiClient, query: StorageInventoryQuery = {}) =>
    client.get<StorageArchiveReport>(`/api/v1/storage/archive/report${buildInventoryQuery(query)}`),
  exportArchiveReport: (client: ApiClient, query: StorageInventoryQuery = {}, format: 'json' | 'csv' = 'json') =>
    client.getBlob(`/api/v1/storage/archive/report/export${buildInventoryQuery(query, format)}`),
  prewarmArchive: (client: ApiClient, payload: StorageArchivePrewarmRequest) =>
    client.post<StorageArchivePrewarmResult>('/api/v1/storage/archive/prewarm', payload, true),

  // 治理 / 再平衡 / 退役
  governance: (client: ApiClient) =>
    client.get<StorageGovernanceStatusResponse>('/api/v1/storage/governance'),
  startRebalance: (client: ApiClient, payload: StorageMaintenanceRequest) =>
    client.post<JobStatus>('/api/v1/storage/governance/rebalance', payload, true),
  startClusterRebalance: (client: ApiClient, payload: ClusterRebalanceRequest) =>
    client.post<Record<string, unknown>>('/api/v1/storage/governance/cluster-rebalance', payload, true),
  cancelClusterRebalance: (client: ApiClient) =>
    client.post<{ cancelled: number }>('/api/v1/storage/governance/cluster-rebalance/cancel', undefined, true),
  startDecommission: (client: ApiClient, payload: StorageMaintenanceRequest) =>
    client.post<JobStatus>('/api/v1/storage/governance/decommission', payload, true)
};

/** 构建复制积压过滤串 */
const buildBacklogQuery = (query: ReplicationBacklogQuery = {}) => {
  const params = new URLSearchParams();
  if (query.status) params.set('status', query.status);
  if (query.source_bucket) params.set('source_bucket', query.source_bucket);
  if (query.target_site) params.set('target_site', query.target_site);
  if (query.object_prefix) params.set('object_prefix', query.object_prefix);
  if (typeof query.limit === 'number') params.set('limit', String(query.limit));
  if (typeof query.include_terminal === 'boolean') params.set('include_terminal', String(query.include_terminal));
  if (query.cursor) params.set('cursor', query.cursor);
  const qs = params.toString();
  return qs ? `?${qs}` : '';
};

type AsyncJobQuery = {
  kind?: string;
  status?: string;
  bucket?: string;
  site_id?: string;
  object_prefix?: string;
  keyword?: string;
  limit?: number;
  include_terminal?: boolean;
  cursor?: string;
};

const buildAsyncQuery = (params: AsyncJobQuery = {}) => {
  const query = new URLSearchParams();
  if (params.kind) query.set('kind', params.kind);
  if (params.status) query.set('status', params.status);
  if (params.bucket) query.set('bucket', params.bucket);
  if (params.site_id) query.set('site_id', params.site_id);
  if (params.object_prefix) query.set('object_prefix', params.object_prefix);
  if (params.keyword) query.set('keyword', params.keyword);
  if (typeof params.limit === 'number') query.set('limit', String(params.limit));
  if (typeof params.include_terminal === 'boolean') query.set('include_terminal', String(params.include_terminal));
  if (params.cursor) query.set('cursor', params.cursor);
  const qs = query.toString();
  return qs ? `?${qs}` : '';
};

export const jobsService = {
  jobs: (client: ApiClient) => client.get<JobStatus[]>('/api/v1/jobs'),
  queue: (
    client: ApiClient,
    body: {
      target?: string;
      kind?: string;
      bucket?: string;
      key?: string;
      version_id?: string;
      priority?: number;
    }
  ) => client.post<JobStatus>('/api/v1/jobs/heal', body),
  heal: (client: ApiClient, target: string) =>
    client.post<JobStatus>('/api/v1/jobs/heal', { target, kind: 'heal' }),
  asyncJobs: (client: ApiClient, params: AsyncJobQuery = {}) =>
    client.get<AsyncJobStatus[]>(`/api/v1/jobs/async${buildAsyncQuery(params)}`),
  asyncJobsPage: (client: ApiClient, params: AsyncJobQuery = {}) =>
    client.get<AsyncJobPage>(`/api/v1/jobs/async/page${buildAsyncQuery(params)}`),
  asyncJobsSummary: (client: ApiClient, params: AsyncJobQuery = {}) =>
    client.get<AsyncJobSummary>(`/api/v1/jobs/async/summary${buildAsyncQuery(params)}`),
  exportAsyncJobs: (client: ApiClient, params: AsyncJobQuery = {}) =>
    client.getText(`/api/v1/jobs/async/export${buildAsyncQuery(params)}`),
  retryAsyncJobs: (client: ApiClient, params: AsyncJobQuery = {}, job_ids: string[] = []) =>
    client.post<AsyncJobBulkOperationResult>(`/api/v1/jobs/async/bulk/retry${buildAsyncQuery(params)}`, { job_ids }),
  cleanupAsyncJobs: (client: ApiClient, params: AsyncJobQuery = {}, job_ids: string[] = []) =>
    client.post<AsyncJobBulkOperationResult>(`/api/v1/jobs/async/bulk/cleanup${buildAsyncQuery(params)}`, { job_ids }),
  skipAsyncJobs: (client: ApiClient, params: AsyncJobQuery = {}, job_ids: string[] = []) =>
    client.post<AsyncJobBulkOperationResult>(`/api/v1/jobs/async/bulk/skip${buildAsyncQuery(params)}`, { job_ids }),

  // 批处理
  batchRuns: (client: ApiClient) => client.get<BatchRunStatus[]>('/api/v1/jobs/batch'),
  createBatch: (client: ApiClient, payload: BatchRunRequest) =>
    client.post<BatchRunStatus>('/api/v1/jobs/batch', payload),
  getBatchRun: (client: ApiClient, id: string) =>
    client.get<BatchRunStatus>(`/api/v1/jobs/batch/${encodeURIComponent(id)}`),

  // 复制积压
  replicationBacklog: (client: ApiClient) =>
    client.get<ReplicationBacklogItem[]>('/api/v1/jobs/replication-backlog'),
  replicationBacklogPage: (client: ApiClient, query: ReplicationBacklogQuery = {}) =>
    client.get<ReplicationBacklogPage>(`/api/v1/jobs/replication-backlog/page${buildBacklogQuery(query)}`),
  replicationBacklogMetrics: (client: ApiClient, query: ReplicationBacklogQuery = {}) =>
    client.get<ReplicationBacklogMetrics>(`/api/v1/jobs/replication-backlog/metrics${buildBacklogQuery(query)}`),
  retryReplicationBacklog: (client: ApiClient, id: string) =>
    client.post<{ retried: boolean; id: string; remaining: number }>(
      `/api/v1/jobs/replication-backlog/${encodeURIComponent(id)}/retry`
    ),
  retryMatchedReplicationBacklog: (client: ApiClient, query: ReplicationBacklogQuery = {}) =>
    client.post<ReplicationBacklogBatchResult>(`/api/v1/jobs/replication-backlog/retry${buildBacklogQuery(query)}`),
  cleanupReplicationBacklog: (client: ApiClient, query: ReplicationBacklogQuery = {}) =>
    client.post<ReplicationBacklogBatchResult>(`/api/v1/jobs/replication-backlog/cleanup${buildBacklogQuery(query)}`),
  retryAllReplicationBacklog: (client: ApiClient) =>
    client.post<{ retried: number }>('/api/v1/jobs/replication-backlog/retry-all'),

  retry: (client: ApiClient, id: string) =>
    client.post<JobStatus>(`/api/v1/jobs/${encodeURIComponent(id)}/retry`, {}),
  cancel: (client: ApiClient, id: string, reason: string) =>
    client.post(`/api/v1/jobs/${id}/cancel`, { reason }, true)
};





