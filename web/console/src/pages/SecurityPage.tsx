import { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { securityService, systemService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { StatCard } from '../components/StatCard';
import { useToast, Button } from '../components/ui';
import type { SecurityConfig, SystemKmsMetricsSummary, SystemMetricsSummary } from '../types';
import { toBilingualPrompt } from '../utils/bilingual';

type SecurityPageProps = {
  client: ApiClient;
};

type SecurityFormState = {
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
  sse_mode: string;
};

const EMPTY_FORM: SecurityFormState = {
  oidc_enabled: false,
  ldap_enabled: false,
  oidc_discovery_url: '',
  oidc_issuer: '',
  oidc_client_id: '',
  oidc_jwks_url: '',
  oidc_allowed_algs: '',
  oidc_username_claim: 'preferred_username',
  oidc_groups_claim: 'groups',
  oidc_role_claim: 'role',
  oidc_default_role: 'viewer',
  oidc_group_role_map: '',
  ldap_url: '',
  ldap_bind_dn: '',
  ldap_user_base_dn: '',
  ldap_user_filter: '(uid={username})',
  ldap_group_base_dn: '',
  ldap_group_filter: '(member={user_dn})',
  ldap_group_attribute: 'memberOf',
  ldap_group_name_attribute: 'cn',
  ldap_default_role: 'viewer',
  ldap_group_role_map: '',
  kms_endpoint: '',
  sse_mode: 'SSE-KMS'
};

function toFormState(config: SecurityConfig): SecurityFormState {
  return {
    oidc_enabled: config.oidc_enabled,
    ldap_enabled: config.ldap_enabled,
    oidc_discovery_url: config.oidc_discovery_url,
    oidc_issuer: config.oidc_issuer,
    oidc_client_id: config.oidc_client_id,
    oidc_jwks_url: config.oidc_jwks_url,
    oidc_allowed_algs: config.oidc_allowed_algs,
    oidc_username_claim: config.oidc_username_claim,
    oidc_groups_claim: config.oidc_groups_claim,
    oidc_role_claim: config.oidc_role_claim,
    oidc_default_role: config.oidc_default_role,
    oidc_group_role_map: config.oidc_group_role_map,
    ldap_url: config.ldap_url,
    ldap_bind_dn: config.ldap_bind_dn,
    ldap_user_base_dn: config.ldap_user_base_dn,
    ldap_user_filter: config.ldap_user_filter,
    ldap_group_base_dn: config.ldap_group_base_dn,
    ldap_group_filter: config.ldap_group_filter,
    ldap_group_attribute: config.ldap_group_attribute,
    ldap_group_name_attribute: config.ldap_group_name_attribute,
    ldap_default_role: config.ldap_default_role,
    ldap_group_role_map: config.ldap_group_role_map,
    kms_endpoint: config.kms_endpoint,
    sse_mode: config.sse_mode
  };
}

const inputClass =
  'mt-1 h-11 w-full rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface';
const textareaClass =
  'mt-1 min-h-24 w-full rounded-md border border-outline/60 bg-surface-lowest px-3 py-3 text-on-surface';

export function SecurityPage({ client }: SecurityPageProps) {
  const toast = useToast();
  const [config, setConfig] = useState<SecurityConfig | null>(null);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [kmsStatus, setKmsStatus] = useState<SystemKmsMetricsSummary | null>(null);
  const [form, setForm] = useState<SecurityFormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  async function reload() {
    const [current, summarySnapshot, currentKmsStatus] = await Promise.all([
      securityService.config(client),
      systemService.metricsSummary(client),
      securityService.kmsStatus(client)
    ]);
    setConfig(current);
    setSummary(summarySnapshot);
    setKmsStatus(currentKmsStatus);
    setForm(toFormState(current));
  }

  useEffect(() => {
    reload().catch((requestError) => {
      toast.error(requestError instanceof Error ? requestError.message : '加载安全配置失败');
    });
  }, [client]);

  function boolText(value: boolean) {
    return value ? '启用' : '禁用';
  }

  function formatTime(value?: string | null) {
    if (!value) return '--';
    return new Date(value).toLocaleString();
  }

  function kmsRotationStatusText(status?: string) {
    if (!status) return '未知';
    if (status === 'idle') return '空闲';
    if (status === 'running') return '执行中';
    if (status === 'completed') return '已完成';
    if (status === 'failed') return '失败';
    if (status === 'partial_failed') return '部分失败';
    return status;
  }

  function updateField<Key extends keyof SecurityFormState>(
    key: Key,
    value: SecurityFormState[Key]
  ) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h1 className="font-heading text-2xl text-on-surface">安全与 KMS</h1>

        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="OIDC"
            value={summary ? boolText(summary.security.oidc_enabled) : '...'}
            helper="统一指标摘要"
          />
          <StatCard
            label="LDAP"
            value={summary ? boolText(summary.security.ldap_enabled) : '...'}
            helper="目录鉴权"
          />
          <StatCard
            label="KMS 健康"
            value={summary ? boolText(summary.security.kms_healthy) : '...'}
            helper={summary ? `Endpoint ${boolText(summary.security.kms_endpoint_configured)}` : '密钥管理'}
          />
          <StatCard
            label="服务账号"
            value={
              summary
                ? `${summary.sessions.service_accounts_enabled}/${summary.sessions.service_accounts_total}`
                : '...'
            }
            helper={summary ? summary.security.sse_mode : 'SSE 模式'}
          />
        </div>

        {config ? (
          <dl className="mt-4 grid gap-2 text-sm md:grid-cols-3 xl:grid-cols-6">
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <dt className="text-muted">OIDC</dt>
              <dd className="text-on-surface">{boolText(config.oidc_enabled)}</dd>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <dt className="text-muted">LDAP</dt>
              <dd className="text-on-surface">{boolText(config.ldap_enabled)}</dd>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <dt className="text-muted">KMS 健康</dt>
              <dd className="text-on-surface">{kmsStatus ? boolText(kmsStatus.healthy) : boolText(config.kms_healthy)}</dd>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <dt className="text-muted">SSE 模式</dt>
              <dd className="text-on-surface">{config.sse_mode}</dd>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <dt className="text-muted">最近成功</dt>
              <dd className="text-on-surface">{formatTime(kmsStatus?.last_success_at ?? config.kms_last_success_at)}</dd>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <dt className="text-muted">轮换状态</dt>
              <dd className="text-on-surface">
                {kmsRotationStatusText(kmsStatus?.rotation_status ?? config.kms_rotation_status)}
              </dd>
            </div>
          </dl>
        ) : null}

        {kmsStatus ? (
          <div className="mt-4 grid gap-3 lg:grid-cols-[1.2fr,1fr]">
            <article className="rounded-xl border border-outline/60 bg-surface-container-high p-4">
              <h2 className="font-heading text-lg text-on-surface">KMS 运行态</h2>
              <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
                <p>KMS Endpoint：{kmsStatus.endpoint_configured ? '已配置' : '未配置'}</p>
                <p>最近检查：{formatTime(kmsStatus.last_checked_at)}</p>
                <p>最近成功：{formatTime(kmsStatus.last_success_at)}</p>
                <p>轮换最近完成：{formatTime(kmsStatus.rotation_last_completed_at)}</p>
              </div>
              {kmsStatus.last_error ? (
                <p className="mt-3 rounded-lg bg-error/10 p-3 text-sm text-error">
                  最近错误：{toBilingualPrompt(kmsStatus.last_error)}
                </p>
              ) : (
                <p className="mt-3 rounded-lg bg-primary/10 p-3 text-sm text-primary">当前未记录 KMS 错误。</p>
              )}
            </article>

            <article className="rounded-xl border border-outline/60 bg-surface-container-high p-4">
              <h2 className="font-heading text-lg text-on-surface">轮换进度</h2>
              <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
                <p>扫描对象：{kmsStatus.rotation_scanned}</p>
                <p>成功轮换：{kmsStatus.rotation_rotated}</p>
                <p>跳过对象：{kmsStatus.rotation_skipped}</p>
                <p>失败对象：{kmsStatus.rotation_failed}</p>
                <p>最近成功轮换：{formatTime(kmsStatus.rotation_last_success_at)}</p>
                <p>重试建议：{kmsStatus.retry_recommended ? '建议重试' : '无需重试'}</p>
              </div>
              {kmsStatus.rotation_last_failure_reason ? (
                <p className="mt-3 rounded-lg bg-warning/10 p-3 text-sm text-warning">
                  失败原因：{toBilingualPrompt(kmsStatus.rotation_last_failure_reason)}
                </p>
              ) : null}
            </article>
          </div>
        ) : null}

        <form
          className="mt-4 space-y-4 rounded-xl border border-outline/60 bg-surface-container-high p-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setSaving(true);
            try {
              await securityService.updateConfig(client, form);
              toast.success('安全配置已更新');
              await reload();
            } catch (requestError) {
              toast.error(requestError instanceof Error ? requestError.message : '更新安全配置失败');
            } finally {
              setSaving(false);
            }
          }}
        >
          <section className="grid gap-3 md:grid-cols-2">
            <label className="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                checked={form.oidc_enabled}
                onChange={(event) => updateField('oidc_enabled', event.target.checked)}
              />
              启用 OIDC
            </label>
            <label className="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                checked={form.ldap_enabled}
                onChange={(event) => updateField('ldap_enabled', event.target.checked)}
              />
              启用 LDAP
            </label>
            <label className="text-sm text-muted">
              KMS 地址
              <input
                value={form.kms_endpoint}
                onChange={(event) => updateField('kms_endpoint', event.target.value)}
                className={inputClass}
              />
            </label>
            <label className="text-sm text-muted">
              SSE 模式
              <select
                value={form.sse_mode}
                onChange={(event) => updateField('sse_mode', event.target.value)}
                className={inputClass}
              >
                <option value="SSE-S3">SSE-S3</option>
                <option value="SSE-KMS">SSE-KMS</option>
                <option value="SSE-C">SSE-C</option>
              </select>
            </label>
          </section>

          <section className="space-y-3 rounded-xl border border-outline/60 bg-on-surface/5 p-4">
            <div>
              <h2 className="font-heading text-lg text-on-surface">OIDC 配置</h2>
              <p className="mt-1 text-sm text-muted">用于 Discovery、JWKS、Claim 映射与组到角色映射。</p>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-sm text-muted">
                Discovery 地址
                <input
                  value={form.oidc_discovery_url}
                  onChange={(event) => updateField('oidc_discovery_url', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                Issuer
                <input
                  value={form.oidc_issuer}
                  onChange={(event) => updateField('oidc_issuer', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                Client ID
                <input
                  value={form.oidc_client_id}
                  onChange={(event) => updateField('oidc_client_id', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                JWKS 地址
                <input
                  value={form.oidc_jwks_url}
                  onChange={(event) => updateField('oidc_jwks_url', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                允许算法
                <input
                  value={form.oidc_allowed_algs}
                  onChange={(event) => updateField('oidc_allowed_algs', event.target.value)}
                  className={inputClass}
                  placeholder="如：RS256,ES256"
                />
              </label>
              <label className="text-sm text-muted">
                用户名 Claim
                <input
                  value={form.oidc_username_claim}
                  onChange={(event) => updateField('oidc_username_claim', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户组 Claim
                <input
                  value={form.oidc_groups_claim}
                  onChange={(event) => updateField('oidc_groups_claim', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                角色 Claim
                <input
                  value={form.oidc_role_claim}
                  onChange={(event) => updateField('oidc_role_claim', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                默认角色
                <input
                  value={form.oidc_default_role}
                  onChange={(event) => updateField('oidc_default_role', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted md:col-span-2">
                用户组角色映射
                <textarea
                  value={form.oidc_group_role_map}
                  onChange={(event) => updateField('oidc_group_role_map', event.target.value)}
                  className={textareaClass}
                  placeholder="例如：platform-admins=admin,security=auditor"
                />
              </label>
            </div>
          </section>

          <section className="space-y-3 rounded-xl border border-outline/60 bg-on-surface/5 p-4">
            <div>
              <h2 className="font-heading text-lg text-on-surface">LDAP 配置</h2>
              <p className="mt-1 text-sm text-muted">用于真实 Bind / Search、组收集与组到角色映射。</p>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-sm text-muted">
                LDAP 地址
                <input
                  value={form.ldap_url}
                  onChange={(event) => updateField('ldap_url', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                绑定 DN
                <input
                  value={form.ldap_bind_dn}
                  onChange={(event) => updateField('ldap_bind_dn', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户 Base DN
                <input
                  value={form.ldap_user_base_dn}
                  onChange={(event) => updateField('ldap_user_base_dn', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户过滤器
                <input
                  value={form.ldap_user_filter}
                  onChange={(event) => updateField('ldap_user_filter', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户组 Base DN
                <input
                  value={form.ldap_group_base_dn}
                  onChange={(event) => updateField('ldap_group_base_dn', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户组过滤器
                <input
                  value={form.ldap_group_filter}
                  onChange={(event) => updateField('ldap_group_filter', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户组属性
                <input
                  value={form.ldap_group_attribute}
                  onChange={(event) => updateField('ldap_group_attribute', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                用户组名称属性
                <input
                  value={form.ldap_group_name_attribute}
                  onChange={(event) => updateField('ldap_group_name_attribute', event.target.value)}
                  className={inputClass}
                />
              </label>
              <label className="text-sm text-muted">
                默认角色
                <input
                  value={form.ldap_default_role}
                  onChange={(event) => updateField('ldap_default_role', event.target.value)}
                  className={inputClass}
                />
              </label>
              <div className="rounded-md border border-dashed border-outline/60 bg-surface-container-high p-3 text-sm text-muted">
                LDAP 绑定密码仅支持后端环境变量配置，前端不展示也不下发明文。
              </div>
              <label className="text-sm text-muted md:col-span-2">
                用户组角色映射
                <textarea
                  value={form.ldap_group_role_map}
                  onChange={(event) => updateField('ldap_group_role_map', event.target.value)}
                  className={textareaClass}
                  placeholder="例如：ops=operator,audit=auditor"
                />
              </label>
            </div>
          </section>

          <div>
            <Button type="submit" variant="primary" loading={saving}>
              保存安全配置
            </Button>
          </div>
        </form>
      </article>

      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h2 className="font-heading text-xl text-on-surface">危险操作</h2>
        <p className="mt-1 text-sm text-muted">该操作必须显式确认并填写审计原因。</p>
        <div className="mt-4">
          <ConfirmActionDialog
            title="轮换 KMS 密钥"
            description="该操作会为托管对象创建密钥轮换任务，请填写审计原因。"
            actionLabel="轮换密钥"
            onConfirm={async (reason) => {
              try {
                const result = await securityService.rotateKms(client, reason);
                toast.success(`KMS 轮换完成：成功 ${result.rotated}，失败 ${result.failed}`);
                await reload();
              } catch (requestError) {
                toast.error(requestError instanceof Error ? requestError.message : '轮换密钥失败');
                throw requestError;
              }
            }}
          />
        </div>
        {kmsStatus?.retry_recommended ? (
          <div className="mt-3">
            <ConfirmActionDialog
              title="重试失败的 KMS 轮换"
              description="该操作仅重试上一次轮换失败的对象，请填写审计原因。"
              actionLabel="重试失败对象"
              onConfirm={async (reason) => {
                try {
                  const result = await securityService.retryKmsRotation(client, reason);
                  toast.success(`KMS 重试完成：成功 ${result.rotated}，失败 ${result.failed}`);
                  await reload();
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '重试 KMS 轮换失败');
                  throw requestError;
                }
              }}
            />
          </div>
        ) : null}
      </article>
    </section>
  );
}
