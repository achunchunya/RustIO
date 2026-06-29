import { useEffect, useMemo, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { bucketService, jobsService, replicationService, systemService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { StatCard } from '../components/StatCard';
import {
  Badge,
  Button,
  Card,
  Chip,
  Dialog,
  Field,
  Input,
  PageHeader,
  Panel,
  ProgressBar,
  SectionTitle,
  Select,
  useConfirm,
  type BadgeTone
} from '../components/ui';
import type {
  AsyncJobStatus,
  AsyncJobSummary,
  BucketSpec,
  ReplicationBacklogItem,
  ReplicationStatus,
  SiteReplicationDriftReport,
  SiteReplicationStatus,
  SystemMetricsSummary
} from '../types';

type ReplicationPageProps = {
  client: ApiClient;
};

/** 站点状态 → 徽章色:健康 success、降级 warning、其余 error。 */
function siteStateTone(state: string): BadgeTone {
  if (state === 'healthy') return 'success';
  if (state === 'degraded') return 'warning';
  return 'error';
}

/** 积压/任务状态 → 徽章色。 */
function backlogStatusTone(status: string): BadgeTone {
  if (status === 'done' || status === 'drained') return 'success';
  if (status === 'pending' || status === 'retrying' || status === 'in_progress') return 'warning';
  if (status === 'failed' || status === 'dead_letter') return 'error';
  return 'neutral';
}

function switchJobStatusTone(status: string): BadgeTone {
  if (status === 'completed' || status === 'done' || status === 'success') return 'success';
  if (status === 'pending' || status === 'in_progress') return 'warning';
  if (status === 'failed' || status === 'dead_letter') return 'error';
  return 'neutral';
}

export function ReplicationPage({ client }: ReplicationPageProps) {
  const confirm = useConfirm();
  const [rules, setRules] = useState<ReplicationStatus[]>([]);
  const [sites, setSites] = useState<SiteReplicationStatus[]>([]);
  const [buckets, setBuckets] = useState<BucketSpec[]>([]);
  const [backlog, setBacklog] = useState<ReplicationBacklogItem[]>([]);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [replicationSummary, setReplicationSummary] = useState<AsyncJobSummary | null>(null);
  const [switchJobs, setSwitchJobs] = useState<AsyncJobStatus[]>([]);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [saving, setSaving] = useState(false);
  const [updatingRule, setUpdatingRule] = useState('');
  const [deletingRule, setDeletingRule] = useState('');
  const [switchingSiteAction, setSwitchingSiteAction] = useState('');
  const [retryingBacklogId, setRetryingBacklogId] = useState('');
  const [retryingAllBacklog, setRetryingAllBacklog] = useState(false);
  const [cleaningDoneBacklog, setCleaningDoneBacklog] = useState(false);
  const [bootstrapping, setBootstrapping] = useState(false);
  const [driftLoadingSite, setDriftLoadingSite] = useState('');
  const [driftReport, setDriftReport] = useState<SiteReplicationDriftReport | null>(null);
  const [driftTitle, setDriftTitle] = useState('');
  const [bootstrapForm, setBootstrapForm] = useState({
    site_id: '',
    endpoint: '',
    reason: '',
    preferred_primary: false
  });
  const [form, setForm] = useState({
    rule_id: '',
    source_bucket: '',
    rule_name: '',
    target_site: 'dr-site-a',
    endpoint: '',
    prefix: '',
    priority: 100,
    replicate_existing: true,
    sync_deletes: true,
    enabled: true
  });

  async function reload() {
    const [
      replicationRows,
      siteRows,
      bucketRows,
      backlogRows,
      metricsSummary,
      unifiedReplicationSummary,
      failoverJobs,
      failbackJobs
    ] = await Promise.all([
      bucketService.replications(client),
      replicationService.listSites(client),
      bucketService.buckets(client),
      jobsService.replicationBacklog(client),
      systemService.metricsSummary(client),
      jobsService.asyncJobsSummary(client, { kind: 'replication' }),
      jobsService.asyncJobs(client, { kind: 'failover', limit: 20 }),
      jobsService.asyncJobs(client, { kind: 'failback', limit: 20 })
    ]);
    setRules(replicationRows);
    setSites(siteRows);
    setBuckets(bucketRows);
    setBacklog(backlogRows);
    setSummary(metricsSummary);
    setReplicationSummary(unifiedReplicationSummary);
    setSwitchJobs([...failoverJobs, ...failbackJobs]);
    if (!form.source_bucket && bucketRows[0]) {
      setForm((current) => ({ ...current, source_bucket: bucketRows[0].name }));
    }
  }

  useEffect(() => {
    reload().catch((requestError) => {
      setError(requestError instanceof Error ? requestError.message : '加载复制状态失败');
    });
  }, [client]);

  function replicationStatusText(status: string) {
    if (status === 'healthy') return '健康';
    if (status === 'paused') return '暂停';
    return status;
  }

  function backlogStatusText(status: string) {
    if (status === 'pending') return '待重试';
    if (status === 'retrying') return '重试中';
    if (status === 'in_progress') return '执行中';
    if (status === 'failed') return '失败';
    if (status === 'dead_letter') return '死信';
    if (status === 'done') return '已完成';
    if (status === 'skipped') return '已跳过';
    if (status === 'drained') return '已排空';
    return status;
  }

  function siteRoleText(role: string) {
    if (role === 'primary') return '主站';
    if (role === 'secondary') return '从站';
    return role;
  }

  function siteStateText(state: string) {
    if (state === 'healthy') return '健康';
    if (state === 'degraded') return '降级';
    if (state === 'offline') return '离线';
    return state;
  }

  function bootstrapStateText(state: string) {
    if (state === 'pending') return '待初始化';
    if (state === 'in_progress' || state === 'bootstrapping') return '初始化中';
    if (state === 'ready' || state === 'completed' || state === 'done') return '就绪';
    if (state === 'failed') return '失败';
    return state || '未知';
  }

  function switchJobStatusText(status: string) {
    if (status === 'pending') return '排队中';
    if (status === 'in_progress') return '执行中';
    if (status === 'failed') return '失败';
    if (status === 'dead_letter') return '死信';
    if (status === 'completed' || status === 'done' || status === 'success') return '已完成';
    if (status === 'skipped') return '已跳过';
    return status;
  }

  function formatTime(value?: string | null) {
    if (!value) return '从未';
    return new Date(value).toLocaleString();
  }

  function resetRuleForm() {
    setForm((current) => ({
      ...current,
      rule_id: '',
      rule_name: '',
      endpoint: '',
      prefix: '',
      priority: 100,
      replicate_existing: true,
      sync_deletes: true,
      enabled: true
    }));
  }

  async function openDrift(siteId: string, title: string, loader: () => Promise<SiteReplicationDriftReport>) {
    setDriftLoadingSite(siteId);
    setError('');
    try {
      const report = await loader();
      setDriftReport(report);
      setDriftTitle(title);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '获取漂移报告失败');
    } finally {
      setDriftLoadingSite('');
    }
  }

  const sortedRules = useMemo(
    () =>
      [...rules].sort(
        (left, right) =>
          left.source_bucket.localeCompare(right.source_bucket) ||
          left.priority - right.priority ||
          left.target_site.localeCompare(right.target_site) ||
          (left.prefix ?? '').localeCompare(right.prefix ?? '')
      ),
    [rules]
  );

  const sortedBacklog = useMemo(
    () => [...backlog].sort((left, right) => right.queued_at.localeCompare(left.queued_at)),
    [backlog]
  );
  const switchJobBySite = useMemo(() => {
    const mapping: Record<string, AsyncJobStatus> = {};
    const ordered = [...switchJobs].sort((left, right) => right.created_at.localeCompare(left.created_at));
    for (const job of ordered) {
      if (job.site_id && !mapping[job.site_id]) {
        mapping[job.site_id] = job;
      }
    }
    return mapping;
  }, [switchJobs]);
  const sortedSites = useMemo(() => {
    return [...sites].sort((left, right) => {
      const leftOrder = left.role === 'primary' ? 0 : 1;
      const rightOrder = right.role === 'primary' ? 0 : 1;
      return leftOrder - rightOrder || left.site_id.localeCompare(right.site_id);
    });
  }, [sites]);
  const siteMetricsById = useMemo(
    () => Object.fromEntries((summary?.replication.sites ?? []).map((site) => [site.site_id, site])),
    [summary]
  );

  return (
    <section className="space-y-6">
      <PageHeader title="复制" subtitle="跨站复制链路状态、规则配置与失败重试队列。" />

      {error ? <p className="text-sm text-error">{toBilingualPrompt(error)}</p> : null}
      {message ? <p className="text-sm text-success">{toBilingualNotice(message)}</p> : null}

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard
          label="复制任务总数"
          value={replicationSummary ? String(replicationSummary.total) : '...'}
          helper="统一异步任务口径"
        />
        <StatCard
          label="待处理 / 执行中"
          value={
            replicationSummary
              ? `${replicationSummary.pending}/${replicationSummary.in_progress}`
              : '...'
          }
          helper="追平与回压处理"
        />
        <StatCard
          label="失败 / 死信"
          value={
            replicationSummary
              ? `${replicationSummary.failed}/${replicationSummary.dead_letter}`
              : '...'
          }
          helper={replicationSummary ? `可重试 ${replicationSummary.retryable}` : '统一失败口径'}
        />
        <StatCard
          label="健康站点"
          value={
            summary
              ? `${summary.replication.sites_healthy}/${summary.replication.sites_total}`
              : '...'
          }
          helper={summary ? `最大延迟 ${summary.replication.max_lag_seconds} 秒` : '站点健康'}
        />
      </div>

      <Card>
        <SectionTitle>初始化站点（Bootstrap）</SectionTitle>
        <p className="mt-1 text-sm text-muted">
          引导新的容灾站点加入复制拓扑,首个站点将作为初始主站。
        </p>
        <form
          className="mt-4 grid gap-3 md:grid-cols-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setBootstrapping(true);
            setError('');
            setMessage('');
            try {
              await replicationService.bootstrapSite(client, {
                site_id: bootstrapForm.site_id.trim(),
                endpoint: bootstrapForm.endpoint.trim(),
                reason: bootstrapForm.reason.trim(),
                preferred_primary: bootstrapForm.preferred_primary
              });
              setMessage(`站点 ${bootstrapForm.site_id} 的初始化任务已创建`);
              setBootstrapForm({ site_id: '', endpoint: '', reason: '', preferred_primary: false });
              await reload();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '初始化站点失败');
            } finally {
              setBootstrapping(false);
            }
          }}
        >
          <Field label="站点 ID" htmlFor="bootstrap-site-id">
            <Input
              id="bootstrap-site-id"
              size="sm"
              required
              value={bootstrapForm.site_id}
              onChange={(event) =>
                setBootstrapForm((current) => ({ ...current, site_id: event.target.value }))
              }
              placeholder="dr-site-b"
            />
          </Field>
          <Field label="站点端点" htmlFor="bootstrap-endpoint">
            <Input
              id="bootstrap-endpoint"
              size="sm"
              required
              value={bootstrapForm.endpoint}
              onChange={(event) =>
                setBootstrapForm((current) => ({ ...current, endpoint: event.target.value }))
              }
              placeholder="https://dr-site-b.example.internal"
            />
          </Field>
          <Field label="审计原因" htmlFor="bootstrap-reason">
            <Input
              id="bootstrap-reason"
              size="sm"
              required
              value={bootstrapForm.reason}
              onChange={(event) =>
                setBootstrapForm((current) => ({ ...current, reason: event.target.value }))
              }
              placeholder="新建容灾站点"
            />
          </Field>
          <label className="flex items-center gap-2 text-sm text-muted md:mt-7">
            <input
              type="checkbox"
              checked={bootstrapForm.preferred_primary}
              onChange={(event) =>
                setBootstrapForm((current) => ({ ...current, preferred_primary: event.target.checked }))
              }
            />
            设为首选主站
          </label>
          <div className="md:col-span-4">
            <Button
              type="submit"
              loading={bootstrapping}
              disabled={
                !bootstrapForm.site_id.trim() ||
                !bootstrapForm.endpoint.trim() ||
                !bootstrapForm.reason.trim()
              }
            >
              {bootstrapping ? '初始化中...' : '初始化站点'}
            </Button>
          </div>
        </form>
      </Card>

      <Card>
        <div className="flex items-center justify-between gap-3">
          <SectionTitle>{form.rule_id ? '编辑复制规则' : '新增复制规则'}</SectionTitle>
          {form.rule_id ? (
            <Button variant="tertiary" size="sm" onClick={resetRuleForm}>
              取消编辑
            </Button>
          ) : null}
        </div>
        <p className="mt-1 text-sm text-muted">
          支持规则名、端点、前缀、优先级、已有对象追平与删除同步控制。
        </p>
        <form
          className="mt-4 grid gap-3 md:grid-cols-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setSaving(true);
            setError('');
            setMessage('');
            try {
              await bucketService.updateReplication(client, form.source_bucket, {
                rule_id: form.rule_id || undefined,
                rule_name: form.rule_name.trim() || undefined,
                target_site: form.target_site,
                endpoint: form.endpoint.trim() || undefined,
                prefix: form.prefix.trim() || undefined,
                priority: form.priority,
                replicate_existing: form.replicate_existing,
                sync_deletes: form.sync_deletes,
                enabled: form.enabled
              });
              setMessage(`桶 ${form.source_bucket} 的复制规则已保存`);
              resetRuleForm();
              await reload();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '保存复制规则失败');
            } finally {
              setSaving(false);
            }
          }}
        >
          <Field label="源桶" htmlFor="rule-source-bucket">
            <Select
              id="rule-source-bucket"
              size="sm"
              required
              value={form.source_bucket}
              onChange={(event) => setForm((current) => ({ ...current, source_bucket: event.target.value }))}
            >
              {buckets.length === 0 ? <option value="">无可用桶</option> : null}
              {buckets.map((bucket) => (
                <option key={bucket.name} value={bucket.name}>
                  {bucket.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="规则名称" htmlFor="rule-name">
            <Input
              id="rule-name"
              size="sm"
              value={form.rule_name}
              onChange={(event) => setForm((current) => ({ ...current, rule_name: event.target.value }))}
              placeholder="例如:logs-dr"
            />
          </Field>
          <Field label="目标站点" htmlFor="rule-target-site">
            <Input
              id="rule-target-site"
              size="sm"
              required
              value={form.target_site}
              onChange={(event) => setForm((current) => ({ ...current, target_site: event.target.value }))}
            />
          </Field>
          <Field label="站点端点" htmlFor="rule-endpoint">
            <Input
              id="rule-endpoint"
              size="sm"
              value={form.endpoint}
              onChange={(event) => setForm((current) => ({ ...current, endpoint: event.target.value }))}
              placeholder="https://dr-site-a.example.internal"
            />
          </Field>
          <Field label="前缀过滤" htmlFor="rule-prefix">
            <Input
              id="rule-prefix"
              size="sm"
              value={form.prefix}
              onChange={(event) => setForm((current) => ({ ...current, prefix: event.target.value }))}
              placeholder="logs/"
            />
          </Field>
          <Field label="优先级" htmlFor="rule-priority">
            <Input
              id="rule-priority"
              size="sm"
              type="number"
              min={0}
              max={1000}
              value={form.priority}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  priority: Number.parseInt(event.target.value || '100', 10)
                }))
              }
            />
          </Field>
          <label className="flex items-center gap-2 text-sm text-muted md:mt-7">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))}
            />
            启用复制
          </label>
          <label className="flex items-center gap-2 text-sm text-muted md:mt-7">
            <input
              type="checkbox"
              checked={form.replicate_existing}
              onChange={(event) =>
                setForm((current) => ({ ...current, replicate_existing: event.target.checked }))
              }
            />
            追平已有对象
          </label>
          <label className="flex items-center gap-2 text-sm text-muted md:mt-7">
            <input
              type="checkbox"
              checked={form.sync_deletes}
              onChange={(event) =>
                setForm((current) => ({ ...current, sync_deletes: event.target.checked }))
              }
            />
            同步删除操作
          </label>
          <div className="md:col-span-4">
            <Button type="submit" loading={saving} disabled={saving || !form.source_bucket}>
              {saving ? '保存中...' : '保存复制规则'}
            </Button>
          </div>
        </form>
      </Card>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <SectionTitle>站点容灾（Site Replication）</SectionTitle>
            <p className="mt-1 text-sm text-muted">主从站点状态、复制延迟、漂移收敛与切换操作。</p>
          </div>
        </div>

        <div className="mt-4 space-y-3">
          {sortedSites.length === 0 ? (
            <Panel className="text-sm text-muted">当前未配置站点复制拓扑。</Panel>
          ) : (
            sortedSites.map((site) => {
              const switchJob = switchJobBySite[site.site_id];
              const switchPending = Boolean(switchJob && !switchJob.terminal);
              const driftLoading = driftLoadingSite === site.site_id;
              return (
                <Panel key={site.site_id}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="flex items-center gap-2 font-medium text-on-surface">
                        {site.site_id}
                        {site.preferred_primary ? <Badge tone="primary">首选主站</Badge> : null}
                      </p>
                      <p className="mt-1 text-xs text-muted">{site.endpoint}</p>
                    </div>
                    <div className="flex flex-col items-end gap-1 text-xs text-muted">
                      <span>
                        角色:<span className="text-on-surface">{siteRoleText(site.role)}</span>
                      </span>
                      <Badge tone={siteStateTone(site.state)}>{siteStateText(site.state)}</Badge>
                    </div>
                  </div>

                  <p className="mt-2 text-xs text-muted">
                    延迟:{site.lag_seconds} 秒 · 托管桶:{site.managed_buckets} · 最近同步:
                    {formatTime(site.last_sync_at)}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    待处理:{siteMetricsById[site.site_id]?.backlog_pending ?? 0} · 失败:
                    {siteMetricsById[site.site_id]?.backlog_failed ?? 0} · 死信:
                    {siteMetricsById[site.site_id]?.backlog_dead_letter ?? 0} · SLA:
                    {siteMetricsById[site.site_id]?.backlog_sla_status ?? 'unknown'}
                  </p>

                  <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted">
                    <Chip>引导:{bootstrapStateText(site.bootstrap_state)}</Chip>
                    <Chip>拓扑版本 {site.topology_version}</Chip>
                    <Chip>漂移桶 {site.drifted_buckets}</Chip>
                    <Chip>待重同步 {site.pending_resync_items}</Chip>
                  </div>
                  <p className="mt-2 text-xs text-muted">
                    最近重同步:{formatTime(site.last_resync_at)} · 最近收敛:
                    {formatTime(site.last_reconcile_at)}
                  </p>

                  {site.last_error ? (
                    <p className="mt-2 text-xs text-error">错误:{toBilingualPrompt(site.last_error)}</p>
                  ) : null}

                  {switchJob ? (
                    <div className="mt-3 rounded-md border border-outline/40 bg-surface-container p-2">
                      <p className="flex flex-wrap items-center gap-2 text-xs text-muted">
                        切换任务:{switchJob.kind === 'failback' ? 'Failback' : 'Failover'}
                        <Badge tone={switchJobStatusTone(switchJob.status)}>
                          {switchJobStatusText(switchJob.status)}
                        </Badge>
                        · 尝试 {switchJob.attempt}
                      </p>
                      <ProgressBar
                        className="mt-2"
                        ratio={Math.max(0.04, switchJob.progress)}
                        tone={switchJob.status === 'failed' || switchJob.status === 'dead_letter' ? 'error' : 'primary'}
                      />
                      {switchJob.last_error ? (
                        <p className="mt-2 text-xs text-error">
                          任务错误:{toBilingualPrompt(switchJob.last_error)}
                        </p>
                      ) : null}
                    </div>
                  ) : null}

                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      loading={driftLoading}
                      onClick={() =>
                        openDrift(site.site_id, `站点 ${site.site_id} 漂移报告`, () =>
                          replicationService.siteDrift(client, site.site_id)
                        )
                      }
                    >
                      查看漂移
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      loading={driftLoading}
                      onClick={() =>
                        openDrift(site.site_id, `站点 ${site.site_id} 收敛预检`, () =>
                          replicationService.reconcilePreview(client, site.site_id)
                        )
                      }
                    >
                      收敛预检
                    </Button>
                    <ConfirmActionDialog
                      title={`重同步站点 ${site.site_id}`}
                      description="将该站点重新同步至期望拓扑,用于追平漂移与缺失对象。"
                      actionLabel="重同步"
                      onConfirm={async (reason) => {
                        setSwitchingSiteAction(`resync:${site.site_id}`);
                        setError('');
                        setMessage('');
                        try {
                          await replicationService.resyncSite(client, site.site_id, reason);
                          setMessage(`站点 ${site.site_id} 的重同步任务已创建`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '重同步失败');
                          throw requestError;
                        } finally {
                          setSwitchingSiteAction('');
                        }
                      }}
                    />
                    <ConfirmActionDialog
                      title={`收敛站点 ${site.site_id}`}
                      description="按收敛预检的建议动作对齐站点拓扑,可能删除非预期的桶根目录,请先查看收敛预检。"
                      actionLabel="执行收敛"
                      onConfirm={async (reason) => {
                        setSwitchingSiteAction(`reconcile:${site.site_id}`);
                        setError('');
                        setMessage('');
                        try {
                          await replicationService.reconcileSite(client, site.site_id, reason);
                          setMessage(`站点 ${site.site_id} 的收敛任务已创建`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '执行收敛失败');
                          throw requestError;
                        } finally {
                          setSwitchingSiteAction('');
                        }
                      }}
                    />
                    {site.role !== 'primary' && !switchPending ? (
                      <ConfirmActionDialog
                        title={`Failover 到站点 ${site.site_id}`}
                        description="将该站点提升为主站,可能影响跨站写入路由。"
                        actionLabel="执行 Failover"
                        onConfirm={async (reason) => {
                          setSwitchingSiteAction(`failover:${site.site_id}`);
                          setError('');
                          setMessage('');
                          try {
                            await replicationService.failoverSite(client, site.site_id, reason);
                            setMessage(`站点 ${site.site_id} 的 Failover 任务已创建`);
                            await reload();
                          } catch (requestError) {
                            setError(requestError instanceof Error ? requestError.message : '执行 Failover 失败');
                            throw requestError;
                          } finally {
                            setSwitchingSiteAction('');
                          }
                        }}
                      />
                    ) : null}
                    {site.role !== 'primary' && site.preferred_primary && !switchPending ? (
                      <ConfirmActionDialog
                        title={`Failback 到站点 ${site.site_id}`}
                        description="将业务主站切回首选主站,建议在复制延迟收敛后执行。"
                        actionLabel="执行 Failback"
                        onConfirm={async (reason) => {
                          setSwitchingSiteAction(`failback:${site.site_id}`);
                          setError('');
                          setMessage('');
                          try {
                            await replicationService.failbackSite(client, site.site_id, reason);
                            setMessage(`站点 ${site.site_id} 的 Failback 任务已创建`);
                            await reload();
                          } catch (requestError) {
                            setError(requestError instanceof Error ? requestError.message : '执行 Failback 失败');
                            throw requestError;
                          } finally {
                            setSwitchingSiteAction('');
                          }
                        }}
                      />
                    ) : null}
                    {switchingSiteAction.endsWith(`:${site.site_id}`) || switchPending ? (
                      <Badge tone="warning">{switchPending ? '切换任务处理中...' : '提交中...'}</Badge>
                    ) : null}
                  </div>
                </Panel>
              );
            })
          )}
        </div>
      </Card>

      <div className="space-y-3">
        {sortedRules.map((rule) => (
          <Card key={rule.rule_id} className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-on-surface">{rule.rule_name || rule.source_bucket}</p>
                <p className="mt-1 text-xs text-muted">源桶:{rule.source_bucket}</p>
              </div>
              <Badge tone={rule.status === 'healthy' ? 'success' : 'warning'}>
                {replicationStatusText(rule.status)}
              </Badge>
            </div>
            <p className="mt-1 text-sm text-muted">目标站点:{rule.target_site}</p>
            <p className="mt-1 text-xs text-muted">
              端点:{rule.endpoint || '自动推断'} · 前缀:{rule.prefix || '全部对象'} · 优先级:{rule.priority}
            </p>
            <p className="mt-1 text-xs text-muted">
              追平已有对象:{rule.replicate_existing ? '开启' : '关闭'} · 同步删除:
              {rule.sync_deletes ? '开启' : '关闭'}
            </p>
            <p className="mt-1 text-xs text-muted">复制延迟:{rule.lag_seconds} 秒</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() =>
                  setForm({
                    rule_id: rule.rule_id,
                    source_bucket: rule.source_bucket,
                    rule_name: rule.rule_name ?? '',
                    target_site: rule.target_site,
                    endpoint: rule.endpoint ?? '',
                    prefix: rule.prefix ?? '',
                    priority: rule.priority,
                    replicate_existing: rule.replicate_existing,
                    sync_deletes: rule.sync_deletes,
                    enabled: rule.status === 'healthy'
                  })
                }
              >
                编辑规则
              </Button>
              <Button
                variant="secondary"
                size="sm"
                loading={updatingRule === rule.rule_id}
                disabled={updatingRule === rule.rule_id}
                onClick={async () => {
                  setUpdatingRule(rule.rule_id);
                  setError('');
                  setMessage('');
                  try {
                    await bucketService.updateReplication(client, rule.source_bucket, {
                      rule_id: rule.rule_id,
                      rule_name: rule.rule_name ?? undefined,
                      target_site: rule.target_site,
                      endpoint: rule.endpoint ?? undefined,
                      prefix: rule.prefix ?? undefined,
                      priority: rule.priority,
                      replicate_existing: rule.replicate_existing,
                      sync_deletes: rule.sync_deletes,
                      enabled: rule.status !== 'healthy'
                    });
                    setMessage(
                      `复制规则 ${rule.rule_name || rule.source_bucket} 已${rule.status === 'healthy' ? '暂停' : '启用'}`
                    );
                    await reload();
                  } catch (requestError) {
                    setError(requestError instanceof Error ? requestError.message : '更新复制状态失败');
                  } finally {
                    setUpdatingRule('');
                  }
                }}
              >
                {updatingRule === rule.rule_id
                  ? '处理中...'
                  : rule.status === 'healthy'
                    ? '暂停复制'
                    : '启用复制'}
              </Button>
              <Button
                variant="danger"
                size="sm"
                loading={deletingRule === rule.rule_id}
                disabled={deletingRule === rule.rule_id}
                onClick={async () => {
                  if (!await confirm(`确认删除复制规则 ${rule.rule_name || rule.source_bucket}?`)) {
                    return;
                  }
                  setDeletingRule(rule.rule_id);
                  setError('');
                  setMessage('');
                  try {
                    await bucketService.deleteReplication(client, rule.source_bucket, rule.rule_id);
                    setMessage(`复制规则 ${rule.rule_name || rule.source_bucket} 已删除`);
                    if (form.rule_id === rule.rule_id) {
                      resetRuleForm();
                    }
                    await reload();
                  } catch (requestError) {
                    setError(requestError instanceof Error ? requestError.message : '删除复制规则失败');
                  } finally {
                    setDeletingRule('');
                  }
                }}
              >
                {deletingRule === rule.rule_id ? '删除中...' : '删除规则'}
              </Button>
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <SectionTitle>失败重试队列</SectionTitle>
            <p className="mt-1 text-sm text-muted">复制失败/待补偿对象积压列表。</p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={async () => {
                setError('');
                try {
                  await reload();
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '刷新积压队列失败');
                }
              }}
            >
              刷新队列
            </Button>
            <Button
              size="sm"
              loading={retryingAllBacklog}
              disabled={retryingAllBacklog || backlog.length === 0}
              onClick={async () => {
                if (!await confirm('确认重试全部复制积压项?')) return;
                setRetryingAllBacklog(true);
                setError('');
                setMessage('');
                try {
                  const result = await jobsService.retryAsyncJobs(client, { kind: 'replication' });
                  setMessage(`已触发全部重试,处理 ${result.updated} 条复制任务`);
                  await reload();
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '重试全部积压失败');
                } finally {
                  setRetryingAllBacklog(false);
                }
              }}
            >
              {retryingAllBacklog ? '处理中...' : '重试全部'}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              loading={cleaningDoneBacklog}
              disabled={cleaningDoneBacklog}
              onClick={async () => {
                setCleaningDoneBacklog(true);
                setError('');
                setMessage('');
                try {
                  const result = await jobsService.cleanupAsyncJobs(client, {
                    kind: 'replication',
                    status: 'done'
                  });
                  setMessage(`已清理 ${result.removed} 条复制终态任务`);
                  await reload();
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '清理复制终态任务失败');
                } finally {
                  setCleaningDoneBacklog(false);
                }
              }}
            >
              {cleaningDoneBacklog ? '处理中...' : '清理已完成'}
            </Button>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          {sortedBacklog.length === 0 ? (
            <Panel className="text-sm text-muted">当前无复制积压项。</Panel>
          ) : (
            sortedBacklog.map((item) => (
              <Panel key={item.id}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="text-sm font-medium text-on-surface">
                      {item.source_bucket} → {item.target_site}
                    </p>
                    <p className="mt-1 font-mono text-xs text-primary">{item.object_key}</p>
                  </div>
                  <Badge tone={backlogStatusTone(item.status)}>{backlogStatusText(item.status)}</Badge>
                </div>
                <p className="mt-2 text-xs text-muted">错误:{toBilingualPrompt(item.last_error)}</p>
                <p className="mt-1 text-xs text-muted">
                  尝试次数:{item.attempts} · 入队时间:{formatTime(item.queued_at)}
                </p>
                <div className="mt-3">
                  <Button
                    variant="secondary"
                    size="sm"
                    loading={retryingBacklogId === item.id}
                    disabled={retryingBacklogId === item.id}
                    onClick={async () => {
                      setRetryingBacklogId(item.id);
                      setError('');
                      setMessage('');
                      try {
                        await jobsService.retryAsyncJobs(client, {}, [item.id]);
                        setMessage(`积压项 ${item.id} 已触发重试`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '重试积压项失败');
                      } finally {
                        setRetryingBacklogId('');
                      }
                    }}
                  >
                    {retryingBacklogId === item.id ? '重试中...' : '重试该项'}
                  </Button>
                </div>
              </Panel>
            ))
          )}
        </div>
      </Card>

      <Dialog
        open={Boolean(driftReport)}
        onClose={() => setDriftReport(null)}
        title={driftTitle}
        description={driftReport ? `生成于 ${formatTime(driftReport.generated_at)} · 模式 ${driftReport.mode}` : undefined}
        className="max-w-2xl"
        footer={
          <Button variant="tertiary" onClick={() => setDriftReport(null)}>
            关闭
          </Button>
        }
      >
        {driftReport ? (
          <div className="max-h-[60vh] space-y-4 overflow-y-auto text-sm">
            <div>
              <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted">
                收敛护栏
                <Badge tone={driftReport.guardrails.safe_to_reconcile ? 'success' : 'warning'}>
                  {driftReport.guardrails.safe_to_reconcile ? '可安全收敛' : '需确认'}
                </Badge>
              </p>
              {driftReport.guardrails.blocking_reason_messages.length > 0 ? (
                <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-error">
                  {driftReport.guardrails.blocking_reason_messages.map((reason) => (
                    <li key={reason}>{toBilingualPrompt(reason)}</li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-xs text-muted">无阻塞原因。</p>
              )}
            </div>

            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-muted">建议动作</p>
              {driftReport.suggested_actions.length > 0 ? (
                <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-muted">
                  {driftReport.suggested_actions.map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-xs text-muted">暂无建议动作。</p>
              )}
            </div>

            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-muted">
                漂移桶（{driftReport.buckets.length}）
              </p>
              {driftReport.buckets.length > 0 ? (
                <div className="mt-2 space-y-1.5">
                  {driftReport.buckets.map((bucket) => (
                    <div
                      key={bucket.bucket}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-outline/40 bg-surface-container px-2.5 py-1.5"
                    >
                      <span className="font-mono text-xs text-on-surface">{bucket.bucket}</span>
                      <span className="text-xs text-muted">
                        <Badge tone="warning">{bucket.state}</Badge>
                        <span className="ml-2">
                          待处理 {bucket.pending_backlog} · 失败 {bucket.failed_backlog}
                        </span>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-1 text-xs text-muted">无漂移桶。</p>
              )}
            </div>

            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-muted">
                受影响规则（{driftReport.rules.length}）
              </p>
              {driftReport.rules.length > 0 ? (
                <div className="mt-2 space-y-1.5">
                  {driftReport.rules.map((rule) => (
                    <div
                      key={rule.rule_id}
                      className="rounded-md border border-outline/40 bg-surface-container px-2.5 py-1.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs text-on-surface">
                          {rule.rule_name || rule.source_bucket}
                        </span>
                        <Badge tone={rule.status === 'healthy' ? 'success' : 'warning'}>{rule.status}</Badge>
                      </div>
                      {rule.drift_reasons.length > 0 ? (
                        <p className="mt-1 text-xs text-muted">{rule.drift_reasons.join(' · ')}</p>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-1 text-xs text-muted">无受影响规则。</p>
              )}
            </div>
          </div>
        ) : null}
      </Dialog>
    </section>
  );
}
