import { useEffect, useMemo, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { bucketService, jobsService, systemService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { StatCard } from '../components/StatCard';
import type {
  AsyncJobStatus,
  AsyncJobSummary,
  BucketSpec,
  ReplicationBacklogItem,
  ReplicationStatus,
  SiteReplicationStatus,
  SystemMetricsSummary
} from '../types';

type ReplicationPageProps = {
  client: ApiClient;
};

export function ReplicationPage({ client }: ReplicationPageProps) {
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
      bucketService.siteReplications(client),
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

  function switchJobStatusText(status: string) {
    if (status === 'pending') return '排队中';
    if (status === 'in_progress') return '执行中';
    if (status === 'failed') return '失败';
    if (status === 'dead_letter') return '死信';
    if (status === 'completed' || status === 'done' || status === 'success') return '已完成';
    if (status === 'skipped') return '已跳过';
    return status;
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
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h1 className="font-heading text-2xl text-white">复制</h1>
        <p className="mt-1 text-sm text-slate-300">跨站复制链路状态、规则配置与失败重试队列。</p>
        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}

        <div className="mt-4 grid gap-4 md:grid-cols-4">
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
            helper={
              replicationSummary ? `可重试 ${replicationSummary.retryable}` : '统一失败口径'
            }
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

        <form
          className="mt-4 grid gap-3 rounded-xl border border-white/10 bg-black/10 p-4 md:grid-cols-4"
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
              await reload();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '保存复制规则失败');
            } finally {
              setSaving(false);
            }
          }}
        >
          <div className="md:col-span-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-white">
                {form.rule_id ? '编辑复制规则' : '新增复制规则'}
              </p>
              <p className="text-xs text-slate-400">
                支持规则名、端点、前缀、优先级、已有对象追平与删除同步控制。
              </p>
            </div>
            {form.rule_id ? (
              <button
                type="button"
                className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
                onClick={() =>
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
                  }))
                }
              >
                取消编辑
              </button>
            ) : null}
          </div>
          <label className="text-sm text-slate-300">
            源桶
            <select
              required
              value={form.source_bucket}
              onChange={(event) => setForm((current) => ({ ...current, source_bucket: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            >
              {buckets.length === 0 ? <option value="">无可用桶</option> : null}
              {buckets.map((bucket) => (
                <option key={bucket.name} value={bucket.name}>
                  {bucket.name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm text-slate-300">
            规则名称
            <input
              value={form.rule_name}
              onChange={(event) => setForm((current) => ({ ...current, rule_name: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="例如：logs-dr"
            />
          </label>
          <label className="text-sm text-slate-300">
            目标站点
            <input
              required
              value={form.target_site}
              onChange={(event) => setForm((current) => ({ ...current, target_site: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            />
          </label>
          <label className="text-sm text-slate-300">
            站点端点
            <input
              value={form.endpoint}
              onChange={(event) => setForm((current) => ({ ...current, endpoint: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="https://dr-site-a.example.internal"
            />
          </label>
          <label className="text-sm text-slate-300">
            前缀过滤
            <input
              value={form.prefix}
              onChange={(event) => setForm((current) => ({ ...current, prefix: event.target.value }))}
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="logs/"
            />
          </label>
          <label className="text-sm text-slate-300">
            优先级
            <input
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
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300 md:mt-8">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))}
            />
            启用复制
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300 md:mt-8">
            <input
              type="checkbox"
              checked={form.replicate_existing}
              onChange={(event) =>
                setForm((current) => ({ ...current, replicate_existing: event.target.checked }))
              }
            />
            追平已有对象
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300 md:mt-8">
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
            <button
              type="submit"
              disabled={saving || !form.source_bucket}
              className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
            >
              {saving ? '保存中...' : '保存复制规则'}
            </button>
          </div>
        </form>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-heading text-xl text-white">站点容灾（Site Replication）</h2>
            <p className="mt-1 text-sm text-slate-300">主从站点状态、复制延迟与 Failover/Failback 操作。</p>
          </div>
        </div>

        <div className="mt-4 space-y-3">
          {sortedSites.length === 0 ? (
            <p className="rounded-md border border-white/10 bg-black/10 px-3 py-4 text-sm text-slate-400">
              当前未配置站点复制拓扑。
            </p>
          ) : (
            sortedSites.map((site) => (
              <article key={site.site_id} className="rounded-lg border border-white/10 bg-black/10 p-3">
                {(() => {
                  const switchJob = switchJobBySite[site.site_id];
                  const switchPending = Boolean(switchJob && !switchJob.terminal);
                  return (
                    <>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="font-medium text-white">
                      {site.site_id}
                      {site.preferred_primary ? (
                        <span className="ml-2 rounded bg-signal-500/15 px-2 py-0.5 text-xs text-signal-500">
                          首选主站
                        </span>
                      ) : null}
                    </p>
                    <p className="mt-1 text-xs text-slate-400">{site.endpoint}</p>
                  </div>
                  <div className="text-right text-xs text-slate-300">
                    <p>
                      角色：<span className="text-white">{siteRoleText(site.role)}</span>
                    </p>
                    <p className="mt-1">
                      状态：
                      <span
                        className={`ml-1 ${
                          site.state === 'healthy'
                            ? 'text-signal-500'
                            : site.state === 'degraded'
                              ? 'text-amber-300'
                              : 'text-rose-300'
                        }`}
                      >
                        {siteStateText(site.state)}
                      </span>
                    </p>
                  </div>
                </div>
                <p className="mt-2 text-xs text-slate-400">
                  延迟：{site.lag_seconds} 秒 · 托管桶：{site.managed_buckets} · 最近同步：
                  {new Date(site.last_sync_at).toLocaleString()}
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  待处理：{siteMetricsById[site.site_id]?.backlog_pending ?? 0} · 失败：
                  {siteMetricsById[site.site_id]?.backlog_failed ?? 0} · 死信：
                  {siteMetricsById[site.site_id]?.backlog_dead_letter ?? 0} · SLA：
                  {siteMetricsById[site.site_id]?.backlog_sla_status ?? 'unknown'}
                </p>
                {site.last_error ? (
                  <p className="mt-1 text-xs text-rose-300">错误：{toBilingualPrompt(site.last_error)}</p>
                ) : null}
                {switchJob ? (
                  <div className="mt-2 rounded-md border border-white/10 bg-white/5 p-2">
                    <p className="text-xs text-slate-300">
                      切换任务：{switchJob.kind === 'failback' ? 'Failback' : 'Failover'} · {switchJobStatusText(switchJob.status)} ·
                      尝试 {switchJob.attempt}
                    </p>
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                      <div className="h-full bg-signal-500" style={{ width: `${Math.max(4, switchJob.progress * 100)}%` }} />
                    </div>
                    {switchJob.last_error ? (
                      <p className="mt-2 text-xs text-rose-300">任务错误：{toBilingualPrompt(switchJob.last_error)}</p>
                    ) : null}
                  </div>
                ) : null}
                <div className="mt-3 flex flex-wrap gap-2">
                  {site.role !== 'primary' && !switchPending ? (
                    <ConfirmActionDialog
                      title={`Failover 到站点 ${site.site_id}`}
                      description="将该站点提升为主站，可能影响跨站写入路由。"
                      actionLabel="执行 Failover"
                      onConfirm={async (reason) => {
                        setSwitchingSiteAction(`failover:${site.site_id}`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.failoverSite(client, site.site_id, reason);
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
                      description="将业务主站切回首选主站，建议在复制延迟收敛后执行。"
                      actionLabel="执行 Failback"
                      onConfirm={async (reason) => {
                        setSwitchingSiteAction(`failback:${site.site_id}`);
                        setError('');
                        setMessage('');
                        try {
                          await bucketService.failbackSite(client, site.site_id, reason);
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
                  {switchingSiteAction === `failover:${site.site_id}` ||
                  switchingSiteAction === `failback:${site.site_id}` ||
                  switchPending ? (
                    <span className="inline-flex items-center rounded border border-white/10 px-2 py-1 text-xs text-slate-300">
                      {switchPending ? '切换任务处理中...' : '提交中...'}
                    </span>
                  ) : null}
                </div>
                    </>
                  );
                })()}
              </article>
            ))
          )}
        </div>
      </article>

      <div className="space-y-3">
        {sortedRules.map((rule) => (
          <article key={rule.rule_id} className="rounded-lg border border-white/10 bg-ink-800/70 p-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-white">{rule.rule_name || rule.source_bucket}</p>
                <p className="mt-1 text-xs text-slate-400">源桶：{rule.source_bucket}</p>
              </div>
              <span className={`text-sm ${rule.status === 'healthy' ? 'text-signal-500' : 'text-amber-400'}`}>
                {replicationStatusText(rule.status)}
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-300">目标站点：{rule.target_site}</p>
            <p className="mt-1 text-xs text-slate-400">
              端点：{rule.endpoint || '自动推断'} · 前缀：{rule.prefix || '全部对象'} · 优先级：{rule.priority}
            </p>
            <p className="mt-1 text-xs text-slate-400">
              追平已有对象：{rule.replicate_existing ? '开启' : '关闭'} · 同步删除：{rule.sync_deletes ? '开启' : '关闭'}
            </p>
            <p className="mt-1 text-xs text-slate-400">复制延迟：{rule.lag_seconds} 秒</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
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
              </button>
              <button
                className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
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
              </button>
              <button
                className="h-10 rounded-md border border-rose-500/30 px-3 text-sm text-rose-200 hover:bg-rose-500/10 disabled:opacity-60"
                disabled={deletingRule === rule.rule_id}
                onClick={async () => {
                  if (!window.confirm(`确认删除复制规则 ${rule.rule_name || rule.source_bucket}？`)) {
                    return;
                  }
                  setDeletingRule(rule.rule_id);
                  setError('');
                  setMessage('');
                  try {
                    await bucketService.deleteReplication(client, rule.source_bucket, rule.rule_id);
                    setMessage(`复制规则 ${rule.rule_name || rule.source_bucket} 已删除`);
                    if (form.rule_id === rule.rule_id) {
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
                    await reload();
                  } catch (requestError) {
                    setError(requestError instanceof Error ? requestError.message : '删除复制规则失败');
                  } finally {
                    setDeletingRule('');
                  }
                }}
              >
                {deletingRule === rule.rule_id ? '删除中...' : '删除规则'}
              </button>
            </div>
          </article>
        ))}
      </div>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-heading text-xl text-white">失败重试队列</h2>
            <p className="mt-1 text-sm text-slate-300">复制失败/待补偿对象积压列表。</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
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
            </button>
            <button
              className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white disabled:opacity-60"
              disabled={retryingAllBacklog || backlog.length === 0}
              onClick={async () => {
                if (!window.confirm('确认重试全部复制积压项？')) return;
                setRetryingAllBacklog(true);
                setError('');
                setMessage('');
                try {
                  const result = await jobsService.retryAsyncJobs(client, { kind: 'replication' });
                  setMessage(`已触发全部重试，处理 ${result.updated} 条复制任务`);
                  await reload();
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '重试全部积压失败');
                } finally {
                  setRetryingAllBacklog(false);
                }
              }}
            >
              {retryingAllBacklog ? '处理中...' : '重试全部'}
            </button>
            <button
              className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
              disabled={cleaningDoneBacklog}
              onClick={async () => {
                setCleaningDoneBacklog(true);
                setError('');
                setMessage('');
                try {
                  const result = await jobsService.cleanupAsyncJobs(client, { kind: 'replication', status: 'done' });
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
            </button>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          {sortedBacklog.length === 0 ? (
            <p className="rounded-md border border-white/10 bg-black/10 px-3 py-4 text-sm text-slate-400">
              当前无复制积压项。
            </p>
          ) : (
            sortedBacklog.map((item) => (
              <article key={item.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="text-sm font-medium text-white">
                      {item.source_bucket} → {item.target_site}
                    </p>
                    <p className="mt-1 font-mono text-xs text-signal-500">{item.object_key}</p>
                  </div>
                  <span className="text-xs text-amber-300">{backlogStatusText(item.status)}</span>
                </div>
                <p className="mt-2 text-xs text-slate-400">
                  错误：{toBilingualPrompt(item.last_error)}
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  尝试次数：{item.attempts} · 入队时间：{new Date(item.queued_at).toLocaleString()}
                </p>
                <div className="mt-3">
                  <button
                    className="h-9 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5 disabled:opacity-60"
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
                  </button>
                </div>
              </article>
            ))
          )}
        </div>
      </article>
    </section>
  );
}
