import { useEffect, useState } from 'react';
import { toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { clusterService, systemService } from '../api/services';
import { useEventStream } from '../hooks/useEventStream';
import { StatCard } from '../components/StatCard';
import type { ClusterHealth, ClusterNode, ClusterQuota, SystemMetricsSummary } from '../types';

type DashboardPageProps = {
  client: ApiClient;
  token: string;
};

function clusterStatusText(status?: string) {
  if (!status) return '加载中';
  if (status === 'healthy') return '健康';
  if (status === 'degraded') return '降级';
  if (status === 'critical') return '严重异常';
  return `未知(${status})`;
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const sized = value / 1024 ** exponent;
  return `${sized.toFixed(sized >= 100 ? 0 : sized >= 10 ? 1 : 2)} ${units[exponent]}`;
}

export function DashboardPage({ client, token }: DashboardPageProps) {
  const [health, setHealth] = useState<ClusterHealth | null>(null);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [nodes, setNodes] = useState<ClusterNode[]>([]);
  const [quotas, setQuotas] = useState<ClusterQuota[]>([]);
  const [error, setError] = useState('');
  const events = useEventStream(token);

  useEffect(() => {
    Promise.all([
      clusterService.health(client),
      systemService.metricsSummary(client),
      clusterService.nodes(client),
      clusterService.quotas(client)
    ])
      .then(([healthSnapshot, metricsSummary, nodesSnapshot, quotaSnapshot]) => {
        setHealth(healthSnapshot);
        setSummary(metricsSummary);
        setNodes(nodesSnapshot);
        setQuotas(quotaSnapshot);
      })
      .catch((requestError) => {
        setError(requestError instanceof Error ? requestError.message : '加载集群总览失败');
      });
  }, [client]);

  return (
    <section className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="集群状态"
          value={clusterStatusText(summary?.cluster_status ?? health?.status)}
          helper={`节点 ${summary ? `${summary.nodes.online}/${summary.nodes.total}` : '--'} · 事件 ${events.length}`}
        />
        <StatCard
          label="异步待处理"
          value={summary ? String(summary.jobs.async_pending) : '...'}
          helper={
            summary
              ? `执行中 ${summary.jobs.async_in_progress} / 可重试 ${summary.jobs.async_retryable}`
              : '统一任务平面'
          }
        />
        <StatCard
          label="复制积压"
          value={summary ? String(summary.replication.backlog_total) : '...'}
          helper={
            summary
              ? `失败 ${summary.replication.backlog_failed} / 死信 ${summary.replication.backlog_dead_letter}`
              : '跨站复制摘要'
          }
        />
        <StatCard
          label="KMS 风险"
          value={
            summary
              ? summary.kms.healthy
                ? summary.kms.rotation_failed > 0
                  ? '需重试'
                  : '正常'
                : '异常'
              : '...'
          }
          helper={
            summary ? `轮换 ${summary.kms.rotation_status} / 失败 ${summary.kms.rotation_failed}` : 'KMS 健康与轮换'
          }
        />
        <StatCard
          label="审计异常"
          value={summary ? String(summary.audit.failed_outcomes_total) : '...'}
          helper={summary ? `总事件 ${summary.audit.events_total}` : '审计链路'}
        />
        <StatCard
          label="会话提醒"
          value={
            summary
              ? String(summary.sessions.admin_sessions_expiring_24h + summary.sessions.sts_sessions_expiring_24h)
              : '...'
          }
          helper={
            summary
              ? `控制台 ${summary.sessions.admin_sessions_expiring_24h} / STS ${summary.sessions.sts_sessions_expiring_24h}`
              : '24 小时内到期'
          }
        />
      </div>

      {error ? <p className="rounded-md bg-rose-500/15 p-3 text-sm text-rose-300">{toBilingualPrompt(error)}</p> : null}

      {summary ? (
        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">控制面风险摘要</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">告警链路</p>
              <p className="mt-2 text-white">活跃告警 {summary.alerts.firing_alerts}</p>
              <p className="mt-1">投递失败 {summary.alerts.delivery_failed} / 执行中 {summary.alerts.delivery_in_progress}</p>
            </div>
            <div className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">KMS</p>
              <p className="mt-2 text-white">{summary.kms.healthy ? '健康' : '异常'} / {summary.kms.rotation_status}</p>
              <p className="mt-1">最近失败 {summary.kms.rotation_failed} 个</p>
            </div>
            <div className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">IAM / 会话</p>
              <p className="mt-2 text-white">用户 {summary.iam.users_enabled}/{summary.iam.users_total}</p>
              <p className="mt-1">活跃会话 {summary.sessions.admin_sessions_active + summary.sessions.sts_sessions_active}</p>
            </div>
            <div className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">复制 / 审计</p>
              <p className="mt-2 text-white">失败 backlog {summary.replication.backlog_failed}</p>
              <p className="mt-1">审计失败 {summary.audit.failed_outcomes_total}</p>
            </div>
          </div>
        </article>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-heading text-xl text-white">统一任务摘要</h2>
            <span className="text-xs text-slate-400">
              {summary ? new Date(summary.generated_at).toLocaleString() : '加载中...'}
            </span>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm text-slate-300">
              <p>Pending：{summary?.jobs.async_pending ?? '--'}</p>
              <p className="mt-1">In-progress：{summary?.jobs.async_in_progress ?? '--'}</p>
              <p className="mt-1">Completed：{summary?.jobs.async_completed ?? '--'}</p>
              <p className="mt-1">Failed：{summary?.jobs.async_failed ?? '--'}</p>
            </div>
            <div className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm text-slate-300">
              <p>复制站点：{summary?.replication.sites_total ?? '--'}</p>
              <p className="mt-1">健康站点：{summary?.replication.sites_healthy ?? '--'}</p>
              <p className="mt-1">最大延迟：{summary?.replication.max_lag_seconds ?? '--'} 秒</p>
              <p className="mt-1">告警站点：{summary?.replication.backlog_sla_firing_sites ?? '--'}</p>
            </div>
          </div>
        </article>

        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">实时控制事件</h2>
          <ul className="mt-3 max-h-72 space-y-2 overflow-auto pr-1">
            {events.map((event, index) => (
              <li key={`${event.topic}-${event.timestamp}-${index}`} className="rounded-lg border border-white/5 bg-black/10 p-3 text-sm">
                <p className="font-mono text-xs text-signal-500">{event.topic}</p>
                <p className="mt-1 text-slate-200">{event.source}</p>
                <p className="mt-1 text-xs text-slate-400">{new Date(event.timestamp).toLocaleString()}</p>
              </li>
            ))}
          </ul>
        </article>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">节点健康</h2>
          <div className="mt-3 space-y-2">
            {nodes.map((node) => (
              <div key={node.id} className="flex items-center justify-between rounded-lg border border-white/5 bg-black/10 p-3">
                <div>
                  <p className="font-medium text-white">{node.hostname}</p>
                  <p className="text-xs text-slate-400">{node.zone}</p>
                </div>
                <span className={`text-sm ${node.online ? 'text-signal-500' : 'text-rose-400'}`}>
                  {node.online ? '在线' : '离线'}
                </span>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">租户配额</h2>
          <div className="mt-3 space-y-3">
            {quotas.map((quota) => {
              const ratio = quota.hard_limit_bytes > 0 ? quota.used_bytes / quota.hard_limit_bytes : 0;
              const percent = Math.max(0, Math.min(100, ratio * 100));
              return (
                <div key={quota.tenant} className="rounded-lg border border-white/5 bg-black/10 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-medium text-white">{quota.tenant}</p>
                    <p className="text-xs text-slate-300">{percent.toFixed(1)}%</p>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    已用 {formatBytes(quota.used_bytes)} / 配额 {formatBytes(quota.hard_limit_bytes)}
                  </p>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/10">
                    <div
                      className={`h-full ${
                        percent >= 90 ? 'bg-rose-500' : percent >= 75 ? 'bg-amber-400' : 'bg-signal-500'
                      }`}
                      style={{ width: `${percent}%` }}
                    />
                  </div>
                </div>
              );
            })}
            {quotas.length === 0 ? <p className="text-sm text-slate-400">暂无租户配额数据</p> : null}
          </div>
        </article>
      </div>
    </section>
  );
}
