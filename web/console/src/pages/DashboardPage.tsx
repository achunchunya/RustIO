import { useEffect, useState } from 'react';
import { toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { clusterService, systemService } from '../api/services';
import { useEventStream } from '../hooks/useEventStream';
import { useMetricsHistory } from '../hooks/useMetricsHistory';
import { StatCard } from '../components/StatCard';
import { PageHeader, Card, Panel, SectionTitle, Badge, ProgressBar, Gauge, Donut, Sparkline } from '../components/ui';
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
  const { history } = useMetricsHistory(client);

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
      <PageHeader title="集群总览" subtitle="集群健康、控制面风险与实时事件" />

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

      {error ? (
        <p className="rounded-md border border-error/30 bg-error/10 p-3 text-sm text-error">
          {toBilingualPrompt(error)}
        </p>
      ) : null}

      {summary ? (
        <Card>
          <SectionTitle>集群能力概览</SectionTitle>
          <div className="mt-4 grid items-center gap-6 md:grid-cols-2 xl:grid-cols-4">
            <div className="flex flex-col items-center">
              <Gauge
                ratio={summary.storage.utilization_ratio}
                tone={
                  summary.storage.utilization_ratio >= 0.9
                    ? 'error'
                    : summary.storage.utilization_ratio >= 0.75
                      ? 'warning'
                      : 'success'
                }
                label={`${(summary.storage.utilization_ratio * 100).toFixed(0)}%`}
                sublabel="容量利用率"
              />
              <p className="mt-1 text-xs text-muted">
                {formatBytes(summary.storage.capacity_used_bytes)} / {formatBytes(summary.storage.capacity_total_bytes)}
              </p>
            </div>

            <div className="flex flex-col items-center">
              <Donut
                ratio={
                  summary.storage.ec_data_shards + summary.storage.ec_parity_shards > 0
                    ? summary.storage.ec_parity_shards /
                      (summary.storage.ec_data_shards + summary.storage.ec_parity_shards)
                    : 0
                }
                tone="info"
                label={`${summary.storage.ec_data_shards}+${summary.storage.ec_parity_shards}`}
                sublabel="EC data+parity"
              />
              <p className="mt-1 text-xs text-muted">可容忍 {summary.storage.ec_parity_shards} 盘/节点故障</p>
            </div>

            <div className="flex flex-col items-center">
              <Gauge
                ratio={summary.raft.quorum > 0 ? Math.min(1, summary.raft.online_peers / summary.raft.quorum) : 0}
                tone={summary.raft.online_peers >= summary.raft.quorum ? 'success' : 'error'}
                label={`${summary.raft.online_peers}/${summary.raft.quorum}`}
                sublabel="Raft 法定票"
              />
              <p className="mt-1 text-xs text-muted">Leader {summary.raft.leader_id || '—'}</p>
            </div>

            <div className="space-y-3">
              <Panel>
                <p className="text-xs uppercase tracking-wide text-muted">容量趋势(实时)</p>
                <Sparkline
                  className="mt-2"
                  values={history.length > 1 ? history.map((h) => h.capacityRatio) : [0, 0]}
                  tone="primary"
                />
              </Panel>
              <div className="grid grid-cols-2 gap-2">
                <Panel>
                  <p className="text-xs text-muted">再平衡对象</p>
                  <p className="mt-1 font-heading text-lg font-semibold text-on-surface">
                    {summary.storage.governance.rebalance_objects_total}
                  </p>
                </Panel>
                <Panel>
                  <p className="text-xs text-muted">分片健康</p>
                  <p className="mt-1 font-heading text-lg font-semibold text-success">
                    {summary.storage.shard_healthy_total}
                  </p>
                </Panel>
              </div>
            </div>
          </div>
        </Card>
      ) : null}

      {summary ? (
        <Card>
          <SectionTitle>控制面风险摘要</SectionTitle>
          <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Panel className="text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">告警链路</p>
              <p className="mt-2 text-on-surface">活跃告警 {summary.alerts.firing_alerts}</p>
              <p className="mt-1">投递失败 {summary.alerts.delivery_failed} / 执行中 {summary.alerts.delivery_in_progress}</p>
            </Panel>
            <Panel className="text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">KMS</p>
              <p className="mt-2 text-on-surface">{summary.kms.healthy ? '健康' : '异常'} / {summary.kms.rotation_status}</p>
              <p className="mt-1">最近失败 {summary.kms.rotation_failed} 个</p>
            </Panel>
            <Panel className="text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">IAM / 会话</p>
              <p className="mt-2 text-on-surface">用户 {summary.iam.users_enabled}/{summary.iam.users_total}</p>
              <p className="mt-1">活跃会话 {summary.sessions.admin_sessions_active + summary.sessions.sts_sessions_active}</p>
            </Panel>
            <Panel className="text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">复制 / 审计</p>
              <p className="mt-2 text-on-surface">失败 backlog {summary.replication.backlog_failed}</p>
              <p className="mt-1">审计失败 {summary.audit.failed_outcomes_total}</p>
            </Panel>
          </div>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <div className="flex items-center justify-between gap-3">
            <SectionTitle>统一任务摘要</SectionTitle>
            <span className="text-xs text-muted">
              {summary ? new Date(summary.generated_at).toLocaleString() : '加载中...'}
            </span>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <Panel className="text-sm text-muted">
              <p>Pending：{summary?.jobs.async_pending ?? '--'}</p>
              <p className="mt-1">In-progress：{summary?.jobs.async_in_progress ?? '--'}</p>
              <p className="mt-1">Completed：{summary?.jobs.async_completed ?? '--'}</p>
              <p className="mt-1">Failed：{summary?.jobs.async_failed ?? '--'}</p>
            </Panel>
            <Panel className="text-sm text-muted">
              <p>复制站点：{summary?.replication.sites_total ?? '--'}</p>
              <p className="mt-1">健康站点：{summary?.replication.sites_healthy ?? '--'}</p>
              <p className="mt-1">最大延迟：{summary?.replication.max_lag_seconds ?? '--'} 秒</p>
              <p className="mt-1">告警站点：{summary?.replication.backlog_sla_firing_sites ?? '--'}</p>
            </Panel>
          </div>
        </Card>

        <Card>
          <SectionTitle>实时控制事件</SectionTitle>
          <ul className="mt-3 max-h-72 space-y-2 overflow-auto pr-1">
            {events.map((event, index) => (
              <li
                key={`${event.topic}-${event.timestamp}-${index}`}
                className="rounded-md border border-outline/40 bg-surface-container-high p-4 text-sm"
              >
                <p className="font-mono text-xs text-primary">{event.topic}</p>
                <p className="mt-1 text-on-surface">{event.source}</p>
                <p className="mt-1 text-xs text-muted">{new Date(event.timestamp).toLocaleString()}</p>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <SectionTitle>节点健康</SectionTitle>
          <div className="mt-3 space-y-2">
            {nodes.map((node) => (
              <Panel key={node.id} className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-on-surface">{node.hostname}</p>
                  <p className="text-xs text-muted">{node.zone}</p>
                </div>
                <Badge tone={node.online ? 'success' : 'error'}>
                  {node.online ? '在线' : '离线'}
                </Badge>
              </Panel>
            ))}
          </div>
        </Card>

        <Card>
          <SectionTitle>租户配额</SectionTitle>
          <div className="mt-3 space-y-3">
            {quotas.map((quota) => {
              const ratio = quota.hard_limit_bytes > 0 ? quota.used_bytes / quota.hard_limit_bytes : 0;
              const percent = Math.max(0, Math.min(100, ratio * 100));
              return (
                <Panel key={quota.tenant}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-medium text-on-surface">{quota.tenant}</p>
                    <p className="text-xs text-muted">{percent.toFixed(1)}%</p>
                  </div>
                  <p className="mt-1 text-xs text-muted">
                    已用 {formatBytes(quota.used_bytes)} / 配额 {formatBytes(quota.hard_limit_bytes)}
                  </p>
                  <ProgressBar
                    className="mt-2"
                    ratio={ratio}
                    tone={percent >= 90 ? 'error' : percent >= 75 ? 'warning' : 'primary'}
                  />
                </Panel>
              );
            })}
            {quotas.length === 0 ? <p className="text-sm text-muted">暂无租户配额数据</p> : null}
          </div>
        </Card>
      </div>
    </section>
  );
}
