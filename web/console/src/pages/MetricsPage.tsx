import { useEffect, useMemo, useState } from 'react';
import { ApiClient } from '../api/client';
import { systemService } from '../api/services';
import { StatCard } from '../components/StatCard';
import {
  Badge,
  Button,
  Card,
  Chip,
  PageHeader,
  Panel,
  ProgressBar,
  SectionTitle,
  useToast,
  type BadgeTone
} from '../components/ui';
import type { SystemMetricsSummary } from '../types';
import { toBilingualPrompt } from '../utils/bilingual';

type MetricsPageProps = {
  client: ApiClient;
};

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const sized = value / 1024 ** exponent;
  return `${sized.toFixed(sized >= 100 ? 0 : sized >= 10 ? 1 : 2)} ${units[exponent]}`;
}

function formatPercent(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0%';
  return `${(value * 100).toFixed(value >= 0.1 ? 1 : 2)}%`;
}

function formatDateTime(value?: string | null) {
  if (!value) return '--';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '--';
  return parsed.toLocaleString();
}

function formatDurationSeconds(value: number) {
  if (!Number.isFinite(value) || value < 0) return '--';
  if (value < 60) return `${value.toFixed(value >= 10 ? 1 : 2)} 秒`;
  const minutes = Math.floor(value / 60);
  const seconds = value % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours} 小时 ${remainingMinutes} 分`;
  }
  return `${minutes} 分 ${seconds.toFixed(0)} 秒`;
}

function clusterStatusText(status: string) {
  if (status === 'healthy') return '健康';
  if (status === 'degraded') return '降级';
  if (status === 'critical') return '严重异常';
  return status || '未知';
}

function storageStatusText(status: string) {
  if (status === 'healthy') return '健康';
  if (status === 'degraded') return '降级';
  if (status === 'critical') return '严重异常';
  if (status === 'offline') return '离线';
  if (status === 'warning') return '告警';
  if (status === 'failed') return '失败';
  if (status === 'running') return '运行中';
  if (status === 'pending') return '待处理';
  if (status === 'retrying') return '重试中';
  return '未知';
}

function governanceResultText(status: string) {
  if (status === 'healthy') return '扫描健康';
  if (status === 'degraded') return '发现异常';
  if (status === 'failed') return '扫描失败';
  if (status === 'running') return '扫描中';
  if (status === 'unknown') return '未知';
  return '未知';
}

function boolText(value: boolean) {
  return value ? '已启用' : '未启用';
}

function formatTime(value?: string | null) {
  if (!value) return '--';
  return new Date(value).toLocaleString();
}

function chipTone(status: string): BadgeTone {
  if (status === 'healthy' || status === 'active' || status === 'stable') {
    return 'success';
  }
  if (status === 'degraded' || status === 'warning' || status === 'firing') {
    return 'warning';
  }
  if (status === 'critical' || status === 'failed' || status === 'offline') {
    return 'error';
  }
  return 'neutral';
}

export function MetricsPage({ client }: MetricsPageProps) {
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [rawMetrics, setRawMetrics] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copying, setCopying] = useState(false);
  const [error, setError] = useState('');
  const showSuccess = useToast();

  async function reload(silent = false) {
    if (!silent) {
      setLoading(true);
    }
    setError('');
    try {
      const [summarySnapshot, prometheusSnapshot] = await Promise.all([
        systemService.metricsSummary(client),
        systemService.prometheusMetrics(client)
      ]);
      setSummary(summarySnapshot);
      setRawMetrics(prometheusSnapshot);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '加载指标总览失败');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void reload();
  }, [client]);

  const metricsLines = useMemo(
    () => rawMetrics.split('\n').filter((line) => line.trim().length > 0),
    [rawMetrics]
  );

  const generatedAt = summary ? new Date(summary.generated_at).toLocaleString() : '--';
  const storageUsedPercent = summary ? Math.max(0, Math.min(100, summary.storage.utilization_ratio * 100)) : 0;
  const raftPeerPercent =
    summary && summary.raft.quorum > 0
      ? Math.max(0, Math.min(100, (summary.raft.online_peers / Math.max(summary.nodes.total, 1)) * 100))
      : 0;
  const governance = summary?.storage.governance ?? null;
  const diskMetrics = useMemo(() => {
    if (!summary) return [];
    return [...summary.storage.disks].sort((left, right) => {
      if (right.heal_pressure !== left.heal_pressure) {
        return right.heal_pressure - left.heal_pressure;
      }
      const leftAnomaly = left.last_anomaly_at ? new Date(left.last_anomaly_at).getTime() : 0;
      const rightAnomaly = right.last_anomaly_at ? new Date(right.last_anomaly_at).getTime() : 0;
      if (rightAnomaly !== leftAnomaly) {
        return rightAnomaly - leftAnomaly;
      }
      const severity = (status: string) => {
        if (status === 'offline') return 3;
        if (status === 'degraded') return 2;
        if (status === 'critical') return 2;
        return 1;
      };
      const severityGap = severity(right.status) - severity(left.status);
      if (severityGap !== 0) {
        return severityGap;
      }
      return left.disk_id.localeCompare(right.disk_id);
    });
  }, [summary]);
  const activeRepairObjects = governance
    ? governance.pending_objects + governance.running_objects + governance.retrying_objects
    : 0;
  const anomalousDiskCount = diskMetrics.filter(
    (disk) => disk.shard_missing > 0 || disk.shard_corrupted > 0 || !disk.online
  ).length;

  return (
    <section className="space-y-6">
      <PageHeader
        title="指标中心"
        subtitle="汇总节点、存储、Raft、复制、告警、安全、任务与会话运行态。"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="secondary"
              loading={refreshing}
              disabled={refreshing || loading}
              onClick={async () => {
                setRefreshing(true);
                await reload(true);
                setRefreshing(false);
              }}
            >
              {refreshing ? '刷新中...' : '刷新指标'}
            </Button>
            <Button
              variant="primary"
              loading={copying}
              disabled={copying || !rawMetrics}
              onClick={async () => {
                if (!rawMetrics) return;
                setCopying(true);
                setError('');
                try {
                  await navigator.clipboard.writeText(rawMetrics);
                  showSuccess('Prometheus 指标文本已复制');
                } catch {
                  setError('复制指标文本失败');
                } finally {
                  setCopying(false);
                }
              }}
            >
              {copying ? '复制中...' : '复制 Prometheus 文本'}
            </Button>
          </div>
        }
      />
      <p className="-mt-2 text-xs text-muted">最近生成时间：{generatedAt}</p>

      {error ? <p className="rounded-lg bg-error/10 p-3 text-sm text-error">{toBilingualPrompt(error)}</p> : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="集群状态"
          value={summary ? clusterStatusText(summary.cluster_status) : loading ? '加载中' : '--'}
          helper={summary ? `租户 ${summary.tenants_total} 个` : '系统指标摘要'}
        />
        <StatCard
          label="节点在线"
          value={summary ? `${summary.nodes.online}/${summary.nodes.total}` : loading ? '加载中' : '--'}
          helper={summary ? `离线 ${summary.nodes.offline}，可用区 ${summary.nodes.zones_total}` : '节点心跳'}
        />
        <StatCard
          label="存储利用率"
          value={summary ? formatPercent(summary.storage.utilization_ratio) : loading ? '加载中' : '--'}
          helper={summary ? `已用 ${formatBytes(summary.storage.capacity_used_bytes)}` : '原始容量'}
        />
        <StatCard
          label="复制堆积"
          value={summary ? String(summary.replication.backlog_total) : loading ? '加载中' : '--'}
          helper={
            summary
              ? `失败 ${summary.replication.backlog_failed} / 死信 ${summary.replication.backlog_dead_letter}`
              : '复制队列'
          }
        />
        <StatCard
          label="Raft 法定票"
          value={summary ? `${summary.raft.online_peers}/${summary.raft.quorum}` : loading ? '加载中' : '--'}
          helper={summary ? `term=${summary.raft.term}` : '元数据层'}
        />
        <StatCard
          label="活跃告警"
          value={summary ? String(summary.alerts.firing_alerts) : loading ? '加载中' : '--'}
          helper={summary ? `通知通道健康 ${summary.alerts.channels_healthy}/${summary.alerts.channels_total}` : '告警链路'}
        />
        <StatCard
          label="运行任务"
          value={summary ? String(summary.jobs.running) : loading ? '加载中' : '--'}
          helper={summary ? `待处理 ${summary.jobs.pending} / 完成 ${summary.jobs.completed}` : '后台任务'}
        />
        <StatCard
          label="活跃会话"
          value={
            summary
              ? String(summary.sessions.admin_sessions_active + summary.sessions.sts_sessions_active)
              : loading
                ? '加载中'
                : '--'
          }
          helper={
            summary
              ? `控制台 ${summary.sessions.admin_sessions_active} / STS ${summary.sessions.sts_sessions_active}`
              : '访问面'
          }
        />
        <StatCard
          label="待修复对象"
          value={summary ? String(activeRepairObjects) : loading ? '加载中' : '--'}
          helper={
            governance
              ? `失败 ${governance.failed_objects} / 最近扫描 ${governanceResultText(governance.last_scan_result)}`
              : '存储治理'
          }
        />
        <StatCard
          label="治理锁定对象"
          value={summary ? String(summary.storage.governance.retained_objects + summary.storage.governance.legal_hold_objects) : loading ? '加载中' : '--'}
          helper={
            governance
              ? `保留期 ${governance.retained_objects} / 法务保全 ${governance.legal_hold_objects}`
              : '对象锁治理'
          }
        />
        <StatCard
          label="IAM 主体"
          value={summary ? `${summary.iam.users_enabled}/${summary.iam.users_total}` : loading ? '加载中' : '--'}
          helper={summary ? `组 ${summary.iam.groups_total} / 策略 ${summary.iam.policies_total}` : '用户与策略'}
        />
        <StatCard
          label="审计异常"
          value={summary ? String(summary.audit.failed_outcomes_total) : loading ? '加载中' : '--'}
          helper={summary ? `总事件 ${summary.audit.events_total}` : '审计闭环'}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <div className="flex items-center justify-between gap-3">
            <div>
              <SectionTitle>节点与存储</SectionTitle>
              <p className="mt-1 text-sm text-muted">查看容量、空闲空间与节点在线情况。</p>
            </div>
            {summary ? (
              <Badge tone={chipTone(summary.cluster_status)}>
                {clusterStatusText(summary.cluster_status)}
              </Badge>
            ) : null}
          </div>

          <div className="mt-4 space-y-4">
            <Panel>
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm text-muted">原始容量使用率</p>
                <p className="text-sm text-on-surface">{summary ? formatPercent(summary.storage.utilization_ratio) : '--'}</p>
              </div>
              <ProgressBar className="mt-2" ratio={storageUsedPercent / 100} tone="primary" />
              <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-3">
                <p>总容量：{summary ? formatBytes(summary.storage.capacity_total_bytes) : '--'}</p>
                <p>已用：{summary ? formatBytes(summary.storage.capacity_used_bytes) : '--'}</p>
                <p>可用：{summary ? formatBytes(summary.storage.capacity_free_bytes) : '--'}</p>
              </div>
            </Panel>

            <div className="grid gap-3 md:grid-cols-2">
              <Panel className="text-sm text-muted">
                <p className="text-xs uppercase tracking-[0.2em] text-muted">节点</p>
                <p className="mt-2 text-on-surface">在线 {summary?.nodes.online ?? '--'} / 总数 {summary?.nodes.total ?? '--'}</p>
                <p className="mt-1">离线 {summary?.nodes.offline ?? '--'}，可用区 {summary?.nodes.zones_total ?? '--'}</p>
              </Panel>
              <Panel className="text-sm text-muted">
                <p className="text-xs uppercase tracking-[0.2em] text-muted">租户</p>
                <p className="mt-2 text-on-surface">总计 {summary?.tenants_total ?? '--'} 个</p>
                <p className="mt-1">指标生成：{generatedAt}</p>
              </Panel>
            </div>
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between gap-3">
            <div>
              <SectionTitle>Raft 元数据层</SectionTitle>
              <p className="mt-1 text-sm text-muted">关注 leader、term、commit index 与 quorum。</p>
            </div>
            {summary ? (
              <Badge tone={summary.raft.quorum_available ? 'success' : 'error'}>
                {summary.raft.quorum_available ? '法定票满足' : '法定票不足'}
              </Badge>
            ) : null}
          </div>

          <div className="mt-4 space-y-4">
            <Panel>
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm text-muted">在线 peer 占比</p>
                <p className="text-sm text-on-surface">{summary ? `${summary.raft.online_peers}/${summary.nodes.total}` : '--'}</p>
              </div>
              <ProgressBar className="mt-2" ratio={raftPeerPercent / 100} tone="primary" />
            </Panel>

            <dl className="grid gap-3 md:grid-cols-2">
              <Panel>
                <dt className="text-xs uppercase tracking-[0.2em] text-muted">集群 ID</dt>
                <dd className="mt-2 break-all text-sm text-on-surface">{summary?.raft.cluster_id ?? '--'}</dd>
              </Panel>
              <Panel>
                <dt className="text-xs uppercase tracking-[0.2em] text-muted">Leader</dt>
                <dd className="mt-2 text-sm text-on-surface">{summary?.raft.leader_id || '未选主'}</dd>
              </Panel>
              <Panel>
                <dt className="text-xs uppercase tracking-[0.2em] text-muted">Term / Commit</dt>
                <dd className="mt-2 text-sm text-on-surface">
                  {summary ? `${summary.raft.term} / ${summary.raft.commit_index}` : '--'}
                </dd>
              </Panel>
              <Panel>
                <dt className="text-xs uppercase tracking-[0.2em] text-muted">成员变更阶段</dt>
                <dd className="mt-2 text-sm text-on-surface">{summary?.raft.membership_phase ?? '--'}</dd>
              </Panel>
            </dl>

            {summary?.raft.last_error ? (
              <p className="rounded-lg bg-error/10 p-3 text-sm text-error">
                最近错误：{toBilingualPrompt(summary.raft.last_error)}
              </p>
            ) : (
              <p className="rounded-lg bg-success/10 p-3 text-sm text-success">当前未发现 Raft 侧错误。</p>
            )}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.15fr,1fr]">
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <SectionTitle>存储治理摘要</SectionTitle>
              <p className="mt-1 text-sm text-muted">聚合后台扫描、自愈任务和对象锁治理状态。</p>
            </div>
            {governance ? (
              <Badge tone={chipTone(governance.last_scan_result)}>
                {governanceResultText(governance.last_scan_result)}
              </Badge>
            ) : null}
          </div>

          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">扫描与修复</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>最近扫描：{formatDateTime(governance?.last_scan_at)}</p>
                <p>最近修复：{formatDateTime(governance?.last_heal_at)}</p>
                <p>最近修复耗时：{governance?.last_heal_at ? formatDurationSeconds(governance.last_heal_duration_seconds) : '--'}</p>
                <p>扫描累计：{governance?.scan_runs_total ?? '--'}，失败 {governance?.scan_failures_total ?? '--'}</p>
                <p>修复累计：{governance?.heal_objects_total ?? '--'}，失败 {governance?.heal_failures_total ?? '--'}</p>
              </div>
            </Panel>

            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">修复对象队列</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>待处理：{governance?.pending_objects ?? '--'}</p>
                <p>修复中：{governance?.running_objects ?? '--'}</p>
                <p>重试中：{governance?.retrying_objects ?? '--'}</p>
                <p>失败对象：{governance?.failed_objects ?? '--'}</p>
                <p>异常盘数：{summary ? anomalousDiskCount : '--'}</p>
              </div>
            </Panel>

            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">对象锁治理</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>对象锁桶：{governance?.object_lock_buckets ?? '--'}</p>
                <p>默认保留桶：{governance?.retention_buckets ?? '--'}</p>
                <p>法务保全桶：{governance?.legal_hold_buckets ?? '--'}</p>
                <p>保留期对象：{governance?.retained_objects ?? '--'}</p>
                <p>法务保全对象：{governance?.legal_hold_objects ?? '--'}</p>
              </div>
            </Panel>

            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">任务类型分布</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>scan：{summary?.jobs.scan ?? '--'}</p>
                <p>scrub：{summary?.jobs.scrub ?? '--'}</p>
                <p>heal：{summary?.jobs.heal ?? '--'}</p>
                <p>rebuild：{summary?.jobs.rebuild ?? '--'}</p>
                <p>重试任务：{summary?.jobs.retrying ?? '--'}</p>
              </div>
            </Panel>
          </div>
        </Card>

        <Card>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <SectionTitle>盘级修复压力</SectionTitle>
              <p className="mt-1 text-sm text-muted">显示每块盘的分片健康、修复压力和最近异常时间。</p>
            </div>
            {summary ? (
              <Badge tone={anomalousDiskCount > 0 ? 'warning' : 'success'}>
                异常盘 {anomalousDiskCount}/{summary.storage.disks_total}
              </Badge>
            ) : null}
          </div>

          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Panel className="text-sm text-muted">
              <p>EC 布局：数据片 {summary?.storage.ec_data_shards ?? '--'} / 校验片 {summary?.storage.ec_parity_shards ?? '--'}</p>
              <p className="mt-1">分片文件：{summary?.storage.shard_files_total ?? '--'}，体积 {summary ? formatBytes(summary.storage.shard_bytes_total) : '--'}</p>
              <p className="mt-1">健康分片：{summary?.storage.shard_healthy_total ?? '--'}</p>
            </Panel>
            <Panel className="text-sm text-muted">
              <p>缺失分片：{summary?.storage.shard_missing_total ?? '--'}</p>
              <p className="mt-1">损坏分片：{summary?.storage.shard_corrupted_total ?? '--'}</p>
              <p className="mt-1">在线磁盘：{summary ? `${summary.storage.disks_online}/${summary.storage.disks_total}` : '--'}</p>
            </Panel>
          </div>

          <div className="mt-4 space-y-3">
            {diskMetrics.length > 0 ? (
              diskMetrics.map((disk) => (
                <Panel key={disk.disk_id}>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="font-medium text-on-surface">{disk.disk_id}</p>
                        <Badge tone={chipTone(disk.status)}>
                          {storageStatusText(disk.status)}
                        </Badge>
                        <Badge tone={disk.heal_pressure > 0 ? 'warning' : 'success'}>
                          修复压力 {disk.heal_pressure}
                        </Badge>
                      </div>
                      <p className="mt-1 break-all text-xs text-muted">{disk.path}</p>
                    </div>
                    <div className="text-right text-xs text-muted">
                      <p>最近异常：{formatDateTime(disk.last_anomaly_at)}</p>
                      <p className="mt-1">Manifest：{disk.manifests_total}</p>
                    </div>
                  </div>
                  <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
                    <p>健康分片：{disk.shard_healthy}</p>
                    <p>分片文件：{disk.shard_files}</p>
                    <p>缺失分片：{disk.shard_missing}</p>
                    <p>损坏分片：{disk.shard_corrupted}</p>
                    <p>分片体积：{formatBytes(disk.shard_bytes)}</p>
                    <p>磁盘在线：{boolText(disk.online)}</p>
                  </div>
                </Panel>
              ))
            ) : (
              <Panel className="border-dashed text-sm text-muted">
                暂无盘级分片数据。
              </Panel>
            )}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.4fr,1fr]">
        <Card>
          <div className="flex items-center justify-between gap-3">
            <div>
              <SectionTitle>复制站点总览</SectionTitle>
              <p className="mt-1 text-sm text-muted">同时观察站点健康、延迟与 backlog SLA。</p>
            </div>
            {summary ? (
              <Badge tone={summary.replication.backlog_sla_firing_sites > 0 ? 'warning' : 'success'}>
                SLA 告警站点 {summary.replication.backlog_sla_firing_sites}
              </Badge>
            ) : null}
          </div>

          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Panel className="text-sm text-muted">
              <p>复制规则：{summary?.replication.rules_total ?? '--'}</p>
              <p className="mt-1">站点：{summary?.replication.sites_total ?? '--'}，健康站点：{summary?.replication.sites_healthy ?? '--'}</p>
              <p className="mt-1">Checkpoint：{summary?.replication.checkpoints_total ?? '--'}</p>
            </Panel>
            <Panel className="text-sm text-muted">
              <p>Pending：{summary?.replication.backlog_pending ?? '--'}</p>
              <p className="mt-1">In-progress：{summary?.replication.backlog_in_progress ?? '--'}</p>
              <p className="mt-1">最大复制延迟：{summary?.replication.max_lag_seconds ?? '--'} 秒</p>
            </Panel>
          </div>

          <div className="mt-4 space-y-3">
            {summary?.replication.sites.map((site) => (
              <Panel key={site.site_id}>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-medium text-on-surface">{site.site_id}</p>
                      <Badge tone={chipTone(site.state)}>
                        {site.state}
                      </Badge>
                      <Badge tone={chipTone(site.backlog_sla_status)}>
                        backlog {site.backlog_sla_status}
                      </Badge>
                    </div>
                    <p className="mt-1 break-all text-xs text-muted">{site.endpoint || '未登记 endpoint'}</p>
                  </div>
                  <div className="text-right text-sm text-muted">
                    <p>延迟 {site.lag_seconds} 秒</p>
                    <p className="mt-1">触发告警 {site.firing_alerts} 条</p>
                  </div>
                </div>
                <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-4">
                  <p>总量：{site.backlog_total}</p>
                  <p>Pending：{site.backlog_pending}</p>
                  <p>失败：{site.backlog_failed}</p>
                  <p>死信：{site.backlog_dead_letter}</p>
                </div>
              </Panel>
            ))}
          </div>
        </Card>

        <Card>
          <SectionTitle>告警、IAM、KMS 与审计</SectionTitle>
          <p className="mt-1 text-sm text-muted">聚焦控制面风险暴露、身份面和 KMS 运维状态。</p>

          <div className="mt-4 space-y-3">
            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">告警</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>规则数：{summary?.alerts.rules_total ?? '--'}</p>
                <p>通道健康：{summary ? `${summary.alerts.channels_healthy}/${summary.alerts.channels_total}` : '--'}</p>
                <p>活跃告警：{summary?.alerts.firing_alerts ?? '--'}</p>
                <p>历史记录：{summary?.alerts.history_total ?? '--'}</p>
                <p>投递待发：{summary?.alerts.delivery_queued ?? '--'}，执行中：{summary?.alerts.delivery_in_progress ?? '--'}</p>
                <p>投递失败：{summary?.alerts.delivery_failed ?? '--'}，已完成：{summary?.alerts.delivery_done ?? '--'}</p>
              </div>
              {summary?.alerts.last_delivery_error ? (
                <p className="mt-3 rounded-lg bg-error/10 p-3 text-sm text-error">
                  最近投递错误：{toBilingualPrompt(summary.alerts.last_delivery_error)}
                </p>
              ) : null}
            </Panel>

            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">IAM / 会话</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>用户：{summary ? `${summary.iam.users_enabled}/${summary.iam.users_total}` : '--'}</p>
                <p>组 / 策略：{summary ? `${summary.iam.groups_total} / ${summary.iam.policies_total}` : '--'}</p>
                <p>服务账号：{summary ? `${summary.iam.service_accounts_enabled}/${summary.iam.service_accounts_total}` : '--'}</p>
                <p>控制台会话：{summary ? `${summary.sessions.admin_sessions_active}/${summary.sessions.admin_sessions_total}` : '--'}</p>
                <p>STS 会话：{summary ? `${summary.sessions.sts_sessions_active}/${summary.sessions.sts_sessions_total}` : '--'}</p>
                <p>24h 内到期：{summary ? `${summary.sessions.admin_sessions_expiring_24h + summary.sessions.sts_sessions_expiring_24h}` : '--'}</p>
              </div>
            </Panel>

            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">KMS / 安全</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>OIDC：{summary ? boolText(summary.security.oidc_enabled) : '--'}</p>
                <p>LDAP：{summary ? boolText(summary.security.ldap_enabled) : '--'}</p>
                <p>KMS Endpoint：{summary ? boolText(summary.kms.endpoint_configured) : '--'}</p>
                <p>KMS 健康：{summary ? boolText(summary.kms.healthy) : '--'}</p>
                <p>SSE 模式：{summary?.security.sse_mode ?? '--'}</p>
                <p>轮换状态：{summary?.kms.rotation_status ?? '--'}</p>
                <p>轮换失败：{summary?.kms.rotation_failed ?? '--'}</p>
                <p>最近成功：{formatTime(summary?.kms.last_success_at)}</p>
              </div>
              {summary?.kms.rotation_last_failure_reason ? (
                <p className="mt-3 rounded-lg bg-warning/14 p-3 text-sm text-warning">
                  最近轮换失败：{toBilingualPrompt(summary.kms.rotation_last_failure_reason)}
                </p>
              ) : summary?.kms.last_error ? (
                <p className="mt-3 rounded-lg bg-error/10 p-3 text-sm text-error">
                  最近 KMS 错误：{toBilingualPrompt(summary.kms.last_error)}
                </p>
              ) : null}
            </Panel>

            <Panel>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">审计 / 任务</p>
              <div className="mt-2 grid gap-2 text-sm text-muted">
                <p>审计总量：{summary?.audit.events_total ?? '--'}</p>
                <p>认证事件：{summary?.audit.auth_events_total ?? '--'}</p>
                <p>KMS 事件：{summary?.audit.kms_events_total ?? '--'}</p>
                <p>告警事件：{summary?.audit.alert_events_total ?? '--'}</p>
                <p>失败结果：{summary?.audit.failed_outcomes_total ?? '--'}</p>
                <p>最近事件：{formatTime(summary?.audit.latest_event_at)}</p>
                <p>运行任务：{summary?.jobs.running ?? '--'}，待处理：{summary?.jobs.pending ?? '--'}</p>
                <p>失败任务：{summary?.jobs.failed ?? '--'}，已取消：{summary?.jobs.cancelled ?? '--'}</p>
              </div>
            </Panel>
          </div>
        </Card>
      </div>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <SectionTitle>Prometheus 文本预览</SectionTitle>
            <p className="mt-1 text-sm text-muted">当前已输出 {metricsLines.length} 行，可直接用于采集联调。</p>
          </div>
          <Chip>路径：/metrics</Chip>
        </div>
        <pre className="mt-4 max-h-[32rem] overflow-auto rounded-md border border-outline/60 bg-surface-container-high p-4 text-xs leading-6 text-on-surface">
          {rawMetrics || (loading ? '加载中...' : '暂无指标文本')}
        </pre>
      </Card>
    </section>
  );
}
