import { useCallback, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import { systemService, clusterService } from '../api/services';
import type { SystemCapabilities, SystemMetricsSummary, ClusterPeerInfo, ClusterGroup } from '../types';
import {
  Badge,
  Button,
  Card,
  Panel,
  Chip,
  PageHeader,
  SectionTitle,
  BarChart,
  Donut,
  Gauge,
  IconRefresh
} from '../components/ui';
import {
  DIFFERENTIATORS,
  LIST_BENCH,
  THROUGHPUT_BENCH,
  EC_BENCH,
  SECURITY_HARDENING
} from '../data/advantages';

const formatBytes = (bytes: number) => {
  if (!bytes) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
};

/** 分层混合一致性架构图(纯 SVG,随主题变色) */
function ConsistencyDiagram() {
  const layers = [
    { y: 16, name: '控制面', model: 'openraft 强一致', detail: 'bucket / IAM / security 多节点 HA + 动态成员', tone: 'fill-primary' },
    { y: 84, name: '元数据 / LIST', model: 'redb 有序索引', detail: '单页延迟与桶规模解耦,LIST 25× 领先', tone: 'fill-secondary' },
    { y: 152, name: '对象数据 / manifest', model: 'quorum 多副本', detail: '去中心高吞吐 + 读时自愈 healing', tone: 'fill-info' }
  ];
  return (
    <svg viewBox="0 0 420 220" className="w-full" style={{ maxHeight: 240 }}>
      {layers.map((l) => (
        <g key={l.name}>
          <rect x="8" y={l.y} width="404" height="56" rx="10" className="fill-surface-container-high stroke-outline/60" strokeWidth="1" />
          <rect x="8" y={l.y} width="6" height="56" rx="3" className={l.tone} />
          <text x="26" y={l.y + 24} className="fill-on-surface" fontSize="14" fontWeight="600">{l.name}</text>
          <text x="26" y={l.y + 44} className="fill-muted" fontSize="11">{l.detail}</text>
          <text x="404" y={l.y + 24} textAnchor="end" className="fill-secondary" fontSize="12" fontWeight="600">{l.model}</text>
        </g>
      ))}
    </svg>
  );
}

export function CapabilitiesPage({ client }: { client: ApiClient }) {
  const [caps, setCaps] = useState<SystemCapabilities | null>(null);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [peers, setPeers] = useState<ClusterPeerInfo[]>([]);
  const [groups, setGroups] = useState<ClusterGroup[]>([]);
  const [loading, setLoading] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const [c, s, p, g] = await Promise.all([
        systemService.capabilities(client).catch(() => null),
        systemService.metricsSummary(client).catch(() => null),
        clusterService.peers(client).catch(() => []),
        clusterService.groups(client).catch(() => [])
      ]);
      setCaps(c);
      setSummary(s);
      setPeers(p);
      setGroups(g);
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void reload();
    const interval = window.setInterval(() => { void reload(); }, 15000);
    return () => window.clearInterval(interval);
  }, [reload]);

  const ecData = caps?.ec_data_shards ?? summary?.storage.ec_data_shards ?? 0;
  const ecParity = caps?.ec_parity_shards ?? summary?.storage.ec_parity_shards ?? 0;
  const ecTotal = ecData + ecParity;
  const redundancyRatio = ecTotal > 0 ? ecParity / ecTotal : 0;
  const gov = summary?.storage.governance;
  const raft = summary?.raft;
  const quorumRatio = raft && raft.quorum > 0 ? Math.min(1, raft.online_peers / raft.quorum) : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="集群能力 / 优势"
        subtitle="RustIO 相对 MinIO / RustFS 的结构性差异化能力与实测基准。"
        actions={
          <Button variant="secondary" loading={loading} icon={<IconRefresh size={16} />} onClick={reload}>
            刷新
          </Button>
        }
      />

      {/* 差异化总览 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {DIFFERENTIATORS.map((d) => (
          <Card key={d.key} className="flex flex-col">
            <div className="flex items-baseline justify-between">
              <h3 className="font-heading text-base font-semibold text-on-surface">{d.title}</h3>
              <span className="font-heading text-lg font-semibold text-secondary">{d.headline}</span>
            </div>
            <p className="mt-2 text-sm text-muted">{d.desc}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* LIST 性能 */}
        <Card>
          <div className="flex items-center justify-between">
            <SectionTitle>LIST 元数据索引性能</SectionTitle>
            {caps ? (
              <Badge tone={caps.list_index_mode === 'redb-index' ? 'success' : 'warning'}>
                {caps.list_index_mode}
              </Badge>
            ) : null}
          </div>
          <p className="mt-1 text-xs text-muted">
            {LIST_BENCH.objects} 对象同进程对照(基准:scripts/list-bench)
          </p>
          <div className="mt-4">
            <BarChart
              items={[
                { label: 'redb 索引 · 单页', value: LIST_BENCH.singlePageRedbMs, display: `${LIST_BENCH.singlePageRedbMs}ms`, tone: 'success' },
                { label: 'walk-fs · 单页(MinIO 式)', value: LIST_BENCH.singlePageWalkMs, display: `${LIST_BENCH.singlePageWalkMs}ms`, tone: 'error' }
              ]}
            />
          </div>
          <p className="mt-3 text-sm text-on-surface">
            单页 <span className="font-semibold text-success">{LIST_BENCH.singlePageSpeedup}×</span> 更快 · 全量分页{' '}
            <span className="font-semibold text-success">{LIST_BENCH.fullPageSpeedup}×</span>;延迟与桶规模解耦。
          </p>
        </Card>

        {/* EC + SIMD + 吞吐 */}
        <Card>
          <SectionTitle>纠删码冗余 · SIMD · 吞吐</SectionTitle>
          <div className="mt-4 flex items-center gap-5">
            <Donut
              ratio={redundancyRatio}
              tone="info"
              label={ecTotal > 0 ? `${ecData}+${ecParity}` : '—'}
              sublabel="data+parity"
            />
            <div className="space-y-2 text-sm">
              <p className="text-on-surface">
                可容忍 <span className="font-semibold text-info">{ecParity}</span> 盘/节点故障
              </p>
              <div className="flex flex-wrap gap-1.5">
                <Badge tone={caps?.simd_accel ? 'success' : 'neutral'}>
                  SIMD {caps?.simd_accel ? '已启用' : '未知'}
                </Badge>
                <Badge tone={caps?.io_uring ? 'success' : 'neutral'}>
                  io_uring {caps?.io_uring ? '已启用' : '回退 tokio'}
                </Badge>
              </div>
              <p className="text-xs text-muted">
                EC 编码 {EC_BENCH.encodeSimdGiBs} GiB/s(SIMD,{EC_BENCH.encodeSpeedup}× 基线)
              </p>
            </div>
          </div>
          <div className="mt-4 border-t border-outline/50 pt-3">
            <BarChart
              items={[
                { label: '单机 GET', value: THROUGHPUT_BENCH.singleNodeGetGiBs, display: `${THROUGHPUT_BENCH.singleNodeGetGiBs} GiB/s`, tone: 'success' },
                { label: 'MinIO 集群 GET(对照)', value: THROUGHPUT_BENCH.minioClusterGetGiBs, display: `${THROUGHPUT_BENCH.minioClusterGetGiBs} GiB/s`, tone: 'secondary' }
              ]}
            />
          </div>
        </Card>

        {/* Raft HA */}
        <Card>
          <SectionTitle>Raft 强一致控制面</SectionTitle>
          <div className="mt-4 flex items-center gap-6">
            <Gauge
              ratio={quorumRatio}
              tone={raft && raft.online_peers >= raft.quorum ? 'success' : 'error'}
              label={raft ? `${raft.online_peers}/${raft.quorum}` : '—'}
              sublabel="在线 / 法定票"
            />
            <div className="space-y-2 text-sm">
              <p className="text-on-surface">Leader:<span className="ml-1 font-mono text-secondary">{raft?.leader_id || '—'}</span></p>
              <p className="text-muted">任期 {raft?.term ?? '—'} · 提交索引 {raft?.commit_index ?? '—'}</p>
              <div className="flex flex-wrap gap-1.5">
                <Badge tone="success">优雅 Leader 转移</Badge>
                <Badge tone="success">动态成员变更</Badge>
                <Badge tone="info">{raft?.membership_phase || 'stable'}</Badge>
              </div>
            </div>
          </div>
        </Card>

        {/* 弹性扩缩 */}
        <Card>
          <SectionTitle>在线弹性扩缩</SectionTitle>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">集群节点</p>
              <p className="mt-1 font-heading text-2xl font-semibold text-on-surface">{peers.length || summary?.nodes.total || 0}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">分组</p>
              <p className="mt-1 font-heading text-2xl font-semibold text-on-surface">{groups.length}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">再平衡累计对象</p>
              <p className="mt-1 font-heading text-2xl font-semibold text-on-surface">{gov?.rebalance_objects_total ?? 0}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">退役累计对象</p>
              <p className="mt-1 font-heading text-2xl font-semibold text-on-surface">{gov?.decommission_objects_total ?? 0}</p>
            </Panel>
          </div>
          <p className="mt-3 text-sm text-muted">运行时增删节点 + 存量再平衡,全程无停机降级。</p>
        </Card>
      </div>

      {/* 分层混合一致性架构 */}
      <Card>
        <SectionTitle>分层混合一致性架构</SectionTitle>
        <p className="mt-1 text-sm text-muted">三层各用最优一致性模型 —— 业界独有的结构性差异化。</p>
        <div className="mt-4">
          <ConsistencyDiagram />
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* 安全姿态 */}
        <Card>
          <SectionTitle>安全姿态</SectionTitle>
          <ul className="mt-4 space-y-2">
            {SECURITY_HARDENING.map((item) => (
              <li key={item} className="flex items-start gap-2 text-sm text-on-surface">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-success" />
                {item}
              </li>
            ))}
          </ul>
          {summary ? (
            <div className="mt-4 flex flex-wrap gap-1.5">
              <Badge tone={summary.security.oidc_enabled ? 'success' : 'neutral'}>OIDC</Badge>
              <Badge tone={summary.security.ldap_enabled ? 'success' : 'neutral'}>LDAP</Badge>
              <Badge tone={summary.security.kms_healthy ? 'success' : 'warning'}>KMS</Badge>
              <Badge tone="info">SSE {summary.security.sse_mode}</Badge>
            </div>
          ) : null}
        </Card>

        {/* MinIO 兼容 */}
        <Card>
          <SectionTitle>S3 / MinIO 兼容</SectionTitle>
          <div className="mt-3 flex items-center gap-2">
            <Badge tone={caps?.minio_compat ? 'success' : 'neutral'}>
              {caps?.minio_compat ? 'MinIO 健康检查别名兼容' : '兼容性未知'}
            </Badge>
            <span className="text-xs text-muted">/minio/health/*</span>
          </div>
          <p className="mt-4 text-xs uppercase tracking-wide text-muted">已实现 S3 能力</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {(caps?.s3_features ?? []).map((f) => (
              <Chip key={f}>{f}</Chip>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
