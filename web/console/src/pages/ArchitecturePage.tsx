import { useCallback, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import { clusterService, systemService } from '../api/services';
import type {
  ArchitectureTopology,
  ArchitectureAlignmentReport,
  ClusterPeerInfo,
  ClusterGroup,
  SystemInfo
} from '../types';
import { Badge, Button, Card, Panel, PageHeader, SectionTitle, Chip, IconRefresh } from '../components/ui';
import type { BadgeTone } from '../components/ui';

const alignmentTone = (status: string): BadgeTone => {
  const s = status.toLowerCase();
  if (s.includes('ready') || s.includes('aligned') || s.includes('ok')) return 'success';
  if (s.includes('partial') || s.includes('pending')) return 'warning';
  if (s.includes('missing') || s.includes('error') || s.includes('fail')) return 'error';
  return 'neutral';
};

/** 集群拓扑 SVG:按分组聚类的节点圆点,排空节点用警告色。 */
function ClusterTopology({ peers }: { peers: ClusterPeerInfo[] }) {
  const groups = Array.from(new Set(peers.map((p) => p.group_id))).sort();
  const colW = 150;
  const rowH = 60;
  const maxRows = Math.max(1, ...groups.map((g) => peers.filter((p) => p.group_id === g).length));
  const width = Math.max(320, groups.length * colW);
  const height = 56 + maxRows * rowH;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="mt-4 w-full" style={{ maxHeight: height }}>
      {groups.map((g, gi) => {
        const cx = gi * colW + colW / 2;
        const members = peers.filter((p) => p.group_id === g);
        return (
          <g key={g}>
            <text x={cx} y={24} textAnchor="middle" className="fill-muted" fontSize="12" fontWeight="600">
              组 {g}
            </text>
            <rect
              x={gi * colW + 12}
              y={36}
              width={colW - 24}
              height={maxRows * rowH + 4}
              rx="10"
              className="fill-surface-container-high stroke-outline/40"
              strokeWidth="1"
            />
            {members.map((p, mi) => {
              const cy = 36 + 28 + mi * rowH;
              return (
                <g key={p.node_id}>
                  <circle cx={cx} cy={cy} r={14} className={p.draining ? 'fill-warning' : 'fill-primary'} />
                  <text x={cx} y={cy + 4} textAnchor="middle" className="fill-on-primary" fontSize="11" fontWeight="600">
                    {p.node_id}
                  </text>
                  <text x={cx} y={cy + 30} textAnchor="middle" className="fill-muted" fontSize="10">
                    {p.node_name || `node-${p.node_id}`}
                  </text>
                </g>
              );
            })}
          </g>
        );
      })}
    </svg>
  );
}

export function ArchitecturePage({ client }: { client: ApiClient }) {
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [topology, setTopology] = useState<ArchitectureTopology | null>(null);
  const [alignment, setAlignment] = useState<ArchitectureAlignmentReport | null>(null);
  const [peers, setPeers] = useState<ClusterPeerInfo[]>([]);
  const [groups, setGroups] = useState<ClusterGroup[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [infoRes, topoRes, alignRes, peersRes, groupsRes] = await Promise.all([
        systemService.info(client).catch(() => null),
        systemService.topology(client).catch(() => null),
        systemService.alignment(client).catch(() => null),
        clusterService.peers(client).catch(() => []),
        clusterService.groups(client).catch(() => [])
      ]);
      setInfo(infoRes);
      setTopology(topoRes);
      setAlignment(alignRes);
      setPeers(peersRes);
      setGroups(groupsRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void reload();
    const timer = window.setInterval(() => { void reload(); }, 15000);
    return () => window.clearInterval(timer);
  }, [reload]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="架构与拓扑"
        subtitle="平面架构、对齐状态与集群节点拓扑、分组分布。"
        actions={
          <Button variant="secondary" loading={loading} icon={<IconRefresh size={16} />} onClick={reload}>
            刷新
          </Button>
        }
      />

      {error ? <p className="text-sm text-error">{error}</p> : null}

      {info ? (
        <Card>
          <SectionTitle>系统信息</SectionTitle>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">名称</p>
              <p className="mt-1 font-medium text-on-surface">{info.name}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">版本</p>
              <p className="mt-1 font-mono text-on-surface">{info.version}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">架构版本</p>
              <p className="mt-1 font-mono text-on-surface">{info.architecture_version}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">平面数</p>
              <p className="mt-1 font-medium text-on-surface">{info.plane_count}</p>
            </Panel>
          </div>
        </Card>
      ) : null}

      {alignment ? (
        <Card>
          <div className="flex items-center justify-between">
            <SectionTitle>架构对齐报告</SectionTitle>
            <Badge tone={alignmentTone(alignment.overall_status)}>{alignment.overall_status}</Badge>
          </div>
          {alignment.missing_planes.length > 0 ? (
            <p className="mt-2 text-sm text-warning">缺失平面:{alignment.missing_planes.join('、')}</p>
          ) : null}
          <div className="mt-4 space-y-2">
            {alignment.planes.map((plane) => (
              <Panel key={plane.plane_id} className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-on-surface">{plane.plane_name}</p>
                  <p className="text-xs text-muted">
                    组件就绪 {plane.component_ready}/{plane.component_total}
                    {plane.checks.length > 0 ? ` · ${plane.checks.join('、')}` : ''}
                  </p>
                </div>
                <Badge tone={alignmentTone(plane.status)}>{plane.status}</Badge>
              </Panel>
            ))}
          </div>
        </Card>
      ) : null}

      {topology ? (
        <Card>
          <SectionTitle>平面拓扑</SectionTitle>
          <p className="mt-1 text-xs text-muted">
            版本 {topology.version} · 对齐于 {topology.aligned_at}
          </p>
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            {topology.planes.map((plane) => (
              <Panel key={plane.id}>
                <p className="font-medium text-on-surface">{plane.name}</p>
                {plane.responsibilities.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {plane.responsibilities.map((r) => (
                      <Chip key={r}>{r}</Chip>
                    ))}
                  </div>
                ) : null}
                <div className="mt-3 space-y-1">
                  {plane.components.map((c) => (
                    <div key={c.id} className="flex items-center justify-between text-sm">
                      <span className="text-on-surface">{c.responsibility}</span>
                      <span className="text-xs text-muted">{c.owner}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            ))}
          </div>
        </Card>
      ) : null}

      {peers.length > 0 ? (
        <Card>
          <SectionTitle>集群拓扑</SectionTitle>
          <p className="mt-1 text-xs text-muted">按分组聚类的节点分布(排空节点以警告色标记)。</p>
          <ClusterTopology peers={peers} />
        </Card>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <SectionTitle>集群节点(Peers)</SectionTitle>
          <p className="mt-1 text-xs text-muted">共 {peers.length} 个节点</p>
          <div className="mt-4 divide-y divide-outline/50">
            {peers.length === 0 ? (
              <p className="py-4 text-sm text-muted">暂无节点数据(单机模式或未组建集群)。</p>
            ) : (
              peers.map((peer) => (
                <div key={peer.node_id} className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-on-surface">
                      {peer.node_name || `node-${peer.node_id}`}
                    </p>
                    <p className="text-xs text-muted">
                      {peer.api_addr} · 区域 {peer.zone || '—'} · 盘 {peer.disks.length} · 组 {peer.group_id}
                    </p>
                  </div>
                  <Badge tone={peer.draining ? 'warning' : 'success'}>
                    {peer.draining ? '排空中' : '在线'}
                  </Badge>
                </div>
              ))
            )}
          </div>
        </Card>

        <Card>
          <SectionTitle>分组架构(Placement Groups)</SectionTitle>
          <p className="mt-1 text-xs text-muted">共 {groups.length} 个分组</p>
          <div className="mt-4 space-y-2">
            {groups.length === 0 ? (
              <p className="py-4 text-sm text-muted">暂无分组数据。</p>
            ) : (
              groups.map((group) => (
                <Panel key={group.group_id} className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-on-surface">{group.group_id}</p>
                    <p className="text-xs text-muted">节点:{group.node_ids.join('、')}</p>
                  </div>
                  <Badge tone="info">{group.node_count} 节点</Badge>
                </Panel>
              ))
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
