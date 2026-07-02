import { useCallback, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import { storageService } from '../api/services';
import type {
  RemoteTierConfig,
  StorageInventoryEntry,
  StorageGovernanceStatusResponse,
  StorageArchiveReport
} from '../types';
import {
  Badge,
  Button,
  Card,
  Panel,
  PageHeader,
  SectionTitle,
  Field,
  Input,
  ProgressBar,
  Tabs,
  IconRefresh,
  useToast
} from '../components/ui';
import type { BadgeTone, TabItem } from '../components/ui';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';

const TABS: TabItem[] = [
  { key: 'governance', label: '治理概览' },
  { key: 'tiers', label: '分层管理' },
  { key: 'inventory', label: '库存与归档' },
  { key: 'maintenance', label: '再平衡与退役' }
];

const formatBytes = (bytes: number) => {
  if (!bytes) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
};

const tierHealthTone = (status: string): BadgeTone => {
  const s = status.toLowerCase();
  if (s.includes('healthy') || s.includes('ok')) return 'success';
  if (s.includes('degrad') || s.includes('warn')) return 'warning';
  if (s.includes('error') || s.includes('fail') || s.includes('down')) return 'error';
  return 'neutral';
};

export function StoragePage({ client, canWrite }: { client: ApiClient; canWrite: boolean }) {
  const toast = useToast();
  const [tab, setTab] = useState('governance');
  const [loading, setLoading] = useState(false);

  const [governance, setGovernance] = useState<StorageGovernanceStatusResponse | null>(null);
  const [tiers, setTiers] = useState<RemoteTierConfig[]>([]);
  const [inventory, setInventory] = useState<StorageInventoryEntry[]>([]);
  const [archive, setArchive] = useState<StorageArchiveReport | null>(null);
  const [invBucket, setInvBucket] = useState('');
  const [invPrefix, setInvPrefix] = useState('');
  const [diskIds, setDiskIds] = useState('');

  const notify = (fn: () => void) => {
    fn();
  };

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      if (tab === 'governance') setGovernance(await storageService.governance(client));
      else if (tab === 'tiers') setTiers(await storageService.listTiers(client));
      else if (tab === 'inventory') {
        const query = { bucket: invBucket || undefined, prefix: invPrefix || undefined, limit: 200 };
        const [inv, rep] = await Promise.all([
          storageService.listInventory(client, query),
          storageService.archiveReport(client, query).catch(() => null)
        ]);
        setInventory(inv);
        setArchive(rep);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [client, tab, invBucket, invPrefix]);

  useEffect(() => {
    void reload();
    const interval = window.setInterval(() => { void reload(); }, 15000);
    return () => window.clearInterval(interval);
  }, [reload]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="存储治理"
        subtitle="磁盘健康、远端分层、对象库存归档与再平衡退役。"
        actions={
          <Button variant="secondary" loading={loading} icon={<IconRefresh size={16} />} onClick={reload}>
            刷新
          </Button>
        }
      />

      <Tabs items={TABS} active={tab} onChange={setTab} />

      {/* 治理概览 */}
      {tab === 'governance' && governance ? (
        <div className="space-y-6">
          <Card>
            <SectionTitle>治理摘要</SectionTitle>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Panel>
                <p className="text-xs uppercase tracking-wide text-muted">扫描状态</p>
                <p className="mt-1 text-on-surface">{governance.scan_running ? '运行中' : '空闲'}</p>
              </Panel>
              <Panel>
                <p className="text-xs uppercase tracking-wide text-muted">并发度</p>
                <p className="mt-1 text-on-surface">{governance.worker_concurrency}</p>
              </Panel>
              <Panel>
                <p className="text-xs uppercase tracking-wide text-muted">排空盘</p>
                <p className="mt-1 text-on-surface">{governance.draining_disks.length}</p>
              </Panel>
              <Panel>
                <p className="text-xs uppercase tracking-wide text-muted">退役盘</p>
                <p className="mt-1 text-on-surface">{governance.decommissioned_disks.length}</p>
              </Panel>
            </div>
          </Card>

          <Card>
            <SectionTitle>磁盘明细</SectionTitle>
            <div className="mt-4 divide-y divide-outline/50">
              {governance.disks.map((disk) => (
                <div key={disk.disk_id} className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-on-surface">{disk.disk_id}</p>
                    <p className="text-xs text-muted">
                      {disk.path} · 分片 {disk.shard_files} · 修复压力 {disk.heal_pressure}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {disk.placement_state ? <Badge tone="info">{disk.placement_state}</Badge> : null}
                    <Badge tone={disk.online ? 'success' : 'error'}>{disk.status}</Badge>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <SectionTitle>节点健康</SectionTitle>
            <div className="mt-4 divide-y divide-outline/50">
              {governance.peer_health.map((peer) => (
                <div key={peer.node_id} className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-on-surface">node-{peer.node_id}</p>
                    <p className="text-xs text-muted">
                      最近检查 {peer.last_check_at} · 连续失败 {peer.consecutive_failures}
                    </p>
                  </div>
                  <Badge tone={peer.online ? 'success' : 'error'}>{peer.online ? '在线' : '离线'}</Badge>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ) : null}

      {/* 分层管理 */}
      {tab === 'tiers' ? (
        <Card>
          <SectionTitle>远端分层</SectionTitle>
          <div className="mt-4 divide-y divide-outline/50">
            {tiers.length === 0 ? (
              <p className="py-4 text-sm text-muted">暂无远端分层配置。</p>
            ) : (
              tiers.map((tier) => (
                <div key={tier.name} className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium text-on-surface">{tier.name}</p>
                    <p className="text-xs text-muted">
                      {tier.backend} · {tier.endpoint} · 存储类 {tier.storage_class}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge tone={tier.enabled ? 'success' : 'neutral'}>
                      {tier.enabled ? '启用' : '停用'}
                    </Badge>
                    <Badge tone={tierHealthTone(tier.health_status)}>{tier.health_status}</Badge>
                    {canWrite ? (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() =>
                          notify(() => {
                            void storageService
                              .checkTierHealth(client, tier.name)
                              .then(() => reload())
                              .then(() => toast.success(`已检查 ${tier.name}`))
                              .catch((e) => toast.error(e instanceof Error ? e.message : '检查失败'));
                          })
                        }
                      >
                        健康检查
                      </Button>
                    ) : null}
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      ) : null}

      {/* 库存与归档 */}
      {tab === 'inventory' ? (
        <div className="space-y-6">
          <Card>
            <div className="flex flex-wrap items-end gap-3">
              <Field label="桶" htmlFor="inv-bucket" className="w-48">
                <Input id="inv-bucket" value={invBucket} onChange={(e) => setInvBucket(e.target.value)} placeholder="可选" />
              </Field>
              <Field label="前缀" htmlFor="inv-prefix" className="w-48">
                <Input id="inv-prefix" value={invPrefix} onChange={(e) => setInvPrefix(e.target.value)} placeholder="可选" />
              </Field>
              <Button variant="primary" loading={loading} onClick={reload}>
                查询
              </Button>
            </div>
          </Card>

          {archive ? (
            <Card>
              <SectionTitle>归档摘要</SectionTitle>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Panel>
                  <p className="text-xs uppercase tracking-wide text-muted">远端对象</p>
                  <p className="mt-1 text-on-surface">{archive.summary.remote_objects}</p>
                </Panel>
                <Panel>
                  <p className="text-xs uppercase tracking-wide text-muted">远端容量</p>
                  <p className="mt-1 text-on-surface">{formatBytes(archive.summary.remote_bytes)}</p>
                </Panel>
                <Panel>
                  <p className="text-xs uppercase tracking-wide text-muted">恢复中</p>
                  <p className="mt-1 text-on-surface">{archive.summary.restoring_objects}</p>
                </Panel>
                <Panel>
                  <p className="text-xs uppercase tracking-wide text-muted">即将过期</p>
                  <p className="mt-1 text-on-surface">{archive.summary.expiring_soon_objects}</p>
                </Panel>
              </div>
            </Card>
          ) : null}

          <Card>
            <SectionTitle>对象库存</SectionTitle>
            <div className="mt-4 divide-y divide-outline/50">
              {inventory.length === 0 ? (
                <p className="py-4 text-sm text-muted">无匹配对象。</p>
              ) : (
                inventory.map((item) => (
                  <div key={`${item.bucket}/${item.object_key}/${item.version_id}`} className="flex items-center justify-between py-3">
                    <div className="min-w-0">
                      <p className="truncate font-medium text-on-surface">
                        {item.bucket}/{item.object_key}
                      </p>
                      <p className="text-xs text-muted">
                        {formatBytes(item.size)} · {item.storage_class}
                        {item.remote_tier ? ` · 层 ${item.remote_tier}` : ''}
                      </p>
                    </div>
                    <Badge tone={item.archive_state.includes('cold') ? 'info' : 'neutral'}>
                      {item.archive_state}
                    </Badge>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      ) : null}

      {/* 再平衡与退役 */}
      {tab === 'maintenance' ? (
        <Card>
          <SectionTitle>再平衡与退役</SectionTitle>
          {canWrite ? (
            <>
              <Field label="磁盘 ID(逗号分隔,如 disk-0,disk-1;集群再平衡可留空)" htmlFor="disk-ids" className="mt-4">
                <Input id="disk-ids" value={diskIds} onChange={(e) => setDiskIds(e.target.value)} placeholder="disk-0,disk-1" />
              </Field>
              <div className="mt-4 flex flex-wrap gap-2">
                <ConfirmActionDialog
                  title="磁盘再平衡"
                  description="对指定磁盘(或留空=全集群)发起再平衡计划。"
                  actionLabel="发起再平衡"
                  onConfirm={(reason) =>
                    storageService
                      .startRebalance(client, {
                        disk_ids: diskIds ? diskIds.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
                        reason
                      })
                      .then(() => notify(() => toast.success('已提交再平衡计划')))
                  }
                />
                <ConfirmActionDialog
                  title="集群全量摊匀"
                  description="对整个集群发起全量再平衡(后台编排)。"
                  actionLabel="集群摊匀"
                  onConfirm={(reason) =>
                    storageService
                      .startClusterRebalance(client, { reason })
                      .then(() => notify(() => toast.success('已提交集群摊匀')))
                  }
                />
                <ConfirmActionDialog
                  title="磁盘退役"
                  description="将指定磁盘退役(需至少一个磁盘 ID)。"
                  actionLabel="退役磁盘"
                  onConfirm={(reason) =>
                    storageService
                      .startDecommission(client, {
                        disk_ids: diskIds.split(',').map((s) => s.trim()).filter(Boolean),
                        reason
                      })
                      .then(() => notify(() => toast.success('已提交退役计划')))
                  }
                />
                <Button
                  variant="secondary"
                  onClick={() =>
                    storageService
                      .cancelClusterRebalance(client)
                      .then((r) => notify(() => toast.success(`已取消 ${r.cancelled} 个再平衡任务`)))
                      .catch((e) => toast.error(e instanceof Error ? e.message : '取消失败'))
                  }
                >
                  取消集群再平衡
                </Button>
              </div>
              <p className="mt-3 text-xs text-muted">再平衡/退役会返回任务,可在「任务」页跟踪进度。</p>
            </>
          ) : (
            <p className="mt-4 text-sm text-muted">需要 cluster:write 权限执行再平衡与退役操作。</p>
          )}
        </Card>
      ) : null}
    </div>
  );
}
