import { useCallback, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import { systemService } from '../api/services';
import type { MetadataRaftStatus } from '../types';
import { Badge, Button, Card, Panel, PageHeader, SectionTitle, Field, Input, IconRefresh } from '../components/ui';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';

export function RaftPage({ client, canWrite }: { client: ApiClient; canWrite: boolean }) {
  const [status, setStatus] = useState<MetadataRaftStatus | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [peerId, setPeerId] = useState('');
  const [peerEndpoint, setPeerEndpoint] = useState('');

  const reload = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setStatus(await systemService.raftStatus(client));
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const runAction = async (fn: () => Promise<MetadataRaftStatus>, ok: string) => {
    setError('');
    setMessage('');
    try {
      setStatus(await fn());
      setMessage(ok);
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败');
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Raft 管理"
        subtitle="元数据 Raft 集群状态、Leader 选举与成员变更。"
        actions={
          <Button variant="secondary" loading={loading} icon={<IconRefresh size={16} />} onClick={reload}>
            刷新
          </Button>
        }
      />

      {error ? <p className="text-sm text-error">{error}</p> : null}
      {message ? <p className="text-sm text-success">{message}</p> : null}

      {status ? (
        <Card>
          <div className="flex items-center justify-between">
            <SectionTitle>集群状态</SectionTitle>
            <Badge tone={status.online_peers >= status.quorum ? 'success' : 'error'}>
              {status.online_peers >= status.quorum ? '法定票达成' : '法定票不足'}
            </Badge>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">Leader</p>
              <p className="mt-1 font-mono text-on-surface">{status.leader_id || '—'}</p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">任期 / 提交索引</p>
              <p className="mt-1 font-mono text-on-surface">
                {status.term} / {status.commit_index}
              </p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">在线 / 法定票</p>
              <p className="mt-1 font-mono text-on-surface">
                {status.online_peers} / {status.quorum}
              </p>
            </Panel>
            <Panel>
              <p className="text-xs uppercase tracking-wide text-muted">成员变更阶段</p>
              <p className="mt-1 text-on-surface">{status.membership_phase}</p>
            </Panel>
          </div>
          {status.last_error ? (
            <p className="mt-3 text-sm text-error">最近错误:{status.last_error}</p>
          ) : null}
          <div className="mt-4">
            <p className="text-xs uppercase tracking-wide text-muted">节点列表</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {status.peers.map((p) => (
                <Badge key={p} tone={p === status.leader_id ? 'primary' : 'neutral'}>
                  {p}
                  {p === status.leader_id ? ' (leader)' : ''}
                </Badge>
              ))}
            </div>
          </div>
        </Card>
      ) : null}

      {canWrite ? (
        <Card>
          <SectionTitle>成员管理</SectionTitle>
          <p className="mt-1 text-sm text-muted">以下均为危险操作,需填写审计原因后执行。</p>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <Field label="节点 ID" htmlFor="raft-peer-id">
              <Input
                id="raft-peer-id"
                value={peerId}
                onChange={(e) => setPeerId(e.target.value)}
                placeholder="如 1"
              />
            </Field>
            <Field label="节点 Endpoint(添加时)" htmlFor="raft-peer-ep">
              <Input
                id="raft-peer-ep"
                value={peerEndpoint}
                onChange={(e) => setPeerEndpoint(e.target.value)}
                placeholder="http://node:9000"
              />
            </Field>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            <ConfirmActionDialog
              title="添加 Raft 节点"
              description={`将节点 ${peerId || '?'} 加入 Raft 成员。`}
              actionLabel="添加节点"
              onConfirm={(reason) =>
                runAction(
                  () =>
                    systemService.raftAddPeer(client, {
                      id: peerId,
                      endpoint: peerEndpoint || undefined,
                      reason
                    }),
                  '已提交添加节点'
                )
              }
            />
            <ConfirmActionDialog
              title="转移 Leader"
              description={`将 Leader 转移到节点 ${peerId || '?'}。`}
              actionLabel="转移 Leader"
              onConfirm={(reason) => runAction(() => systemService.raftTransfer(client, peerId, reason), '已提交转移')}
            />
            <ConfirmActionDialog
              title="触发选举"
              description={`让节点 ${peerId || '?'} 发起选举。`}
              actionLabel="触发选举"
              onConfirm={(reason) => runAction(() => systemService.raftElect(client, peerId, reason), '已提交选举')}
            />
            <ConfirmActionDialog
              title="节点下线"
              description={`将节点 ${peerId || '?'} 标记为离线。`}
              actionLabel="下线"
              onConfirm={(reason) => runAction(() => systemService.raftPeerOffline(client, peerId, reason), '已提交下线')}
            />
            <ConfirmActionDialog
              title="节点上线"
              description={`将节点 ${peerId || '?'} 标记为在线。`}
              actionLabel="上线"
              onConfirm={(reason) => runAction(() => systemService.raftPeerOnline(client, peerId, reason), '已提交上线')}
            />
            <ConfirmActionDialog
              title="移除节点"
              description={`从 Raft 成员中移除节点 ${peerId || '?'}。`}
              actionLabel="移除"
              onConfirm={(reason) =>
                runAction(() => systemService.raftRemovePeer(client, peerId, { reason }), '已提交移除')
              }
            />
          </div>

          <div className="mt-4 flex flex-wrap gap-2 border-t border-outline/50 pt-4">
            <ConfirmActionDialog
              title="完成成员变更"
              description="提交进行中的 joint 成员变更。"
              actionLabel="完成成员变更"
              onConfirm={(reason) => runAction(() => systemService.raftMembershipFinalize(client, reason), '已完成')}
            />
            <ConfirmActionDialog
              title="中止成员变更"
              description="中止进行中的 joint 成员变更。"
              actionLabel="中止成员变更"
              onConfirm={(reason) => runAction(() => systemService.raftMembershipAbort(client, reason), '已中止')}
            />
          </div>
        </Card>
      ) : null}
    </div>
  );
}
