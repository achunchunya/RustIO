import { useEffect, useRef, useState } from 'react';
import { ApiClient } from '../api/client';
import { clusterService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { PageHeader, Card, Button, Badge, useToast } from '../components/ui';
import type { ClusterNode, DiagnosticReport } from '../types';

type OperationsPageProps = {
  client: ApiClient;
};

export function OperationsPage({ client }: OperationsPageProps) {
  const [nodes, setNodes] = useState<ClusterNode[]>([]);
  const toast = useToast();
  const [latestDiagnostic, setLatestDiagnostic] = useState<DiagnosticReport | null>(null);
  const [creatingDiagnostic, setCreatingDiagnostic] = useState(false);

  async function reload() {
    const snapshot = await clusterService.nodes(client);
    setNodes(snapshot);
  }

  useEffect(() => {
    reload().catch((requestError) => {
      toast.error(requestError instanceof Error ? requestError.message : '加载节点失败');
    });
    const timer = window.setInterval(() => { void reload(); }, 15000);
    return () => window.clearInterval(timer);
  }, [client]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="运维操作"
        subtitle="节点操作需二次确认并填写审计原因。"
        actions={
          <Button
            variant="primary"
            loading={creatingDiagnostic}
            disabled={creatingDiagnostic}
            onClick={async () => {
              setCreatingDiagnostic(true);
              try {
                const report = await clusterService.createDiagnostic(client);
                setLatestDiagnostic(report);
                toast.success(`诊断报告已生成：${report.id}`);
              } catch (requestError) {
                toast.error(requestError instanceof Error ? requestError.message : '生成诊断报告失败');
              } finally {
                setCreatingDiagnostic(false);
              }
            }}
          >
            {creatingDiagnostic ? '生成中...' : '生成诊断报告'}
          </Button>
        }
      />

      <Card>
        {latestDiagnostic ? (
          <p className="mt-2 text-xs text-muted">
            最近报告：{latestDiagnostic.summary}（{new Date(latestDiagnostic.created_at).toLocaleString()}）
          </p>
        ) : null}

        <div className="mt-4 space-y-3">
          {nodes.map((node) => (
            <article
              key={node.id}
              className="rounded-md border border-outline/40 bg-surface-container-high p-3"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-on-surface">{node.hostname}</p>
                  <p className="text-xs text-muted">{node.zone}</p>
                </div>
                <Badge tone={node.online ? 'success' : 'error'}>
                  {node.online ? '在线' : '离线'}
                </Badge>
              </div>
              <div className="mt-3 flex gap-2">
                {node.online ? (
                  <ConfirmActionDialog
                    title={`下线节点 ${node.hostname}`}
                    description="在集群降级场景下可能影响写入法定仲裁，请谨慎操作。"
                    actionLabel="执行下线"
                    onConfirm={async (reason) => {
                      try {
                        await clusterService.setNodeOffline(client, node.id, reason);
                        toast.success(`节点 ${node.hostname} 已下线`);
                        await reload();
                      } catch (requestError) {
                        toast.error(requestError instanceof Error ? requestError.message : '下线节点失败');
                        throw requestError;
                      }
                    }}
                  />
                ) : (
                  <ConfirmActionDialog
                    title={`上线节点 ${node.hostname}`}
                    description="节点会重新加入集群并触发同步流程。"
                    actionLabel="执行上线"
                    onConfirm={async (reason) => {
                      try {
                        await clusterService.setNodeOnline(client, node.id, reason);
                        toast.success(`节点 ${node.hostname} 已上线`);
                        await reload();
                      } catch (requestError) {
                        toast.error(requestError instanceof Error ? requestError.message : '上线节点失败');
                        throw requestError;
                      }
                    }}
                  />
                )}
              </div>
            </article>
          ))}
        </div>
      </Card>
    </div>
  );
}
