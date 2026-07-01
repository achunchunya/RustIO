import { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { clusterService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { Badge, Button, Card, PageHeader, SectionTitle, Textarea, useToast } from '../components/ui';
import type { ClusterConfigSnapshot, ClusterConfigValidationResult } from '../types';
import { toBilingualPrompt } from '../utils/bilingual';

type ConfigPageProps = {
  client: ApiClient;
  canWrite: boolean;
};

function formatConfig(payload: Record<string, unknown>) {
  return JSON.stringify(payload, null, 2);
}

function parseConfigEditor(raw: string): Record<string, unknown> {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('配置必须是 JSON 对象');
  }
  return parsed as Record<string, unknown>;
}

export function ConfigPage({ client, canWrite }: ConfigPageProps) {
  const showSuccess = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [current, setCurrent] = useState<ClusterConfigSnapshot | null>(null);
  const [history, setHistory] = useState<ClusterConfigSnapshot[]>([]);
  const [editor, setEditor] = useState('{}');
  const [validation, setValidation] = useState<ClusterConfigValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [exporting, setExporting] = useState(false);

  async function reload() {
    const [currentConfig, configHistory] = await Promise.all([
      clusterService.configCurrent(client),
      clusterService.configHistory(client, 30)
    ]);
    setCurrent(currentConfig);
    setHistory(configHistory);
    setEditor(formatConfig(currentConfig.payload));
  }

  useEffect(() => {
    setLoading(true);
    reload()
      .catch((requestError) => {
        setError(requestError instanceof Error ? requestError.message : '加载配置中心失败');
      })
      .finally(() => setLoading(false));
  }, [client]);

  return (
    <section className="space-y-6">
      <div>
        <PageHeader
          title="配置中心"
          subtitle="集群配置导出、校验、应用与版本回滚，所有动作均写入审计日志。"
          actions={
            <>
              <Button
                variant="secondary"
                loading={loading}
                disabled={loading}
                onClick={async () => {
                  setError('');
                  setLoading(true);
                  try {
                    await reload();
                    setValidation(null);
                    showSuccess('配置已刷新 / Configuration refreshed');
                  } catch (requestError) {
                    setError(requestError instanceof Error ? requestError.message : '刷新配置失败');
                  } finally {
                    setLoading(false);
                  }
                }}
              >
                {loading ? '刷新中...' : '刷新配置'}
              </Button>
              <Button
                variant="secondary"
                loading={exporting}
                disabled={exporting}
                onClick={async () => {
                  setExporting(true);
                  setError('');
                  try {
                    const text = await clusterService.exportConfig(client);
                    const blob = new Blob([text], { type: 'application/json' });
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = `rustio-cluster-config-${new Date()
                      .toISOString()
                      .replace(/[:.]/g, '-')}.json`;
                    link.click();
                    URL.revokeObjectURL(link.href);
                    showSuccess('配置文件已导出 / Cluster config exported');
                  } catch (requestError) {
                    setError(requestError instanceof Error ? requestError.message : '导出配置失败');
                  } finally {
                    setExporting(false);
                  }
                }}
              >
                {exporting ? '导出中...' : '导出配置'}
              </Button>
            </>
          }
        />
        {error ? <p className="text-sm text-error">{toBilingualPrompt(error)}</p> : null}
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <SectionTitle>配置编辑器</SectionTitle>
            <Button
              variant="tertiary"
              size="sm"
              onClick={() => {
                if (current) {
                  setEditor(formatConfig(current.payload));
                  showSuccess('已同步当前配置到编辑器 / Synced current config to editor');
                }
              }}
            >
              同步当前配置
            </Button>
          </div>
          <Textarea
            className="mt-3 h-[520px] font-mono text-xs"
            value={editor}
            onChange={(event) => setEditor(event.target.value)}
            spellCheck={false}
          />

          <div className="mt-3 flex flex-wrap gap-2">
            <Button
              variant="secondary"
              loading={validating}
              disabled={validating}
              onClick={async () => {
                setValidating(true);
                setError('');
                try {
                  const payload = parseConfigEditor(editor);
                  const result = await clusterService.validateConfig(client, payload);
                  setValidation(result);
                  if (result.valid) {
                    showSuccess('配置校验通过 / Configuration validation passed');
                  } else {
                    showSuccess(
                      `配置校验失败（${result.errors.length} 个错误） / Configuration validation failed (${result.errors.length} errors)`
                    );
                  }
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '校验配置失败');
                } finally {
                  setValidating(false);
                }
              }}
            >
              {validating ? '校验中...' : '校验配置'}
            </Button>
            {canWrite ? (
              <ConfirmActionDialog
                title="应用集群配置"
                description="该操作会立即更新运行配置并写入审计日志，请确认已完成校验。"
                actionLabel="应用配置"
                onConfirm={async (reason) => {
                  setError('');
                  try {
                    const payload = parseConfigEditor(editor);
                    const snapshot = await clusterService.applyConfig(client, payload, reason);
                    setCurrent(snapshot);
                    setEditor(formatConfig(snapshot.payload));
                    setValidation(null);
                    showSuccess(`配置版本 ${snapshot.version} 已应用`);
                    await reload();
                  } catch (requestError) {
                    setError(requestError instanceof Error ? requestError.message : '应用配置失败');
                    throw requestError;
                  }
                }}
              />
            ) : null}
          </div>
        </Card>

        <Card>
          <SectionTitle>版本历史</SectionTitle>
          {current ? (
            <div className="mt-3 rounded-md border border-outline/40 bg-surface-container-high p-3 text-xs text-muted">
              <p>
                当前版本：<span className="font-mono text-on-surface">{current.version}</span>
              </p>
              <p className="mt-1">
                更新时间：{new Date(current.updated_at).toLocaleString()} · 更新人：{current.updated_by}
              </p>
              <p className="mt-1">
                来源：{current.source} · ETag：<span className="font-mono">{current.etag.slice(0, 12)}</span>
              </p>
              {current.reason ? <p className="mt-1">原因：{current.reason}</p> : null}
            </div>
          ) : null}

          <div className="mt-3 max-h-[520px] space-y-3 overflow-auto pr-1">
            {history.map((item, index) => (
              <div
                key={item.version}
                className="rounded-md border border-outline/40 bg-surface-container-high p-3"
              >
                <p className="font-mono text-xs text-on-surface">{item.version}</p>
                <p className="mt-1 text-xs text-muted">
                  {new Date(item.updated_at).toLocaleString()} · {item.updated_by}
                </p>
                <p className="mt-1 text-xs text-muted">来源：{item.source}</p>
                {item.reason ? <p className="mt-1 text-xs text-muted">原因：{item.reason}</p> : null}
                {canWrite && index > 0 ? (
                  <div className="mt-2">
                    <ConfirmActionDialog
                      title={`回滚至 ${item.version}`}
                      description="会基于选定版本生成新的活动配置版本，并记录审计日志。"
                      actionLabel="回滚到此版本"
                      onConfirm={async (reason) => {
                        setError('');
                        try {
                          const snapshot = await clusterService.rollbackConfig(client, item.version, reason);
                          setCurrent(snapshot);
                          setEditor(formatConfig(snapshot.payload));
                          setValidation(null);
                          showSuccess(`配置已回滚到 ${item.version}`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '回滚配置失败');
                          throw requestError;
                        }
                      }}
                    />
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </Card>
      </div>

      {validation ? (
        <Card>
          <div className="flex flex-wrap items-center gap-3">
            <SectionTitle>校验结果</SectionTitle>
            <Badge tone={validation.valid ? 'success' : 'error'}>
              {validation.valid ? '通过' : '未通过'}
            </Badge>
            <span className="text-sm text-muted">
              错误 {validation.errors.length} · 警告 {validation.warnings.length}
            </span>
          </div>
          {validation.errors.length > 0 ? (
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-error">
              {validation.errors.map((item) => (
                <li key={item}>{toBilingualPrompt(item)}</li>
              ))}
            </ul>
          ) : null}
          {validation.warnings.length > 0 ? (
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-warning">
              {validation.warnings.map((item) => (
                <li key={item}>{toBilingualPrompt(item)}</li>
              ))}
            </ul>
          ) : null}
        </Card>
      ) : null}
    </section>
  );
}
