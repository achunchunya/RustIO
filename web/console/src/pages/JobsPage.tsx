import { useEffect, useState } from 'react';
import { toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { jobsService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { StatCard } from '../components/StatCard';
import { useToast, Button } from '../components/ui';
import type { AsyncJobPage, AsyncJobStatus, AsyncJobSummary } from '../types';

type JobsPageProps = {
  client: ApiClient;
};

type Filters = {
  kind: string;
  status: string;
  bucket: string;
  site_id: string;
  keyword: string;
  include_terminal: boolean;
};

const DEFAULT_FILTERS: Filters = {
  kind: '',
  status: '',
  bucket: '',
  site_id: '',
  keyword: '',
  include_terminal: true
};

function jobKindText(kind: string) {
  if (kind === 'replication') return '复制';
  if (kind === 'lifecycle') return '生命周期';
  if (kind === 'notification') return '通知';
  if (kind === 'failover') return 'Failover';
  if (kind === 'failback') return 'Failback';
  if (kind === 'heal') return '修复';
  return kind;
}

function jobStatusText(status: string) {
  if (status === 'pending') return '待处理';
  if (status === 'queued') return '排队中';
  if (status === 'in_progress') return '执行中';
  if (status === 'running') return '运行中';
  if (status === 'completed' || status === 'done' || status === 'success') return '已完成';
  if (status === 'failed') return '失败';
  if (status === 'dead_letter') return '死信';
  if (status === 'cancelled') return '已取消';
  if (status === 'skipped') return '已跳过';
  return status;
}

function buildQuery(filters: Filters, cursor?: string) {
  return {
    kind: filters.kind || undefined,
    status: filters.status || undefined,
    bucket: filters.bucket || undefined,
    site_id: filters.site_id || undefined,
    keyword: filters.keyword || undefined,
    include_terminal: filters.include_terminal,
    limit: 12,
    cursor
  };
}

export function JobsPage({ client }: JobsPageProps) {
  const toast = useToast();
  const [target, setTarget] = useState('cluster');
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [jobsPage, setJobsPage] = useState<AsyncJobPage>({ items: [], next_cursor: null });
  const [summary, setSummary] = useState<AsyncJobSummary | null>(null);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [currentCursor, setCurrentCursor] = useState('');
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(false);
  const [actioning, setActioning] = useState('');

  async function reload(cursor?: string, resetStack = false) {
    setLoading(true);
    try {
      const query = buildQuery(filters, cursor);
      const [page, currentSummary] = await Promise.all([
        jobsService.asyncJobsPage(client, query),
        jobsService.asyncJobsSummary(client, buildQuery(filters))
      ]);
      setJobsPage(page);
      setSummary(currentSummary);
      setCurrentCursor(cursor ?? '');
      if (resetStack) {
        setCursorStack([]);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    reload(undefined, true).catch((requestError) => {
      toast.error(requestError instanceof Error ? requestError.message : '加载统一任务列表失败');
    });
  }, [client, filters]);

  async function runBulkAction(
    action: 'retry' | 'cleanup' | 'skip',
    jobIds: string[] = [],
    successMessage?: string
  ) {
    setActioning(action);
    try {
      if (action === 'retry') {
        await jobsService.retryAsyncJobs(client, buildQuery(filters), jobIds);
      } else if (action === 'cleanup') {
        await jobsService.cleanupAsyncJobs(client, buildQuery(filters), jobIds);
      } else {
        await jobsService.skipAsyncJobs(client, buildQuery(filters), jobIds);
      }
      toast.success(successMessage ?? '批量操作已完成');
      await reload();
    } catch (requestError) {
      toast.error(requestError instanceof Error ? requestError.message : '批量任务操作失败');
    } finally {
      setActioning('');
    }
  }

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="font-heading text-2xl text-on-surface">后台任务</h1>
            <p className="mt-1 text-sm text-muted">统一查看 replication / lifecycle / notification / failover / failback。</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
              placeholder="修复目标"
            />
            <Button
              variant="primary"
              size="sm"
              loading={starting}
              onClick={async () => {
                setStarting(true);
                try {
                  await jobsService.heal(client, target || 'cluster');
                  toast.success('修复任务已启动');
                  await reload();
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '启动修复失败');
                } finally {
                  setStarting(false);
                }
              }}
            >
              启动修复
            </Button>
            <Button
              variant="secondary"
              size="sm"
              loading={loading}
              onClick={() => {
                reload().catch((requestError) => {
                  toast.error(requestError instanceof Error ? requestError.message : '刷新任务失败');
                });
              }}
            >
              刷新
            </Button>
          </div>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-4">
          <StatCard label="任务总数" value={summary ? String(summary.total) : '...'} helper="统一异步任务口径" />
          <StatCard
            label="待处理"
            value={summary ? String(summary.pending) : '...'}
            helper={summary ? `执行中 ${summary.in_progress}` : '排队与处理中'}
          />
          <StatCard
            label="失败/死信"
            value={summary ? `${summary.failed}/${summary.dead_letter}` : '...'}
            helper={summary ? `可重试 ${summary.retryable}` : '统一重试口径'}
          />
          <StatCard
            label="已完成"
            value={summary ? String(summary.completed) : '...'}
            helper={summary ? `类别 ${summary.kinds.length}` : '跨任务类别'}
          />
        </div>

        <div className="mt-4 grid gap-2 rounded-xl border border-outline/60 bg-surface-container-high p-4 md:grid-cols-6">
          <select
            value={filters.kind}
            onChange={(event) => setFilters((current) => ({ ...current, kind: event.target.value }))}
            className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
          >
            <option value="">全部类别</option>
            <option value="replication">replication</option>
            <option value="lifecycle">lifecycle</option>
            <option value="notification">notification</option>
            <option value="failover">failover</option>
            <option value="failback">failback</option>
            <option value="heal">heal</option>
          </select>
          <select
            value={filters.status}
            onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}
            className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
          >
            <option value="">全部状态</option>
            <option value="pending">pending</option>
            <option value="in_progress">in_progress</option>
            <option value="failed">failed</option>
            <option value="dead_letter">dead_letter</option>
            <option value="completed">completed</option>
            <option value="done">done</option>
            <option value="skipped">skipped</option>
          </select>
          <input
            value={filters.bucket}
            onChange={(event) => setFilters((current) => ({ ...current, bucket: event.target.value }))}
            className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
            placeholder="桶名"
          />
          <input
            value={filters.site_id}
            onChange={(event) => setFilters((current) => ({ ...current, site_id: event.target.value }))}
            className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
            placeholder="站点 ID"
          />
          <input
            value={filters.keyword}
            onChange={(event) => setFilters((current) => ({ ...current, keyword: event.target.value }))}
            className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
            placeholder="关键字"
          />
          <label className="flex items-center gap-2 rounded-md border border-outline/60 px-3 text-sm text-muted">
            <input
              type="checkbox"
              checked={filters.include_terminal}
              onChange={(event) =>
                setFilters((current) => ({ ...current, include_terminal: event.target.checked }))
              }
            />
            包含终态
          </label>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            loading={actioning === 'retry'}
            onClick={() => runBulkAction('retry', [], '当前筛选任务已批量重试')}
          >
            批量重试
          </Button>
          <Button
            variant="secondary"
            size="sm"
            loading={actioning === 'skip'}
            onClick={() => runBulkAction('skip', [], '当前筛选任务已批量跳过')}
          >
            批量跳过
          </Button>
          <Button
            variant="secondary"
            size="sm"
            loading={actioning === 'cleanup'}
            onClick={() => runBulkAction('cleanup', [], '当前筛选终态任务已清理')}
          >
            批量清理
          </Button>
        </div>
      </article>

      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-heading text-xl text-on-surface">统一任务列表</h2>
          <div className="flex gap-2">
            <Button
              variant="tertiary"
              size="sm"
              disabled={cursorStack.length === 0}
              onClick={() => {
                const previous = cursorStack[cursorStack.length - 1];
                setCursorStack((current) => current.slice(0, -1));
                reload(previous, false).catch((requestError) => {
                  toast.error(requestError instanceof Error ? requestError.message : '加载上一页失败');
                });
              }}
            >
              上一页
            </Button>
            <Button
              variant="tertiary"
              size="sm"
              disabled={!jobsPage.next_cursor}
              onClick={() => {
                setCursorStack((current) => [...current, currentCursor]);
                reload(jobsPage.next_cursor ?? undefined, false).catch((requestError) => {
                  toast.error(requestError instanceof Error ? requestError.message : '加载下一页失败');
                });
              }}
            >
              下一页
            </Button>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          {jobsPage.items.map((job: AsyncJobStatus) => (
            <article key={job.job_id} className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="font-medium text-on-surface">
                    {jobKindText(job.kind)}
                    <span className="ml-2 text-xs text-muted">{job.job_id}</span>
                  </p>
                  <p className="mt-1 text-sm text-muted">
                    状态：{jobStatusText(job.status)} · 优先级：P{job.priority} · 尝试次数：{job.attempt}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    桶：{job.bucket || '--'} · 对象：{job.object_key || '--'} · 站点：{job.site_id || '--'}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    Checkpoint：{job.checkpoint ?? '--'} · Lease：{job.lease_owner || '--'}
                    {job.lease_until ? ` (${new Date(job.lease_until).toLocaleString()})` : ''}
                  </p>
                  {job.last_error ? <p className="mt-1 text-xs text-error">错误：{toBilingualPrompt(job.last_error)}</p> : null}
                </div>
                <div className="flex flex-wrap gap-2">
                  {job.retryable ? (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => runBulkAction('retry', [job.job_id], `任务 ${job.job_id} 已重试`)}
                    >
                      重试
                    </Button>
                  ) : null}
                  {!job.terminal ? (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => runBulkAction('skip', [job.job_id], `任务 ${job.job_id} 已跳过`)}
                    >
                      跳过
                    </Button>
                  ) : null}
                  {job.terminal ? (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => runBulkAction('cleanup', [job.job_id], `任务 ${job.job_id} 已清理`)}
                    >
                      清理
                    </Button>
                  ) : null}
                  {job.kind === 'heal' && job.status === 'running' ? (
                    <ConfirmActionDialog
                      title={`取消任务 ${job.job_id}`}
                      description="取消任务可能导致后台处理不完整，请确认审计原因。"
                      actionLabel="取消任务"
                      onConfirm={async (reason) => {
                        try {
                          await jobsService.cancel(client, job.job_id, reason);
                          toast.success(`任务 ${job.job_id} 已取消`);
                          await reload();
                        } catch (requestError) {
                          toast.error(requestError instanceof Error ? requestError.message : '取消任务失败');
                          throw requestError;
                        }
                      }}
                    />
                  ) : null}
                </div>
              </div>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-on-surface/5">
                <div className="h-full bg-primary" style={{ width: `${Math.max(4, job.progress * 100)}%` }} />
              </div>
              <p className="mt-2 text-xs text-muted">
                创建：{new Date(job.created_at).toLocaleString()} · 更新：{new Date(job.updated_at).toLocaleString()}
              </p>
            </article>
          ))}
          {jobsPage.items.length === 0 ? <p className="text-sm text-muted">当前筛选条件下没有任务。</p> : null}
        </div>
      </article>
    </section>
  );
}
