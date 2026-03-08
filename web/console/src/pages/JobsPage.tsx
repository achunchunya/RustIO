import { useEffect, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { jobsService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import { StatCard } from '../components/StatCard';
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
  const [target, setTarget] = useState('cluster');
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [jobsPage, setJobsPage] = useState<AsyncJobPage>({ items: [], next_cursor: null });
  const [summary, setSummary] = useState<AsyncJobSummary | null>(null);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [currentCursor, setCurrentCursor] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
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
      setError(requestError instanceof Error ? requestError.message : '加载统一任务列表失败');
    });
  }, [client, filters]);

  async function runBulkAction(
    action: 'retry' | 'cleanup' | 'skip',
    jobIds: string[] = [],
    successMessage?: string
  ) {
    setActioning(action);
    setError('');
    setMessage('');
    try {
      if (action === 'retry') {
        await jobsService.retryAsyncJobs(client, buildQuery(filters), jobIds);
      } else if (action === 'cleanup') {
        await jobsService.cleanupAsyncJobs(client, buildQuery(filters), jobIds);
      } else {
        await jobsService.skipAsyncJobs(client, buildQuery(filters), jobIds);
      }
      setMessage(successMessage ?? '批量操作已完成');
      await reload();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '批量任务操作失败');
    } finally {
      setActioning('');
    }
  }

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="font-heading text-2xl text-white">后台任务</h1>
            <p className="mt-1 text-sm text-slate-300">统一查看 replication / lifecycle / notification / failover / failback。</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
              placeholder="修复目标"
            />
            <button
              className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white disabled:opacity-60"
              disabled={starting}
              onClick={async () => {
                setStarting(true);
                setError('');
                setMessage('');
                try {
                  await jobsService.heal(client, target || 'cluster');
                  setMessage('修复任务已启动');
                  await reload();
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '启动修复失败');
                } finally {
                  setStarting(false);
                }
              }}
            >
              {starting ? '启动中...' : '启动修复'}
            </button>
            <button
              className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
              onClick={() => {
                reload().catch((requestError) => {
                  setError(requestError instanceof Error ? requestError.message : '刷新任务失败');
                });
              }}
            >
              {loading ? '刷新中...' : '刷新'}
            </button>
          </div>
        </div>

        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}

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

        <div className="mt-4 grid gap-2 rounded-xl border border-white/10 bg-black/10 p-4 md:grid-cols-6">
          <select
            value={filters.kind}
            onChange={(event) => setFilters((current) => ({ ...current, kind: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
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
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
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
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            placeholder="桶名"
          />
          <input
            value={filters.site_id}
            onChange={(event) => setFilters((current) => ({ ...current, site_id: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            placeholder="站点 ID"
          />
          <input
            value={filters.keyword}
            onChange={(event) => setFilters((current) => ({ ...current, keyword: event.target.value }))}
            className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            placeholder="关键字"
          />
          <label className="flex items-center gap-2 rounded-md border border-white/10 px-3 text-sm text-slate-300">
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
          <button
            className="h-10 rounded-md border border-amber-300/30 px-3 text-sm text-amber-200 hover:bg-amber-300/10 disabled:opacity-60"
            disabled={actioning === 'retry'}
            onClick={() => runBulkAction('retry', [], '当前筛选任务已批量重试')}
          >
            {actioning === 'retry' ? '处理中...' : '批量重试'}
          </button>
          <button
            className="h-10 rounded-md border border-sky-300/30 px-3 text-sm text-sky-200 hover:bg-sky-300/10 disabled:opacity-60"
            disabled={actioning === 'skip'}
            onClick={() => runBulkAction('skip', [], '当前筛选任务已批量跳过')}
          >
            {actioning === 'skip' ? '处理中...' : '批量跳过'}
          </button>
          <button
            className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
            disabled={actioning === 'cleanup'}
            onClick={() => runBulkAction('cleanup', [], '当前筛选终态任务已清理')}
          >
            {actioning === 'cleanup' ? '处理中...' : '批量清理'}
          </button>
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-heading text-xl text-white">统一任务列表</h2>
          <div className="flex gap-2">
            <button
              className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
              disabled={cursorStack.length === 0}
              onClick={() => {
                const previous = cursorStack[cursorStack.length - 1];
                setCursorStack((current) => current.slice(0, -1));
                reload(previous, false).catch((requestError) => {
                  setError(requestError instanceof Error ? requestError.message : '加载上一页失败');
                });
              }}
            >
              上一页
            </button>
            <button
              className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
              disabled={!jobsPage.next_cursor}
              onClick={() => {
                setCursorStack((current) => [...current, currentCursor]);
                reload(jobsPage.next_cursor ?? undefined, false).catch((requestError) => {
                  setError(requestError instanceof Error ? requestError.message : '加载下一页失败');
                });
              }}
            >
              下一页
            </button>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          {jobsPage.items.map((job: AsyncJobStatus) => (
            <article key={job.job_id} className="rounded-lg border border-white/10 bg-black/10 p-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="font-medium text-white">
                    {jobKindText(job.kind)}
                    <span className="ml-2 text-xs text-slate-400">{job.job_id}</span>
                  </p>
                  <p className="mt-1 text-sm text-slate-300">
                    状态：{jobStatusText(job.status)} · 优先级：P{job.priority} · 尝试次数：{job.attempt}
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    桶：{job.bucket || '--'} · 对象：{job.object_key || '--'} · 站点：{job.site_id || '--'}
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    Checkpoint：{job.checkpoint ?? '--'} · Lease：{job.lease_owner || '--'}
                    {job.lease_until ? ` (${new Date(job.lease_until).toLocaleString()})` : ''}
                  </p>
                  {job.last_error ? <p className="mt-1 text-xs text-rose-300">错误：{toBilingualPrompt(job.last_error)}</p> : null}
                </div>
                <div className="flex flex-wrap gap-2">
                  {job.retryable ? (
                    <button
                      className="h-9 rounded-md border border-amber-300/30 px-3 text-xs text-amber-200 hover:bg-amber-300/10"
                      onClick={() => runBulkAction('retry', [job.job_id], `任务 ${job.job_id} 已重试`)}
                    >
                      重试
                    </button>
                  ) : null}
                  {!job.terminal ? (
                    <button
                      className="h-9 rounded-md border border-sky-300/30 px-3 text-xs text-sky-200 hover:bg-sky-300/10"
                      onClick={() => runBulkAction('skip', [job.job_id], `任务 ${job.job_id} 已跳过`)}
                    >
                      跳过
                    </button>
                  ) : null}
                  {job.terminal ? (
                    <button
                      className="h-9 rounded-md border border-white/15 px-3 text-xs text-slate-100 hover:bg-white/5"
                      onClick={() => runBulkAction('cleanup', [job.job_id], `任务 ${job.job_id} 已清理`)}
                    >
                      清理
                    </button>
                  ) : null}
                  {job.kind === 'heal' && job.status === 'running' ? (
                    <ConfirmActionDialog
                      title={`取消任务 ${job.job_id}`}
                      description="取消任务可能导致后台处理不完整，请确认审计原因。"
                      actionLabel="取消任务"
                      onConfirm={async (reason) => {
                        setError('');
                        setMessage('');
                        try {
                          await jobsService.cancel(client, job.job_id, reason);
                          setMessage(`任务 ${job.job_id} 已取消`);
                          await reload();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '取消任务失败');
                          throw requestError;
                        }
                      }}
                    />
                  ) : null}
                </div>
              </div>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/10">
                <div className="h-full bg-signal-500" style={{ width: `${Math.max(4, job.progress * 100)}%` }} />
              </div>
              <p className="mt-2 text-xs text-slate-500">
                创建：{new Date(job.created_at).toLocaleString()} · 更新：{new Date(job.updated_at).toLocaleString()}
              </p>
            </article>
          ))}
          {jobsPage.items.length === 0 ? <p className="text-sm text-slate-400">当前筛选条件下没有任务。</p> : null}
        </div>
      </article>
    </section>
  );
}
