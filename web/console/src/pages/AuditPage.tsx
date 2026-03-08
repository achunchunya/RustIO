import { useEffect, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { auditService } from '../api/services';
import type { AuditEvent } from '../types';

type AuditPageProps = {
  client: ApiClient;
};

type AuditFilters = {
  actor: string;
  action: string;
  resource: string;
  outcome: string;
  keyword: string;
  from: string;
  to: string;
};

const EMPTY_FILTERS: AuditFilters = {
  actor: '',
  action: '',
  resource: '',
  outcome: '',
  keyword: '',
  from: '',
  to: ''
};

function toIsoOrUndefined(value: string) {
  if (!value) return undefined;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}

export function AuditPage({ client }: AuditPageProps) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [limit, setLimit] = useState(200);
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  async function reload(nextLimit = limit, nextFilters = filters) {
    setLoading(true);
    setError('');
    const rows = await auditService.events(client, {
      limit: nextLimit,
      actor: nextFilters.actor || undefined,
      action: nextFilters.action || undefined,
      resource: nextFilters.resource || undefined,
      outcome: nextFilters.outcome || undefined,
      keyword: nextFilters.keyword || undefined,
      from: toIsoOrUndefined(nextFilters.from),
      to: toIsoOrUndefined(nextFilters.to)
    });
    setEvents(rows);
    setLoading(false);
  }

  useEffect(() => {
    reload().catch((requestError) => {
      setLoading(false);
      setError(requestError instanceof Error ? requestError.message : '加载审计事件失败');
    });
  }, [client]);

  return (
    <section className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-heading text-2xl text-white">审计事件</h1>
          <p className="mt-1 text-sm text-slate-300">用于策略审查与事故追踪的不可变事件流。</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs text-slate-400">
            条数
            <select
              value={limit}
              onChange={async (event) => {
                const value = Number(event.target.value);
                setLimit(value);
                try {
                  await reload(value, filters);
                } catch (requestError) {
                  setError(requestError instanceof Error ? requestError.message : '刷新审计事件失败');
                }
              }}
              className="ml-2 h-10 rounded-md border border-white/15 bg-ink-900 px-2 text-sm text-slate-100"
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
              <option value={1000}>1000</option>
            </select>
          </label>
          <button
            className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
            onClick={async () => {
              try {
                await reload();
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '刷新审计事件失败');
              }
            }}
          >
            刷新
          </button>
          <button
            className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white"
            onClick={async () => {
              setError('');
              setMessage('');
              try {
                const content = await auditService.exportEvents(client);
                const blob = new Blob([content], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `rustio-audit-${Date.now()}.json`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
                setMessage('审计文件已导出');
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '导出审计文件失败');
              }
            }}
          >
            导出 JSON
          </button>
        </div>
      </div>

      <article className="mt-4 grid gap-3 rounded-xl border border-white/10 bg-black/10 p-3 md:grid-cols-4">
        <input
          value={filters.actor}
          onChange={(event) => setFilters((current) => ({ ...current, actor: event.target.value }))}
          placeholder="操作人"
          className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
        />
        <input
          value={filters.action}
          onChange={(event) => setFilters((current) => ({ ...current, action: event.target.value }))}
          placeholder="动作（如 bucket.create）"
          className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
        />
        <input
          value={filters.resource}
          onChange={(event) => setFilters((current) => ({ ...current, resource: event.target.value }))}
          placeholder="资源（如 bucket/demo）"
          className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
        />
        <select
          value={filters.outcome}
          onChange={(event) => setFilters((current) => ({ ...current, outcome: event.target.value }))}
          className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
        >
          <option value="">全部结果</option>
          <option value="success">success</option>
          <option value="failed">failed</option>
          <option value="cancelled">cancelled</option>
        </select>
        <input
          value={filters.keyword}
          onChange={(event) => setFilters((current) => ({ ...current, keyword: event.target.value }))}
          placeholder="关键字（匹配 actor/action/resource/reason/details）"
          className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100 md:col-span-2"
        />
        <label className="text-xs text-slate-400">
          开始时间
          <input
            type="datetime-local"
            value={filters.from}
            onChange={(event) => setFilters((current) => ({ ...current, from: event.target.value }))}
            className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
        </label>
        <label className="text-xs text-slate-400">
          结束时间
          <input
            type="datetime-local"
            value={filters.to}
            onChange={(event) => setFilters((current) => ({ ...current, to: event.target.value }))}
            className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
          />
        </label>
        <div className="md:col-span-4 flex flex-wrap gap-2">
          <button
            className="h-10 rounded-md bg-signal-600 px-4 text-sm text-white"
            onClick={async () => {
              setError('');
              try {
                await reload();
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '检索审计事件失败');
              }
            }}
          >
            应用筛选
          </button>
          <button
            className="h-10 rounded-md border border-white/15 px-4 text-sm text-slate-100 hover:bg-white/5"
            onClick={async () => {
              const reset = { ...EMPTY_FILTERS };
              setFilters(reset);
              setError('');
              try {
                await reload(limit, reset);
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '清空筛选失败');
              }
            }}
          >
            清空筛选
          </button>
        </div>
      </article>

      {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
      {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}
      {loading ? <p className="mt-3 text-sm text-slate-300">加载中...</p> : null}

      <ul className="mt-4 max-h-[32rem] space-y-2 overflow-auto pr-1">
        {events.map((event) => (
          <li key={event.id} className="rounded-lg border border-white/10 bg-black/10 p-3">
            <p className="font-mono text-xs text-signal-500">{event.action}</p>
            <p className="mt-1 text-sm text-slate-200">{event.resource}</p>
            <p className="mt-1 text-xs text-slate-400">
              操作人：{event.actor} · 结果：{event.outcome} · 时间：{new Date(event.timestamp).toLocaleString()}
            </p>
            {event.reason ? <p className="mt-1 text-xs text-slate-500">原因：{event.reason}</p> : null}
          </li>
        ))}
      </ul>
    </section>
  );
}
