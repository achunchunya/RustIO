import { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { auditService } from '../api/services';
import type { AuditEvent } from '../types';
import {
  PageHeader,
  Card,
  Field,
  Input,
  Select,
  Button,
  Badge,
  useToast,
  type BadgeTone
} from '../components/ui';

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

function outcomeTone(outcome: string): BadgeTone {
  if (outcome === 'success') return 'success';
  return 'error';
}

export function AuditPage({ client }: AuditPageProps) {
  const toast = useToast();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [limit, setLimit] = useState(200);
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [loading, setLoading] = useState(false);

  async function reload(nextLimit = limit, nextFilters = filters) {
    setLoading(true);
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
      toast.error(requestError instanceof Error ? requestError.message : '加载审计事件失败');
    });
    const interval = window.setInterval(() => { void reload(); }, 15000);
    return () => window.clearInterval(interval);
  }, [client]);

  return (
    <section className="space-y-6">
      <PageHeader
        title="审计事件"
        subtitle="用于策略审查与事故追踪的不可变事件流。"
        actions={
          <>
            <Field label="条数" htmlFor="audit-limit">
              <Select
                id="audit-limit"
                size="sm"
                value={limit}
                onChange={async (event) => {
                  const value = Number(event.target.value);
                  setLimit(value);
                  try {
                    await reload(value, filters);
                  } catch (requestError) {
                    toast.error(requestError instanceof Error ? requestError.message : '刷新审计事件失败');
                  }
                }}
              >
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
                <option value={500}>500</option>
                <option value={1000}>1000</option>
              </Select>
            </Field>
            <Button
              variant="secondary"
              onClick={async () => {
                try {
                  await reload();
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '刷新审计事件失败');
                }
              }}
            >
              刷新
            </Button>
            <Button
              variant="primary"
              onClick={async () => {
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
                  toast.success('审计文件已导出');
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '导出审计文件失败');
                }
              }}
            >
              导出 JSON
            </Button>
          </>
        }
      />

      <Card>
        <div className="grid gap-3 md:grid-cols-4">
          <Input
            value={filters.actor}
            onChange={(event) => setFilters((current) => ({ ...current, actor: event.target.value }))}
            placeholder="操作人"
          />
          <Input
            value={filters.action}
            onChange={(event) => setFilters((current) => ({ ...current, action: event.target.value }))}
            placeholder="动作（如 bucket.create）"
          />
          <Input
            value={filters.resource}
            onChange={(event) => setFilters((current) => ({ ...current, resource: event.target.value }))}
            placeholder="资源（如 bucket/demo）"
          />
          <Select
            value={filters.outcome}
            onChange={(event) => setFilters((current) => ({ ...current, outcome: event.target.value }))}
          >
            <option value="">全部结果</option>
            <option value="success">success</option>
            <option value="failed">failed</option>
            <option value="cancelled">cancelled</option>
          </Select>
          <Input
            value={filters.keyword}
            onChange={(event) => setFilters((current) => ({ ...current, keyword: event.target.value }))}
            placeholder="关键字（匹配 actor/action/resource/reason/details）"
            className="md:col-span-2"
          />
          <Field label="开始时间" htmlFor="audit-from">
            <Input
              id="audit-from"
              type="datetime-local"
              value={filters.from}
              onChange={(event) => setFilters((current) => ({ ...current, from: event.target.value }))}
            />
          </Field>
          <Field label="结束时间" htmlFor="audit-to">
            <Input
              id="audit-to"
              type="datetime-local"
              value={filters.to}
              onChange={(event) => setFilters((current) => ({ ...current, to: event.target.value }))}
            />
          </Field>
          <div className="md:col-span-4 flex flex-wrap gap-2">
            <Button
              variant="primary"
              onClick={async () => {
                try {
                  await reload();
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '检索审计事件失败');
                }
              }}
            >
              应用筛选
            </Button>
            <Button
              variant="secondary"
              onClick={async () => {
                const reset = { ...EMPTY_FILTERS };
                setFilters(reset);
                try {
                  await reload(limit, reset);
                } catch (requestError) {
                  toast.error(requestError instanceof Error ? requestError.message : '清空筛选失败');
                }
              }}
            >
              清空筛选
            </Button>
          </div>
        </div>
      </Card>

      {loading ? <p className="text-sm text-muted">加载中...</p> : null}

      <Card className="p-0">
        <ul className="max-h-[32rem] divide-y divide-outline/50 overflow-auto">
          {events.map((event) => (
            <li key={event.id} className="p-3">
              <div className="flex items-start justify-between gap-3">
                <p className="font-mono text-xs text-primary">{event.action}</p>
                <Badge tone={outcomeTone(event.outcome)}>{event.outcome}</Badge>
              </div>
              <p className="mt-1 text-sm text-on-surface">{event.resource}</p>
              <p className="mt-1 text-xs text-muted">
                操作人：{event.actor} · 时间：{new Date(event.timestamp).toLocaleString()}
              </p>
              {event.reason ? <p className="mt-1 text-xs text-muted">原因：{event.reason}</p> : null}
            </li>
          ))}
        </ul>
      </Card>
    </section>
  );
}
