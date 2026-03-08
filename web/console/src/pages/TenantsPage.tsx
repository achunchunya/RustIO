import { useEffect, useMemo, useState } from 'react';
import { ApiClient } from '../api/client';
import { clusterService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import type { TenantSpec } from '../types';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';

type TenantsPageProps = {
  client: ApiClient;
};

type TenantEditDraft = {
  display_name: string;
  owner_group: string;
  hard_limit_tib: string;
};

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const sized = value / 1024 ** exponent;
  return `${sized.toFixed(sized >= 100 ? 0 : sized >= 10 ? 1 : 2)} ${units[exponent]}`;
}

function tibToBytes(tib: string): number {
  const parsed = Number(tib);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 0;
  }
  return Math.floor(parsed * 1024 ** 4);
}

function toDraft(tenant: TenantSpec): TenantEditDraft {
  return {
    display_name: tenant.display_name,
    owner_group: tenant.owner_group,
    hard_limit_tib: (tenant.hard_limit_bytes / 1024 ** 4).toFixed(2)
  };
}

export function TenantsPage({ client }: TenantsPageProps) {
  const [tenants, setTenants] = useState<TenantSpec[]>([]);
  const [drafts, setDrafts] = useState<Record<string, TenantEditDraft>>({});
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [creating, setCreating] = useState(false);
  const [savingTenantId, setSavingTenantId] = useState('');
  const [newTenant, setNewTenant] = useState({
    id: '',
    display_name: '',
    owner_group: 'platform-admins',
    hard_limit_tib: '1'
  });

  async function reload() {
    const rows = await clusterService.tenants(client);
    setTenants(rows);
    setDrafts(
      Object.fromEntries(rows.map((tenant) => [tenant.id, toDraft(tenant)])) as Record<
        string,
        TenantEditDraft
      >
    );
  }

  useEffect(() => {
    reload().catch((requestError) => {
      setError(requestError instanceof Error ? requestError.message : '加载租户失败');
    });
  }, [client]);

  const sortedTenants = useMemo(() => {
    return [...tenants].sort((left, right) => left.id.localeCompare(right.id));
  }, [tenants]);

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h1 className="font-heading text-2xl text-white">租户管理</h1>
        <p className="mt-1 text-sm text-slate-300">租户配额、状态、归属组与生命周期操作。</p>
        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}

        <form
          className="mt-4 grid gap-3 rounded-lg border border-white/10 bg-black/10 p-4 md:grid-cols-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setCreating(true);
            setError('');
            setMessage('');
            try {
              const hardLimit = tibToBytes(newTenant.hard_limit_tib);
              if (hardLimit <= 0) {
                throw new Error('租户硬配额必须大于 0');
              }
              await clusterService.createTenant(client, {
                id: newTenant.id.trim(),
                display_name: newTenant.display_name.trim(),
                owner_group: newTenant.owner_group.trim(),
                hard_limit_bytes: hardLimit
              });
              setNewTenant({
                id: '',
                display_name: '',
                owner_group: 'platform-admins',
                hard_limit_tib: '1'
              });
              setMessage(`租户 ${newTenant.id.trim()} 创建成功`);
              await reload();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建租户失败');
            } finally {
              setCreating(false);
            }
          }}
        >
          <label className="text-sm text-slate-300">
            租户 ID
            <input
              required
              value={newTenant.id}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, id: event.target.value.toLowerCase() }))
              }
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="tenant-id"
            />
          </label>
          <label className="text-sm text-slate-300">
            显示名称
            <input
              required
              value={newTenant.display_name}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, display_name: event.target.value }))
              }
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              placeholder="租户名称"
            />
          </label>
          <label className="text-sm text-slate-300">
            归属组
            <input
              required
              value={newTenant.owner_group}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, owner_group: event.target.value }))
              }
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            />
          </label>
          <label className="text-sm text-slate-300">
            硬配额（TiB）
            <input
              required
              type="number"
              min="0.01"
              step="0.01"
              value={newTenant.hard_limit_tib}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, hard_limit_tib: event.target.value }))
              }
              className="mt-1 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            />
          </label>
          <div className="md:col-span-4">
            <button
              type="submit"
              disabled={creating}
              className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
            >
              {creating ? '创建中...' : '创建租户'}
            </button>
          </div>
        </form>
      </article>

      <div className="space-y-3">
        {sortedTenants.map((tenant) => {
          const draft = drafts[tenant.id] ?? toDraft(tenant);
          const usageRatio =
            tenant.hard_limit_bytes > 0 ? Math.min(100, (tenant.used_bytes / tenant.hard_limit_bytes) * 100) : 0;
          return (
            <article key={tenant.id} className="rounded-lg border border-white/10 bg-ink-800/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-lg font-medium text-white">
                    {tenant.display_name}
                    <span className="ml-2 font-mono text-xs text-slate-400">{tenant.id}</span>
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    owner_group: {tenant.owner_group} · 创建于 {new Date(tenant.created_at).toLocaleString()}
                  </p>
                </div>
                <span
                  className={`rounded px-2 py-1 text-xs ${
                    tenant.enabled ? 'bg-signal-500/15 text-signal-500' : 'bg-amber-500/15 text-amber-300'
                  }`}
                >
                  {tenant.enabled ? 'active' : 'suspended'}
                </span>
              </div>

              <p className="mt-2 text-xs text-slate-300">
                已用 {formatBytes(tenant.used_bytes)} / 配额 {formatBytes(tenant.hard_limit_bytes)} ({usageRatio.toFixed(1)}%)
              </p>
              <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/10">
                <div
                  className={`h-full ${usageRatio >= 90 ? 'bg-rose-500' : usageRatio >= 75 ? 'bg-amber-400' : 'bg-signal-500'}`}
                  style={{ width: `${usageRatio}%` }}
                />
              </div>

              <div className="mt-4 grid gap-2 md:grid-cols-3">
                <label className="text-xs text-slate-300">
                  显示名称
                  <input
                    value={draft.display_name}
                    onChange={(event) =>
                      setDrafts((current) => ({
                        ...current,
                        [tenant.id]: { ...draft, display_name: event.target.value }
                      }))
                    }
                    className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
                  />
                </label>
                <label className="text-xs text-slate-300">
                  归属组
                  <input
                    value={draft.owner_group}
                    onChange={(event) =>
                      setDrafts((current) => ({
                        ...current,
                        [tenant.id]: { ...draft, owner_group: event.target.value }
                      }))
                    }
                    className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
                  />
                </label>
                <label className="text-xs text-slate-300">
                  硬配额（TiB）
                  <input
                    type="number"
                    min="0.01"
                    step="0.01"
                    value={draft.hard_limit_tib}
                    onChange={(event) =>
                      setDrafts((current) => ({
                        ...current,
                        [tenant.id]: { ...draft, hard_limit_tib: event.target.value }
                      }))
                    }
                    className="mt-1 h-10 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
                  />
                </label>
              </div>

              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5 disabled:opacity-60"
                  disabled={savingTenantId === tenant.id}
                  onClick={async () => {
                    setSavingTenantId(tenant.id);
                    setError('');
                    setMessage('');
                    try {
                      const hardLimit = tibToBytes(draft.hard_limit_tib);
                      if (hardLimit <= 0) {
                        throw new Error('租户硬配额必须大于 0');
                      }
                      await clusterService.updateTenant(client, tenant.id, {
                        display_name: draft.display_name.trim(),
                        owner_group: draft.owner_group.trim(),
                        hard_limit_bytes: hardLimit
                      });
                      setMessage(`租户 ${tenant.id} 已更新`);
                      await reload();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '更新租户失败');
                    } finally {
                      setSavingTenantId('');
                    }
                  }}
                >
                  {savingTenantId === tenant.id ? '更新中...' : '保存修改'}
                </button>
                {tenant.enabled ? (
                  <ConfirmActionDialog
                    title={`暂停租户 ${tenant.id}`}
                    description="暂停后该租户将被标记为不可用，建议先确认业务窗口。"
                    actionLabel="暂停租户"
                    onConfirm={async (reason) => {
                      setError('');
                      setMessage('');
                      try {
                        await clusterService.suspendTenant(client, tenant.id, reason);
                        setMessage(`租户 ${tenant.id} 已暂停`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '暂停租户失败');
                        throw requestError;
                      }
                    }}
                  />
                ) : (
                  <ConfirmActionDialog
                    title={`恢复租户 ${tenant.id}`}
                    description="恢复后该租户将重新进入 active 状态。"
                    actionLabel="恢复租户"
                    onConfirm={async (reason) => {
                      setError('');
                      setMessage('');
                      try {
                        await clusterService.resumeTenant(client, tenant.id, reason);
                        setMessage(`租户 ${tenant.id} 已恢复`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '恢复租户失败');
                        throw requestError;
                      }
                    }}
                  />
                )}
                {tenant.id !== 'default' ? (
                  <ConfirmActionDialog
                    title={`删除租户 ${tenant.id}`}
                    description="删除后将移除租户配置与配额记录，该操作不可撤销。"
                    actionLabel="删除租户"
                    onConfirm={async (reason) => {
                      setError('');
                      setMessage('');
                      try {
                        await clusterService.deleteTenant(client, tenant.id, reason);
                        setMessage(`租户 ${tenant.id} 已删除`);
                        await reload();
                      } catch (requestError) {
                        setError(requestError instanceof Error ? requestError.message : '删除租户失败');
                        throw requestError;
                      }
                    }}
                  />
                ) : null}
              </div>
            </article>
          );
        })}
        {sortedTenants.length === 0 ? (
          <p className="rounded-lg border border-white/10 bg-ink-800/70 p-4 text-sm text-slate-400">暂无租户</p>
        ) : null}
      </div>
    </section>
  );
}
