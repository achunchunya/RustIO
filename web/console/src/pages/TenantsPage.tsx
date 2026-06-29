import { useEffect, useMemo, useState } from 'react';
import { ApiClient } from '../api/client';
import { clusterService } from '../api/services';
import { ConfirmActionDialog } from '../components/ConfirmActionDialog';
import {
  Badge,
  Button,
  Card,
  Field,
  Input,
  PageHeader,
  Panel,
  ProgressBar
} from '../components/ui';
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
    <section className="space-y-6">
      <PageHeader title="租户管理" subtitle="租户配额、状态、归属组与生命周期操作。" />

      <Card className="space-y-4">
        {error ? <p className="text-sm text-error">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="text-sm text-primary">{toBilingualNotice(message)}</p> : null}

        <form
          className="grid gap-3 md:grid-cols-4"
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
          <Field label="租户 ID" htmlFor="new-tenant-id">
            <Input
              id="new-tenant-id"
              required
              value={newTenant.id}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, id: event.target.value.toLowerCase() }))
              }
              placeholder="tenant-id"
            />
          </Field>
          <Field label="显示名称" htmlFor="new-tenant-name">
            <Input
              id="new-tenant-name"
              required
              value={newTenant.display_name}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, display_name: event.target.value }))
              }
              placeholder="租户名称"
            />
          </Field>
          <Field label="归属组" htmlFor="new-tenant-group">
            <Input
              id="new-tenant-group"
              required
              value={newTenant.owner_group}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, owner_group: event.target.value }))
              }
            />
          </Field>
          <Field label="硬配额（TiB）" htmlFor="new-tenant-quota">
            <Input
              id="new-tenant-quota"
              required
              type="number"
              min="0.01"
              step="0.01"
              value={newTenant.hard_limit_tib}
              onChange={(event) =>
                setNewTenant((current) => ({ ...current, hard_limit_tib: event.target.value }))
              }
            />
          </Field>
          <div className="md:col-span-4">
            <Button type="submit" variant="primary" loading={creating}>
              {creating ? '创建中...' : '创建租户'}
            </Button>
          </div>
        </form>
      </Card>

      <div className="space-y-3">
        {sortedTenants.map((tenant) => {
          const draft = drafts[tenant.id] ?? toDraft(tenant);
          const usageRatio =
            tenant.hard_limit_bytes > 0 ? Math.min(100, (tenant.used_bytes / tenant.hard_limit_bytes) * 100) : 0;
          const usageTone = usageRatio >= 90 ? 'error' : usageRatio >= 75 ? 'warning' : 'primary';
          return (
            <Card key={tenant.id} className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-lg font-medium text-on-surface">
                    {tenant.display_name}
                    <span className="ml-2 font-mono text-xs text-muted">{tenant.id}</span>
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    owner_group: {tenant.owner_group}
                    {tenant.domain_name ? ` · 域: ${tenant.domain_name}` : ''} · 创建于{' '}
                    {new Date(tenant.created_at).toLocaleString()}
                  </p>
                </div>
                <Badge tone={tenant.enabled ? 'success' : 'warning'}>
                  {tenant.enabled ? 'active' : 'suspended'}
                </Badge>
              </div>

              <p className="text-xs text-muted">
                已用 {formatBytes(tenant.used_bytes)} / 配额 {formatBytes(tenant.hard_limit_bytes)} ({usageRatio.toFixed(1)}%)
              </p>
              <ProgressBar ratio={usageRatio / 100} tone={usageTone} />

              <div className="grid gap-3 pt-2 md:grid-cols-3">
                <Field label="显示名称" htmlFor={`edit-name-${tenant.id}`}>
                  <Input
                    id={`edit-name-${tenant.id}`}
                    size="sm"
                    value={draft.display_name}
                    onChange={(event) =>
                      setDrafts((current) => ({
                        ...current,
                        [tenant.id]: { ...draft, display_name: event.target.value }
                      }))
                    }
                  />
                </Field>
                <Field label="归属组" htmlFor={`edit-group-${tenant.id}`}>
                  <Input
                    id={`edit-group-${tenant.id}`}
                    size="sm"
                    value={draft.owner_group}
                    onChange={(event) =>
                      setDrafts((current) => ({
                        ...current,
                        [tenant.id]: { ...draft, owner_group: event.target.value }
                      }))
                    }
                  />
                </Field>
                <Field label="硬配额（TiB）" htmlFor={`edit-quota-${tenant.id}`}>
                  <Input
                    id={`edit-quota-${tenant.id}`}
                    size="sm"
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
                  />
                </Field>
              </div>

              <div className="flex flex-wrap gap-2 pt-1">
                <Button
                  variant="secondary"
                  size="sm"
                  loading={savingTenantId === tenant.id}
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
                </Button>
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
            </Card>
          );
        })}
        {sortedTenants.length === 0 ? (
          <Panel className="text-sm text-muted">暂无租户</Panel>
        ) : null}
      </div>
    </section>
  );
}
