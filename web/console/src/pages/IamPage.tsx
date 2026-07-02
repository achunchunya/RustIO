import { useEffect, useMemo, useState } from 'react';
import { toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { iamService, systemService } from '../api/services';
import { useConfirm, useToast, Dialog, Button, Field, Input } from '../components/ui';
import type {
  ConsoleSession,
  IamGroup,
  IamPolicy,
  IamUser,
  ServiceAccount,
  StsSession,
  SystemMetricsSummary
} from '../types';

type IamPageProps = {
  client: ApiClient;
};

export function IamPage({ client }: IamPageProps) {
  const confirm = useConfirm();
  const toast = useToast();
  const [users, setUsers] = useState<IamUser[]>([]);
  const [groups, setGroups] = useState<IamGroup[]>([]);
  const [policies, setPolicies] = useState<IamPolicy[]>([]);
  const [serviceAccounts, setServiceAccounts] = useState<ServiceAccount[]>([]);
  const [stsSessions, setStsSessions] = useState<StsSession[]>([]);
  const [consoleSessions, setConsoleSessions] = useState<ConsoleSession[]>([]);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);

  const [userForm, setUserForm] = useState({
    username: '',
    display_name: '',
    password: '',
    role: 'viewer'
  });
  const [groupForm, setGroupForm] = useState({ name: '' });
  const [groupMemberDraft, setGroupMemberDraft] = useState<Record<string, string>>({});
  const [policyForm, setPolicyForm] = useState({
    name: '',
    document: '{\n  "Version": "2012-10-17",\n  "Statement": []\n}'
  });
  const [policyPrincipalDraft, setPolicyPrincipalDraft] = useState<Record<string, string>>({});
  const [serviceForm, setServiceForm] = useState({ owner: '' });
  const [stsForm, setStsForm] = useState({ principal: '', ttl_minutes: 60 });
  const [busy, setBusy] = useState(false);
  const [userActionKey, setUserActionKey] = useState('');
  const [resetTarget, setResetTarget] = useState<string | null>(null);
  const [resetPasswordValue, setResetPasswordValue] = useState('');
  const [resetError, setResetError] = useState('');
  const [resetBusy, setResetBusy] = useState(false);

  const sortedUsers = useMemo(
    () => [...users].sort((left, right) => left.username.localeCompare(right.username)),
    [users]
  );

  async function reloadAll() {
    const [usersRows, groupsRows, policyRows, serviceRows, stsRows, consoleSessionRows, metricsSummary] = await Promise.all([
      iamService.users(client),
      iamService.groups(client),
      iamService.policies(client),
      iamService.serviceAccounts(client),
      iamService.stsSessions(client),
      iamService.consoleSessions(client),
      systemService.metricsSummary(client)
    ]);
    setUsers(usersRows);
    setGroups(groupsRows);
    setPolicies(policyRows);
    setServiceAccounts(serviceRows);
    setStsSessions(stsRows);
    setConsoleSessions(consoleSessionRows);
    setSummary(metricsSummary);
    if (!serviceForm.owner && usersRows[0]) {
      setServiceForm({ owner: usersRows[0].username });
    }
    if (!stsForm.principal && usersRows[0]) {
      setStsForm((current) => ({ ...current, principal: usersRows[0].username }));
    }
  }

  useEffect(() => {
    reloadAll().catch((requestError) => {
      toast.error(requestError instanceof Error ? requestError.message : '加载 IAM 失败');
    });
  }, [client]);

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h1 className="font-heading text-2xl text-on-surface">身份与访问</h1>
        <p className="mt-1 text-sm text-muted">用户、组、策略、服务账号、控制台会话、STS 会话管理。</p>
        {summary ? (
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3 text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">IAM</p>
              <p className="mt-2 text-on-surface">用户 {summary.iam.users_enabled}/{summary.iam.users_total}</p>
              <p className="mt-1">组 {summary.iam.groups_total} / 策略 {summary.iam.policies_total}</p>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3 text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">服务账号</p>
              <p className="mt-2 text-on-surface">{summary.iam.service_accounts_enabled}/{summary.iam.service_accounts_total}</p>
              <p className="mt-1">控制面已纳入统一摘要</p>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3 text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">控制台会话</p>
              <p className="mt-2 text-on-surface">{summary.sessions.admin_sessions_active}/{summary.sessions.admin_sessions_total}</p>
              <p className="mt-1">24h 内到期 {summary.sessions.admin_sessions_expiring_24h}</p>
            </div>
            <div className="rounded-lg border border-outline/60 bg-surface-container-high p-3 text-sm text-muted">
              <p className="text-xs uppercase tracking-[0.2em] text-muted">STS 会话</p>
              <p className="mt-2 text-on-surface">{summary.sessions.sts_sessions_active}/{summary.sessions.sts_sessions_total}</p>
              <p className="mt-1">24h 内到期 {summary.sessions.sts_sessions_expiring_24h}</p>
            </div>
          </div>
        ) : null}
      </article>

      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h2 className="font-heading text-xl text-on-surface">用户</h2>
        <form
          className="mt-3 grid gap-3 md:grid-cols-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            try {
              await iamService.createUser(client, userForm);
              toast.success(`用户 ${userForm.username} 创建成功`);
              setUserForm({ username: '', display_name: '', password: '', role: 'viewer' });
              await reloadAll();
            } catch (requestError) {
              toast.error(requestError instanceof Error ? requestError.message : '创建用户失败');
            } finally {
              setBusy(false);
            }
          }}
        >
          <input
            required
            value={userForm.username}
            onChange={(event) => setUserForm((current) => ({ ...current, username: event.target.value }))}
            placeholder="用户名"
            className="h-11 rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
          />
          <input
            required
            value={userForm.display_name}
            onChange={(event) =>
              setUserForm((current) => ({ ...current, display_name: event.target.value }))
            }
            placeholder="显示名称"
            className="h-11 rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
          />
          <input
            required
            type="password"
            value={userForm.password}
            onChange={(event) => setUserForm((current) => ({ ...current, password: event.target.value }))}
            placeholder="密码"
            className="h-11 rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
          />
          <div className="flex gap-2">
            <select
              value={userForm.role}
              onChange={(event) => setUserForm((current) => ({ ...current, role: event.target.value }))}
              className="h-11 flex-1 rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
            >
              <option value="viewer">viewer</option>
              <option value="operator">operator</option>
              <option value="admin">admin</option>
            </select>
            <Button type="submit" variant="primary" loading={busy}>
              创建
            </Button>
          </div>
        </form>
        <div className="mt-3 overflow-hidden rounded-lg border border-outline/60">
          <table className="w-full text-left text-sm">
            <thead className="bg-on-surface/5 text-muted">
              <tr>
                <th className="px-3 py-2">用户名</th>
                <th className="px-3 py-2">显示名</th>
                <th className="px-3 py-2">角色</th>
                <th className="px-3 py-2">状态</th>
                <th className="px-3 py-2">操作</th>
              </tr>
            </thead>
            <tbody>
              {sortedUsers.map((user) => (
                <tr key={user.username} className="border-t border-outline/60">
                  <td className="px-3 py-2 font-mono text-xs text-primary">{user.username}</td>
                  <td className="px-3 py-2 text-on-surface">{user.display_name}</td>
                  <td className="px-3 py-2 text-muted">{user.role}</td>
                  <td className="px-3 py-2 text-muted">{user.enabled ? '启用' : '禁用'}</td>
                  <td className="px-3 py-2">
                    <div className="flex gap-2">
                      {user.enabled ? (
                        <Button
                          variant="danger"
                          size="sm"
                          loading={userActionKey === `${user.username}:disable`}
                          onClick={async () => {
                            if (!await confirm(`确认禁用用户 ${user.username}？`)) return;
                            setUserActionKey(`${user.username}:disable`);
                            try {
                              await iamService.disableUser(client, user.username);
                              toast.success(`用户 ${user.username} 已禁用`);
                              await reloadAll();
                            } catch (requestError) {
                              toast.error(requestError instanceof Error ? requestError.message : '禁用用户失败');
                            } finally {
                              setUserActionKey('');
                            }
                          }}
                        >
                          禁用
                        </Button>
                      ) : (
                        <Button
                          variant="secondary"
                          size="sm"
                          loading={userActionKey === `${user.username}:enable`}
                          onClick={async () => {
                            setUserActionKey(`${user.username}:enable`);
                            try {
                              await iamService.enableUser(client, user.username);
                              toast.success(`用户 ${user.username} 已启用`);
                              await reloadAll();
                            } catch (requestError) {
                              toast.error(requestError instanceof Error ? requestError.message : '启用用户失败');
                            } finally {
                              setUserActionKey('');
                            }
                          }}
                        >
                          启用
                        </Button>
                      )}
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => {
                          setResetTarget(user.username);
                          setResetPasswordValue('');
                          setResetError('');
                        }}
                      >
                        重置密码
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        loading={userActionKey === `${user.username}:delete`}
                        onClick={async () => {
                          if (!await confirm(`确认删除用户 ${user.username}？相关会话与归属账号将被清理。`)) return;
                          setUserActionKey(`${user.username}:delete`);
                          try {
                            await iamService.deleteUser(client, user.username);
                            toast.success(`用户 ${user.username} 已删除`);
                            await reloadAll();
                          } catch (requestError) {
                            toast.error(requestError instanceof Error ? requestError.message : '删除用户失败');
                          } finally {
                            setUserActionKey('');
                          }
                        }}
                      >
                        删除
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>

      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h2 className="font-heading text-xl text-on-surface">组</h2>
        <form
          className="mt-3 flex gap-2"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            try {
              await iamService.createGroup(client, groupForm);
              toast.success(`组 ${groupForm.name} 创建成功`);
              setGroupForm({ name: '' });
              await reloadAll();
            } catch (requestError) {
              toast.error(requestError instanceof Error ? requestError.message : '创建组失败');
            } finally {
              setBusy(false);
            }
          }}
        >
          <input
            required
            value={groupForm.name}
            onChange={(event) => setGroupForm({ name: event.target.value })}
            placeholder="组名"
            className="h-11 flex-1 rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
          />
          <Button type="submit" variant="primary" loading={busy}>
            创建组
          </Button>
        </form>
        <div className="mt-3 space-y-3">
          {groups.map((group) => (
            <article key={group.name} className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <div className="flex items-center justify-between">
                <p className="font-medium text-on-surface">{group.name}</p>
                <p className="text-xs text-muted">成员数：{group.members.length}</p>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {group.members.length === 0 ? (
                  <span className="text-xs text-muted">暂无成员</span>
                ) : (
                  group.members.map((member) => (
                    <button
                      key={member}
                      className="rounded-full border border-error/40 px-2 py-1 text-xs text-error hover:bg-error/10"
                      onClick={async () => {
                        if (!await confirm(`确认将 ${member} 从组 ${group.name} 移除？`)) return;
                        try {
                          await iamService.removeGroupMember(client, group.name, member);
                          toast.success(`已将 ${member} 从 ${group.name} 移除`);
                          await reloadAll();
                        } catch (requestError) {
                          toast.error(requestError instanceof Error ? requestError.message : '移除成员失败');
                        }
                      }}
                    >
                      {member} · 移除
                    </button>
                  ))
                )}
              </div>
              <div className="mt-3 flex gap-2">
                <input
                  value={groupMemberDraft[group.name] ?? ''}
                  onChange={(event) =>
                    setGroupMemberDraft((current) => ({ ...current, [group.name]: event.target.value }))
                  }
                  placeholder="新增成员用户名"
                  className="h-10 flex-1 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
                />
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={async () => {
                    const username = (groupMemberDraft[group.name] ?? '').trim();
                    if (!username) {
                      toast.error('成员用户名不能为空');
                      return;
                    }
                    try {
                      await iamService.addGroupMember(client, group.name, { username });
                      setGroupMemberDraft((current) => ({ ...current, [group.name]: '' }));
                      toast.success(`成员 ${username} 已加入组 ${group.name}`);
                      await reloadAll();
                    } catch (requestError) {
                      toast.error(requestError instanceof Error ? requestError.message : '添加成员失败');
                    }
                  }}
                >
                  添加成员
                </Button>
              </div>
            </article>
          ))}
        </div>
      </article>

      <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
        <h2 className="font-heading text-xl text-on-surface">策略</h2>
        <form
          className="mt-3 grid gap-3"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            try {
              const document = JSON.parse(policyForm.document) as Record<string, unknown>;
              await iamService.createPolicy(client, {
                name: policyForm.name,
                document
              });
              toast.success(`策略 ${policyForm.name} 创建成功`);
              setPolicyForm({
                name: '',
                document: '{\n  "Version": "2012-10-17",\n  "Statement": []\n}'
              });
              await reloadAll();
            } catch (requestError) {
              toast.error(requestError instanceof Error ? requestError.message : '创建策略失败');
            } finally {
              setBusy(false);
            }
          }}
        >
          <input
            required
            value={policyForm.name}
            onChange={(event) => setPolicyForm((current) => ({ ...current, name: event.target.value }))}
            placeholder="策略名"
            className="h-11 rounded-md border border-outline/60 bg-surface-lowest px-3 text-on-surface"
          />
          <textarea
            required
            value={policyForm.document}
            onChange={(event) => setPolicyForm((current) => ({ ...current, document: event.target.value }))}
            className="h-32 rounded-md border border-outline/60 bg-surface-lowest px-3 py-2 text-sm text-on-surface"
          />
          <Button type="submit" variant="primary" loading={busy}>
            创建策略
          </Button>
        </form>
        <div className="mt-3 space-y-3">
          {policies.map((policy) => (
            <article key={policy.name} className="rounded-lg border border-outline/60 bg-surface-container-high p-3">
              <p className="font-medium text-on-surface">{policy.name}</p>
              <p className="mt-1 text-xs text-muted">
                已挂载：{policy.attached_to.length === 0 ? '无' : policy.attached_to.join(', ')}
              </p>
              <div className="mt-2 flex gap-2">
                <input
                  value={policyPrincipalDraft[policy.name] ?? ''}
                  onChange={(event) =>
                    setPolicyPrincipalDraft((current) => ({
                      ...current,
                      [policy.name]: event.target.value
                    }))
                  }
                  placeholder="principal（用户名或组名）"
                  className="h-10 flex-1 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
                />
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={async () => {
                    const principal = (policyPrincipalDraft[policy.name] ?? '').trim();
                    if (!principal) {
                      toast.error('principal 不能为空');
                      return;
                    }
                    try {
                      await iamService.attachPolicy(client, policy.name, { principal });
                      toast.success(`策略 ${policy.name} 已挂载到 ${principal}`);
                      await reloadAll();
                    } catch (requestError) {
                      toast.error(requestError instanceof Error ? requestError.message : '挂载策略失败');
                    }
                  }}
                >
                  挂载
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={async () => {
                    const principal = (policyPrincipalDraft[policy.name] ?? '').trim();
                    if (!principal) {
                      toast.error('principal 不能为空');
                      return;
                    }
                    try {
                      await iamService.detachPolicy(client, policy.name, { principal });
                      toast.success(`策略 ${policy.name} 已从 ${principal} 解绑`);
                      await reloadAll();
                    } catch (requestError) {
                      toast.error(requestError instanceof Error ? requestError.message : '解绑策略失败');
                    }
                  }}
                >
                  解绑
                </Button>
              </div>
            </article>
          ))}
        </div>
      </article>

      <div className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
          <h2 className="font-heading text-xl text-on-surface">服务账号</h2>
          <form
            className="mt-3 flex gap-2"
            onSubmit={async (event) => {
              event.preventDefault();
              try {
                await iamService.createServiceAccount(client, serviceForm);
                toast.success(`服务账号已为 ${serviceForm.owner} 创建`);
                await reloadAll();
              } catch (requestError) {
                toast.error(requestError instanceof Error ? requestError.message : '创建服务账号失败');
              }
            }}
          >
            <select
              value={serviceForm.owner}
              onChange={(event) => setServiceForm({ owner: event.target.value })}
              className="h-10 flex-1 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
            >
              {users.map((user) => (
                <option key={user.username} value={user.username}>
                  {user.username}
                </option>
              ))}
            </select>
            <Button type="submit" variant="primary" size="sm">
              创建
            </Button>
          </form>
          <div className="mt-3 space-y-2">
            {serviceAccounts.map((account) => (
              <div
                key={account.access_key}
                className="flex items-center justify-between rounded-md border border-outline/60 bg-surface-container-high p-2"
              >
                <div>
                  <p className="font-mono text-xs text-primary">{account.access_key}</p>
                  <p className="text-xs text-muted">Owner: {account.owner}</p>
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={async () => {
                    if (!await confirm(`确认删除服务账号 ${account.access_key}？`)) return;
                    try {
                      await iamService.deleteServiceAccount(client, account.access_key);
                      toast.success(`服务账号 ${account.access_key} 已删除`);
                      await reloadAll();
                    } catch (requestError) {
                      toast.error(requestError instanceof Error ? requestError.message : '删除服务账号失败');
                    }
                  }}
                >
                  删除
                </Button>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
          <h2 className="font-heading text-xl text-on-surface">控制台会话</h2>
          <div className="mt-3 space-y-2">
            {consoleSessions.length === 0 ? (
              <p className="rounded-md border border-dashed border-outline/60 bg-surface-container-high p-3 text-sm text-muted">
                当前没有控制台会话。
              </p>
            ) : null}
            {consoleSessions.map((session) => (
              <div
                key={session.session_id}
                className="flex items-center justify-between rounded-md border border-outline/60 bg-surface-container-high p-2"
              >
                <div>
                  <p className="font-mono text-xs text-primary">{session.session_id}</p>
                  <p className="text-xs text-muted">
                    {session.principal} · {session.provider.toUpperCase()} · {session.role}
                  </p>
                  <p className="text-xs text-muted">
                    访问到期 {new Date(session.access_expires_at).toLocaleString()} · 状态 {session.status}
                  </p>
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  disabled={session.status !== 'active'}
                  onClick={async () => {
                    if (!await confirm(`确认回收控制台会话 ${session.session_id}？`)) return;
                    try {
                      await iamService.deleteConsoleSession(client, session.session_id);
                      toast.success(`控制台会话 ${session.session_id} 已回收`);
                      await reloadAll();
                    } catch (requestError) {
                      toast.error(requestError instanceof Error ? requestError.message : '回收控制台会话失败');
                    }
                  }}
                >
                  {session.status === 'active' ? '回收' : '已回收'}
                </Button>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-2xl border border-outline/60 bg-surface-container/70 p-4">
          <h2 className="font-heading text-xl text-on-surface">STS 会话</h2>
          <form
            className="mt-3 grid gap-2"
            onSubmit={async (event) => {
              event.preventDefault();
              try {
                await iamService.createStsSession(client, stsForm);
                toast.success(`已为 ${stsForm.principal} 创建 STS 会话`);
                await reloadAll();
              } catch (requestError) {
                toast.error(requestError instanceof Error ? requestError.message : '创建 STS 会话失败');
              }
            }}
          >
            <select
              value={stsForm.principal}
              onChange={(event) => setStsForm((current) => ({ ...current, principal: event.target.value }))}
              className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
            >
              {users.map((user) => (
                <option key={user.username} value={user.username}>
                  {user.username}
                </option>
              ))}
            </select>
            <input
              type="number"
              min={5}
              max={10080}
              value={stsForm.ttl_minutes}
              onChange={(event) =>
                setStsForm((current) => ({ ...current, ttl_minutes: Number(event.target.value) }))
              }
              className="h-10 rounded-md border border-outline/60 bg-surface-lowest px-3 text-sm text-on-surface"
            />
            <Button type="submit" variant="primary" size="sm">
              创建会话
            </Button>
          </form>
          <div className="mt-3 space-y-2">
            {stsSessions.map((session) => (
              <div
                key={session.session_id}
                className="flex items-center justify-between rounded-md border border-outline/60 bg-surface-container-high p-2"
              >
                <div>
                  <p className="font-mono text-xs text-primary">{session.session_id}</p>
                  <p className="text-xs text-muted">
                    {session.principal}
                    {session.provider ? ` · ${session.provider.toUpperCase()}` : ''}
                    {session.session_name ? ` · 会话 ${session.session_name}` : ''}
                    {' · '}
                    到期 {new Date(session.expires_at).toLocaleString()}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    {session.role_arn ? `RoleArn：${session.role_arn}` : 'RoleArn：自动继承'}
                    {' · '}
                    会话策略：{session.session_policy ? '已收敛' : '无'}
                  </p>
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={async () => {
                    if (!await confirm(`确认回收 STS 会话 ${session.session_id}？`)) return;
                    try {
                      await iamService.deleteStsSession(client, session.session_id);
                      toast.success(`STS 会话 ${session.session_id} 已回收`);
                      await reloadAll();
                    } catch (requestError) {
                      toast.error(requestError instanceof Error ? requestError.message : '回收 STS 会话失败');
                    }
                  }}
                >
                  回收
                </Button>
              </div>
            ))}
          </div>
        </article>
      </div>

      <Dialog
        open={resetTarget !== null}
        onClose={() => setResetTarget(null)}
        title="重置密码"
        description={resetTarget ? `为用户 ${resetTarget} 设置新密码` : undefined}
        footer={
          <>
            <Button variant="tertiary" onClick={() => setResetTarget(null)} disabled={resetBusy}>
              取消
            </Button>
            <Button
              variant="primary"
              disabled={resetBusy}
              onClick={async () => {
                if (!resetTarget) return;
                setResetError('');
                if (resetPasswordValue.length < 8) {
                  setResetError('新密码长度不能少于 8 位');
                  return;
                }
                setResetBusy(true);
                try {
                  await iamService.resetUserPassword(client, resetTarget, {
                    new_password: resetPasswordValue
                  });
                  toast.success(`用户 ${resetTarget} 密码已重置`);
                  setResetTarget(null);
                  await reloadAll();
                } catch (requestError) {
                  setResetError(
                    requestError instanceof Error ? toBilingualPrompt(requestError.message) : '重置密码失败'
                  );
                } finally {
                  setResetBusy(false);
                }
              }}
            >
              {resetBusy ? '提交中...' : '确认重置'}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Field label="新密码" hint="长度不少于 8 位；重置后该用户已有会话将失效">
            <Input
              type="password"
              autoComplete="new-password"
              value={resetPasswordValue}
              onChange={(event) => setResetPasswordValue(event.target.value)}
            />
          </Field>
          {resetError ? <p className="text-sm text-error">{resetError}</p> : null}
        </div>
      </Dialog>
    </section>
  );
}
