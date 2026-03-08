import { useEffect, useMemo, useState } from 'react';
import { toBilingualNotice, toBilingualPrompt } from '../utils/bilingual';
import { ApiClient } from '../api/client';
import { iamService, systemService } from '../api/services';
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
  const [users, setUsers] = useState<IamUser[]>([]);
  const [groups, setGroups] = useState<IamGroup[]>([]);
  const [policies, setPolicies] = useState<IamPolicy[]>([]);
  const [serviceAccounts, setServiceAccounts] = useState<ServiceAccount[]>([]);
  const [stsSessions, setStsSessions] = useState<StsSession[]>([]);
  const [consoleSessions, setConsoleSessions] = useState<ConsoleSession[]>([]);
  const [summary, setSummary] = useState<SystemMetricsSummary | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

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
      setError(requestError instanceof Error ? requestError.message : '加载 IAM 失败');
    });
  }, [client]);

  return (
    <section className="space-y-4">
      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h1 className="font-heading text-2xl text-white">身份与访问</h1>
        <p className="mt-1 text-sm text-slate-300">用户、组、策略、服务账号、控制台会话、STS 会话管理。</p>
        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {message ? <p className="mt-3 text-sm text-signal-500">{toBilingualNotice(message)}</p> : null}
        {summary ? (
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-white/10 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">IAM</p>
              <p className="mt-2 text-white">用户 {summary.iam.users_enabled}/{summary.iam.users_total}</p>
              <p className="mt-1">组 {summary.iam.groups_total} / 策略 {summary.iam.policies_total}</p>
            </div>
            <div className="rounded-lg border border-white/10 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">服务账号</p>
              <p className="mt-2 text-white">{summary.iam.service_accounts_enabled}/{summary.iam.service_accounts_total}</p>
              <p className="mt-1">控制面已纳入统一摘要</p>
            </div>
            <div className="rounded-lg border border-white/10 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">控制台会话</p>
              <p className="mt-2 text-white">{summary.sessions.admin_sessions_active}/{summary.sessions.admin_sessions_total}</p>
              <p className="mt-1">24h 内到期 {summary.sessions.admin_sessions_expiring_24h}</p>
            </div>
            <div className="rounded-lg border border-white/10 bg-black/10 p-3 text-sm text-slate-300">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-500">STS 会话</p>
              <p className="mt-2 text-white">{summary.sessions.sts_sessions_active}/{summary.sessions.sts_sessions_total}</p>
              <p className="mt-1">24h 内到期 {summary.sessions.sts_sessions_expiring_24h}</p>
            </div>
          </div>
        ) : null}
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">用户</h2>
        <form
          className="mt-3 grid gap-3 md:grid-cols-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError('');
            setMessage('');
            try {
              await iamService.createUser(client, userForm);
              setMessage(`用户 ${userForm.username} 创建成功`);
              setUserForm({ username: '', display_name: '', password: '', role: 'viewer' });
              await reloadAll();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建用户失败');
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
            className="h-11 rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
          />
          <input
            required
            value={userForm.display_name}
            onChange={(event) =>
              setUserForm((current) => ({ ...current, display_name: event.target.value }))
            }
            placeholder="显示名称"
            className="h-11 rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
          />
          <input
            required
            type="password"
            value={userForm.password}
            onChange={(event) => setUserForm((current) => ({ ...current, password: event.target.value }))}
            placeholder="密码"
            className="h-11 rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
          />
          <div className="flex gap-2">
            <select
              value={userForm.role}
              onChange={(event) => setUserForm((current) => ({ ...current, role: event.target.value }))}
              className="h-11 flex-1 rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
            >
              <option value="viewer">viewer</option>
              <option value="operator">operator</option>
              <option value="admin">admin</option>
            </select>
            <button
              type="submit"
              disabled={busy}
              className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
            >
              创建
            </button>
          </div>
        </form>
        <div className="mt-3 overflow-hidden rounded-lg border border-white/10">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/5 text-slate-300">
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
                <tr key={user.username} className="border-t border-white/5">
                  <td className="px-3 py-2 font-mono text-xs text-signal-500">{user.username}</td>
                  <td className="px-3 py-2 text-slate-200">{user.display_name}</td>
                  <td className="px-3 py-2 text-slate-300">{user.role}</td>
                  <td className="px-3 py-2 text-slate-300">{user.enabled ? '启用' : '禁用'}</td>
                  <td className="px-3 py-2">
                    <div className="flex gap-2">
                      {user.enabled ? (
                        <button
                          className="rounded-md border border-amber-500/40 px-2 py-1 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-60"
                          disabled={userActionKey === `${user.username}:disable`}
                          onClick={async () => {
                            if (!window.confirm(`确认禁用用户 ${user.username}？`)) return;
                            setError('');
                            setMessage('');
                            setUserActionKey(`${user.username}:disable`);
                            try {
                              await iamService.disableUser(client, user.username);
                              setMessage(`用户 ${user.username} 已禁用`);
                              await reloadAll();
                            } catch (requestError) {
                              setError(requestError instanceof Error ? requestError.message : '禁用用户失败');
                            } finally {
                              setUserActionKey('');
                            }
                          }}
                        >
                          {userActionKey === `${user.username}:disable` ? '处理中...' : '禁用'}
                        </button>
                      ) : (
                        <button
                          className="rounded-md border border-signal-500/40 px-2 py-1 text-xs text-signal-500 hover:bg-signal-500/10 disabled:opacity-60"
                          disabled={userActionKey === `${user.username}:enable`}
                          onClick={async () => {
                            setError('');
                            setMessage('');
                            setUserActionKey(`${user.username}:enable`);
                            try {
                              await iamService.enableUser(client, user.username);
                              setMessage(`用户 ${user.username} 已启用`);
                              await reloadAll();
                            } catch (requestError) {
                              setError(requestError instanceof Error ? requestError.message : '启用用户失败');
                            } finally {
                              setUserActionKey('');
                            }
                          }}
                        >
                          {userActionKey === `${user.username}:enable` ? '处理中...' : '启用'}
                        </button>
                      )}
                      <button
                        className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                        disabled={userActionKey === `${user.username}:delete`}
                        onClick={async () => {
                          if (!window.confirm(`确认删除用户 ${user.username}？相关会话与归属账号将被清理。`)) return;
                          setError('');
                          setMessage('');
                          setUserActionKey(`${user.username}:delete`);
                          try {
                            await iamService.deleteUser(client, user.username);
                            setMessage(`用户 ${user.username} 已删除`);
                            await reloadAll();
                          } catch (requestError) {
                            setError(requestError instanceof Error ? requestError.message : '删除用户失败');
                          } finally {
                            setUserActionKey('');
                          }
                        }}
                      >
                        {userActionKey === `${user.username}:delete` ? '删除中...' : '删除'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">组</h2>
        <form
          className="mt-3 flex gap-2"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError('');
            setMessage('');
            try {
              await iamService.createGroup(client, groupForm);
              setMessage(`组 ${groupForm.name} 创建成功`);
              setGroupForm({ name: '' });
              await reloadAll();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建组失败');
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
            className="h-11 flex-1 rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
          />
          <button
            type="submit"
            disabled={busy}
            className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
          >
            创建组
          </button>
        </form>
        <div className="mt-3 space-y-3">
          {groups.map((group) => (
            <article key={group.name} className="rounded-lg border border-white/10 bg-black/10 p-3">
              <div className="flex items-center justify-between">
                <p className="font-medium text-white">{group.name}</p>
                <p className="text-xs text-slate-400">成员数：{group.members.length}</p>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {group.members.length === 0 ? (
                  <span className="text-xs text-slate-500">暂无成员</span>
                ) : (
                  group.members.map((member) => (
                    <button
                      key={member}
                      className="rounded-full border border-white/15 px-2 py-1 text-xs text-slate-200 hover:bg-white/5"
                      onClick={async () => {
                        if (!window.confirm(`确认将 ${member} 从组 ${group.name} 移除？`)) return;
                        setError('');
                        setMessage('');
                        try {
                          await iamService.removeGroupMember(client, group.name, member);
                          setMessage(`已将 ${member} 从 ${group.name} 移除`);
                          await reloadAll();
                        } catch (requestError) {
                          setError(requestError instanceof Error ? requestError.message : '移除成员失败');
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
                  className="h-10 flex-1 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                />
                <button
                  className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
                  onClick={async () => {
                    const username = (groupMemberDraft[group.name] ?? '').trim();
                    if (!username) {
                      setError('成员用户名不能为空');
                      return;
                    }
                    setError('');
                    setMessage('');
                    try {
                      await iamService.addGroupMember(client, group.name, { username });
                      setGroupMemberDraft((current) => ({ ...current, [group.name]: '' }));
                      setMessage(`成员 ${username} 已加入组 ${group.name}`);
                      await reloadAll();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '添加成员失败');
                    }
                  }}
                >
                  添加成员
                </button>
              </div>
            </article>
          ))}
        </div>
      </article>

      <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
        <h2 className="font-heading text-xl text-white">策略</h2>
        <form
          className="mt-3 grid gap-3"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError('');
            setMessage('');
            try {
              const document = JSON.parse(policyForm.document) as Record<string, unknown>;
              await iamService.createPolicy(client, {
                name: policyForm.name,
                document
              });
              setMessage(`策略 ${policyForm.name} 创建成功`);
              setPolicyForm({
                name: '',
                document: '{\n  "Version": "2012-10-17",\n  "Statement": []\n}'
              });
              await reloadAll();
            } catch (requestError) {
              setError(requestError instanceof Error ? requestError.message : '创建策略失败');
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
            className="h-11 rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
          />
          <textarea
            required
            value={policyForm.document}
            onChange={(event) => setPolicyForm((current) => ({ ...current, document: event.target.value }))}
            className="h-32 rounded-md border border-white/15 bg-ink-900 px-3 py-2 text-sm text-slate-100"
          />
          <button
            type="submit"
            disabled={busy}
            className="h-11 rounded-md bg-signal-600 px-4 text-sm font-medium text-white disabled:opacity-60"
          >
            创建策略
          </button>
        </form>
        <div className="mt-3 space-y-3">
          {policies.map((policy) => (
            <article key={policy.name} className="rounded-lg border border-white/10 bg-black/10 p-3">
              <p className="font-medium text-white">{policy.name}</p>
              <p className="mt-1 text-xs text-slate-400">
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
                  className="h-10 flex-1 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
                />
                <button
                  className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
                  onClick={async () => {
                    const principal = (policyPrincipalDraft[policy.name] ?? '').trim();
                    if (!principal) {
                      setError('principal 不能为空');
                      return;
                    }
                    setError('');
                    setMessage('');
                    try {
                      await iamService.attachPolicy(client, policy.name, { principal });
                      setMessage(`策略 ${policy.name} 已挂载到 ${principal}`);
                      await reloadAll();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '挂载策略失败');
                    }
                  }}
                >
                  挂载
                </button>
                <button
                  className="h-10 rounded-md border border-white/15 px-3 text-sm text-slate-100 hover:bg-white/5"
                  onClick={async () => {
                    const principal = (policyPrincipalDraft[policy.name] ?? '').trim();
                    if (!principal) {
                      setError('principal 不能为空');
                      return;
                    }
                    setError('');
                    setMessage('');
                    try {
                      await iamService.detachPolicy(client, policy.name, { principal });
                      setMessage(`策略 ${policy.name} 已从 ${principal} 解绑`);
                      await reloadAll();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '解绑策略失败');
                    }
                  }}
                >
                  解绑
                </button>
              </div>
            </article>
          ))}
        </div>
      </article>

      <div className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">服务账号</h2>
          <form
            className="mt-3 flex gap-2"
            onSubmit={async (event) => {
              event.preventDefault();
              setError('');
              setMessage('');
              try {
                await iamService.createServiceAccount(client, serviceForm);
                setMessage(`服务账号已为 ${serviceForm.owner} 创建`);
                await reloadAll();
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '创建服务账号失败');
              }
            }}
          >
            <select
              value={serviceForm.owner}
              onChange={(event) => setServiceForm({ owner: event.target.value })}
              className="h-10 flex-1 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            >
              {users.map((user) => (
                <option key={user.username} value={user.username}>
                  {user.username}
                </option>
              ))}
            </select>
            <button className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white">创建</button>
          </form>
          <div className="mt-3 space-y-2">
            {serviceAccounts.map((account) => (
              <div
                key={account.access_key}
                className="flex items-center justify-between rounded-md border border-white/10 bg-black/10 p-2"
              >
                <div>
                  <p className="font-mono text-xs text-signal-500">{account.access_key}</p>
                  <p className="text-xs text-slate-400">Owner: {account.owner}</p>
                </div>
                <button
                  className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                  onClick={async () => {
                    if (!window.confirm(`确认删除服务账号 ${account.access_key}？`)) return;
                    setError('');
                    setMessage('');
                    try {
                      await iamService.deleteServiceAccount(client, account.access_key);
                      setMessage(`服务账号 ${account.access_key} 已删除`);
                      await reloadAll();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '删除服务账号失败');
                    }
                  }}
                >
                  删除
                </button>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">控制台会话</h2>
          <div className="mt-3 space-y-2">
            {consoleSessions.length === 0 ? (
              <p className="rounded-md border border-dashed border-white/10 bg-black/10 p-3 text-sm text-slate-400">
                当前没有控制台会话。
              </p>
            ) : null}
            {consoleSessions.map((session) => (
              <div
                key={session.session_id}
                className="flex items-center justify-between rounded-md border border-white/10 bg-black/10 p-2"
              >
                <div>
                  <p className="font-mono text-xs text-signal-500">{session.session_id}</p>
                  <p className="text-xs text-slate-300">
                    {session.principal} · {session.provider.toUpperCase()} · {session.role}
                  </p>
                  <p className="text-xs text-slate-400">
                    访问到期 {new Date(session.access_expires_at).toLocaleString()} · 状态 {session.status}
                  </p>
                </div>
                <button
                  className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-60"
                  disabled={session.status !== 'active'}
                  onClick={async () => {
                    if (!window.confirm(`确认回收控制台会话 ${session.session_id}？`)) return;
                    setError('');
                    setMessage('');
                    try {
                      await iamService.deleteConsoleSession(client, session.session_id);
                      setMessage(`控制台会话 ${session.session_id} 已回收`);
                      await reloadAll();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '回收控制台会话失败');
                    }
                  }}
                >
                  {session.status === 'active' ? '回收' : '已回收'}
                </button>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-2xl border border-white/10 bg-ink-800/70 p-4">
          <h2 className="font-heading text-xl text-white">STS 会话</h2>
          <form
            className="mt-3 grid gap-2"
            onSubmit={async (event) => {
              event.preventDefault();
              setError('');
              setMessage('');
              try {
                await iamService.createStsSession(client, stsForm);
                setMessage(`已为 ${stsForm.principal} 创建 STS 会话`);
                await reloadAll();
              } catch (requestError) {
                setError(requestError instanceof Error ? requestError.message : '创建 STS 会话失败');
              }
            }}
          >
            <select
              value={stsForm.principal}
              onChange={(event) => setStsForm((current) => ({ ...current, principal: event.target.value }))}
              className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
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
              className="h-10 rounded-md border border-white/15 bg-ink-900 px-3 text-sm text-slate-100"
            />
            <button className="h-10 rounded-md bg-signal-600 px-3 text-sm text-white">创建会话</button>
          </form>
          <div className="mt-3 space-y-2">
            {stsSessions.map((session) => (
              <div
                key={session.session_id}
                className="flex items-center justify-between rounded-md border border-white/10 bg-black/10 p-2"
              >
                <div>
                  <p className="font-mono text-xs text-signal-500">{session.session_id}</p>
                  <p className="text-xs text-slate-400">
                    {session.principal}
                    {session.provider ? ` · ${session.provider.toUpperCase()}` : ''}
                    {session.session_name ? ` · 会话 ${session.session_name}` : ''}
                    {' · '}
                    到期 {new Date(session.expires_at).toLocaleString()}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {session.role_arn ? `RoleArn：${session.role_arn}` : 'RoleArn：自动继承'}
                    {' · '}
                    会话策略：{session.session_policy ? '已收敛' : '无'}
                  </p>
                </div>
                <button
                  className="rounded-md border border-rose-500/40 px-2 py-1 text-xs text-rose-300 hover:bg-rose-500/10"
                  onClick={async () => {
                    if (!window.confirm(`确认回收 STS 会话 ${session.session_id}？`)) return;
                    setError('');
                    setMessage('');
                    try {
                      await iamService.deleteStsSession(client, session.session_id);
                      setMessage(`STS 会话 ${session.session_id} 已回收`);
                      await reloadAll();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : '回收 STS 会话失败');
                    }
                  }}
                >
                  回收
                </button>
              </div>
            ))}
          </div>
        </article>
      </div>
    </section>
  );
}
