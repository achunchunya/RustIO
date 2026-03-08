import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';

const navItems = [
  { to: '/dashboard', label: '集群总览' },
  { to: '/metrics', label: '指标中心', permission: 'cluster:read' },
  { to: '/tenants', label: '租户管理', permission: 'cluster:read' },
  { to: '/iam', label: '身份与访问', permission: 'iam:read' },
  { to: '/buckets', label: '桶治理', permission: 'bucket:read' },
  { to: '/objects', label: '对象浏览器', permission: 'bucket:read' },
  { to: '/replication', label: '复制', permission: 'replication:read' },
  { to: '/alerts', label: '告警', permission: 'security:read' },
  { to: '/security', label: '安全', permission: 'security:read' },
  { to: '/config', label: '配置中心', permission: 'cluster:read' },
  { to: '/audit', label: '审计', permission: 'audit:read' },
  { to: '/jobs', label: '任务', permission: 'jobs:read' },
  { to: '/operations', label: '运维操作', permission: 'cluster:write' }
];

type AppShellProps = {
  username: string;
  permissions: string[];
  onLogout: () => Promise<void> | void;
};

export function AppShell({ username, permissions, onLogout }: AppShellProps) {
  const navigate = useNavigate();
  const visibleNavItems = navItems.filter(
    (item) => !item.permission || permissions.includes(item.permission)
  );

  return (
    <div className="flex min-h-screen">
      <aside className="w-64 border-r border-white/10 bg-ink-800/70 p-5 backdrop-blur">
        <Link to="/dashboard" className="font-heading text-2xl tracking-tight text-white">
          RustIO 管理端
        </Link>
        <p className="mt-1 text-xs uppercase tracking-[0.2em] text-signal-500">控制平面</p>
        <nav className="mt-8 space-y-1">
          {visibleNavItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm transition ${
                  isActive
                    ? 'bg-signal-500/15 text-signal-500'
                    : 'text-slate-300 hover:bg-white/5 hover:text-white'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="flex-1 p-6">
        <header className="mb-6 flex items-center justify-between rounded-2xl border border-white/10 bg-ink-800/60 px-5 py-4 shadow-panel">
          <div>
            <p className="text-sm text-slate-300">当前登录账号</p>
            <p className="font-heading text-lg text-white">{username}</p>
          </div>
          <button
            className="rounded-md border border-white/15 px-3 py-2 text-sm text-slate-200 hover:bg-white/5"
            onClick={async () => {
              await onLogout();
              navigate('/login');
            }}
          >
            退出登录
          </button>
        </header>
        <Outlet />
      </main>
    </div>
  );
}
