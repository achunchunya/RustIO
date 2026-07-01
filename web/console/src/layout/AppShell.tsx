import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useState, type ComponentType, type SVGProps } from 'react';
import type { ApiClient } from '../api/client';
import { Logo } from '../components/ui/Logo';
import { ThemeToggle } from '../components/ui/ThemeToggle';
import { Button } from '../components/ui/Button';
import { ChangePasswordDialog } from '../components/ChangePasswordDialog';
import { cn } from '../components/ui/cn';
import {
  IconDashboard,
  IconMetrics,
  IconArchitecture,
  IconSpark,
  IconOperations,
  IconRaft,
  IconStorage,
  IconTenants,
  IconIam,
  IconBuckets,
  IconObjects,
  IconReplication,
  IconAlerts,
  IconSecurity,
  IconConfig,
  IconAudit,
  IconJobs,
  IconLogout,
  IconKey
} from '../components/ui/icons';

type NavItem = {
  to: string;
  label: string;
  icon: ComponentType<SVGProps<SVGSVGElement> & { size?: number }>;
  permission?: string;
};

type NavGroup = {
  label: string;
  items: NavItem[];
};

const navGroups: NavGroup[] = [
  {
    label: '总览',
    items: [
      { to: '/dashboard', label: '集群总览', icon: IconDashboard },
      { to: '/capabilities', label: '集群能力', icon: IconSpark, permission: 'cluster:read' },
      { to: '/metrics', label: '指标中心', icon: IconMetrics, permission: 'cluster:read' },
      { to: '/architecture', label: '架构与拓扑', icon: IconArchitecture, permission: 'cluster:read' }
    ]
  },
  {
    label: '集群运维',
    items: [
      { to: '/operations', label: '集群运维', icon: IconOperations, permission: 'cluster:write' },
      { to: '/raft', label: 'Raft 管理', icon: IconRaft, permission: 'cluster:read' },
      { to: '/storage', label: '存储治理', icon: IconStorage, permission: 'cluster:read' }
    ]
  },
  {
    label: '身份与多租户',
    items: [
      { to: '/tenants', label: '租户管理', icon: IconTenants, permission: 'cluster:read' },
      { to: '/iam', label: '身份与访问', icon: IconIam, permission: 'iam:read' }
    ]
  },
  {
    label: '数据面',
    items: [
      { to: '/buckets', label: '桶治理', icon: IconBuckets, permission: 'bucket:read' },
      { to: '/objects', label: '对象浏览器', icon: IconObjects, permission: 'bucket:read' },
      { to: '/replication', label: '复制与容灾', icon: IconReplication, permission: 'replication:read' }
    ]
  },
  {
    label: '可观测与安全',
    items: [
      { to: '/alerts', label: '告警', icon: IconAlerts, permission: 'security:read' },
      { to: '/security', label: '安全', icon: IconSecurity, permission: 'security:read' },
      { to: '/config', label: '配置中心', icon: IconConfig, permission: 'cluster:read' },
      { to: '/audit', label: '审计', icon: IconAudit, permission: 'audit:read' },
      { to: '/jobs', label: '任务', icon: IconJobs, permission: 'jobs:read' }
    ]
  }
];

type AppShellProps = {
  username: string;
  permissions: string[];
  client: ApiClient;
  onLogout: () => Promise<void> | void;
};

export function AppShell({ username, permissions, client, onLogout }: AppShellProps) {
  const navigate = useNavigate();
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const canSee = (item: NavItem) => !item.permission || permissions.includes(item.permission);

  return (
    <div className="flex min-h-screen">
      {/* 侧边栏:浅色态为深松烟墨,暗色态更深 */}
      <aside className="flex w-64 shrink-0 flex-col bg-sidebar text-sidebar-fg">
        <div className="flex h-16 items-center px-5">
          <Link to="/dashboard" className="text-sidebar-fg">
            <Logo size={26} />
          </Link>
        </div>
        <nav className="flex-1 space-y-6 overflow-y-auto px-3 pb-6">
          {navGroups.map((group) => {
            const items = group.items.filter(canSee);
            if (items.length === 0) return null;
            return (
              <div key={group.label}>
                <p className="px-3 pb-2 text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-sidebar-muted">
                  {group.label}
                </p>
                <div className="space-y-0.5">
                  {items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        className={({ isActive }) =>
                          cn(
                            'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition',
                            isActive
                              ? 'bg-sidebar-active text-sidebar-fg'
                              : 'text-sidebar-fg/75 hover:bg-sidebar-active/60 hover:text-sidebar-fg'
                          )
                        }
                      >
                        <Icon size={18} />
                        <span>{item.label}</span>
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>
      </aside>

      {/* 主区 */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-outline/50 bg-surface px-6">
          <p className="font-heading text-base font-semibold tracking-tight text-on-surface">
            RustIO 控制台
          </p>
          <div className="flex items-center gap-4">
            <ThemeToggle />
            <div className="flex items-center gap-3">
              <div className="text-right">
                <p className="text-xs uppercase tracking-wide text-muted">当前账号</p>
                <p className="text-sm font-medium text-on-surface">{username}</p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                icon={<IconKey size={16} />}
                onClick={() => setPasswordDialogOpen(true)}
              >
                修改密码
              </Button>
              <Button
                variant="secondary"
                size="sm"
                icon={<IconLogout size={16} />}
                onClick={async () => {
                  await onLogout();
                  navigate('/login');
                }}
              >
                退出
              </Button>
            </div>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto px-8 py-8">
          <Outlet />
        </main>
      </div>
      <ChangePasswordDialog
        open={passwordDialogOpen}
        onClose={() => setPasswordDialogOpen(false)}
        client={client}
      />
    </div>
  );
}
