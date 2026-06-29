import type { ReactNode } from 'react';

type StatCardProps = {
  label: string;
  value: string;
  helper?: string;
  icon?: ReactNode;
};

/** 统计卡:大写标签 + 大数值 + 可选辅助说明/图标。 */
export function StatCard({ label, value, helper, icon }: StatCardProps) {
  return (
    <article className="animate-rise rounded-lg border border-outline/60 bg-surface-container p-5">
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium uppercase tracking-[0.08em] text-muted">{label}</p>
        {icon ? <span className="text-secondary">{icon}</span> : null}
      </div>
      <p className="mt-3 font-heading text-3xl font-semibold text-on-surface">{value}</p>
      {helper ? <p className="mt-2 text-sm text-muted">{helper}</p> : null}
    </article>
  );
}
