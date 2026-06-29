import { cn } from './cn';
import { IconGrid, IconList } from './icons';

export type TabItem = {
  key: string;
  label: string;
  count?: number;
};

type TabsProps = {
  items: TabItem[];
  active: string;
  onChange: (key: string) => void;
  className?: string;
};

/** 下划线式标签页(对齐设计稿 buckets 顶部 tab)。 */
export function Tabs({ items, active, onChange, className }: TabsProps) {
  return (
    <div className={cn('flex items-center gap-6 border-b border-outline/50', className)}>
      {items.map((item) => {
        const isActive = item.key === active;
        return (
          <button
            key={item.key}
            onClick={() => onChange(item.key)}
            className={cn(
              '-mb-px border-b-2 px-1 pb-3 text-sm font-medium uppercase tracking-wide transition',
              isActive
                ? 'border-primary text-on-surface'
                : 'border-transparent text-muted hover:text-on-surface'
            )}
          >
            {item.label}
            {typeof item.count === 'number' ? (
              <span className="ml-1.5 text-muted">({item.count})</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

type ViewToggleProps = {
  view: 'grid' | 'list';
  onChange: (view: 'grid' | 'list') => void;
  className?: string;
};

/** 网格/列表视图切换。 */
export function ViewToggle({ view, onChange, className }: ViewToggleProps) {
  return (
    <div className={cn('inline-flex rounded-md border border-outline/60 p-0.5', className)}>
      {(['grid', 'list'] as const).map((mode) => {
        const Icon = mode === 'grid' ? IconGrid : IconList;
        const isActive = view === mode;
        return (
          <button
            key={mode}
            onClick={() => onChange(mode)}
            aria-label={mode === 'grid' ? '网格视图' : '列表视图'}
            className={cn(
              'rounded p-1.5 transition',
              isActive ? 'bg-primary text-on-primary' : 'text-muted hover:text-on-surface'
            )}
          >
            <Icon size={16} />
          </button>
        );
      })}
    </div>
  );
}
