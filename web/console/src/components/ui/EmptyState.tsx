import type { ReactNode } from 'react';
import { cn } from './cn';

type EmptyStateProps = {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  /** 虚线"新建"卡片样式(对齐设计稿) */
  dashed?: boolean;
  onClick?: () => void;
  className?: string;
};

/** 空态 / 新建占位卡。 */
export function EmptyState({
  icon,
  title,
  description,
  action,
  dashed = false,
  onClick,
  className
}: EmptyStateProps) {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      onClick={onClick}
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg p-8 text-center',
        dashed
          ? 'border-2 border-dashed border-outline/60 bg-transparent hover:border-secondary/60 hover:bg-surface-container/50'
          : 'border border-outline/50 bg-surface-container',
        onClick && 'cursor-pointer transition',
        className
      )}
    >
      {icon ? <div className="text-muted">{icon}</div> : null}
      <p className="font-heading text-base font-semibold text-on-surface">{title}</p>
      {description ? <p className="max-w-xs text-sm text-muted">{description}</p> : null}
      {action}
    </Tag>
  );
}
