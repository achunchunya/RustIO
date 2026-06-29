import type { HTMLAttributes } from 'react';
import { cn } from './cn';

export type BadgeTone = 'neutral' | 'success' | 'warning' | 'error' | 'info' | 'primary';

const toneClass: Record<BadgeTone, string> = {
  neutral: 'bg-surface-container-high text-muted border-outline/50',
  success: 'bg-success/12 text-success border-success/30',
  warning: 'bg-warning/14 text-warning border-warning/30',
  error: 'bg-error/12 text-error border-error/30',
  info: 'bg-info/12 text-info border-info/30',
  primary: 'bg-primary-container text-on-primary-container border-primary/20'
};

type BadgeProps = HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone };

/** 状态徽章/标签。 */
export function Badge({ tone = 'neutral', className, children, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium',
        toneClass[tone],
        className
      )}
      {...rest}
    >
      {children}
    </span>
  );
}

/** 元数据小标签(无状态色,中性)。 */
export function Chip({ className, children, ...rest }: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border border-outline/50 bg-surface-container-high px-2 py-0.5 text-xs uppercase tracking-wide text-muted',
        className
      )}
      {...rest}
    >
      {children}
    </span>
  );
}
