import { cn } from './cn';
import type { BadgeTone } from './Badge';

type ProgressBarProps = {
  /** 0-1 比例,或用 value/max */
  ratio?: number;
  value?: number;
  max?: number;
  tone?: Extract<BadgeTone, 'primary' | 'success' | 'warning' | 'error' | 'info'>;
  className?: string;
};

const fillClass: Record<NonNullable<ProgressBarProps['tone']>, string> = {
  primary: 'bg-primary',
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-error',
  info: 'bg-info'
};

/** 进度条(替代旧 div 进度条),track + fill 双层。 */
export function ProgressBar({ ratio, value, max, tone = 'primary', className }: ProgressBarProps) {
  const computed = typeof ratio === 'number' ? ratio : max ? (value ?? 0) / max : 0;
  const pct = Math.max(0, Math.min(1, computed)) * 100;
  return (
    <div className={cn('h-2 overflow-hidden rounded-full bg-outline/30', className)}>
      <div
        className={cn('h-full rounded-full transition-all', fillClass[tone])}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
