import type { HTMLAttributes, LabelHTMLAttributes, ReactNode } from 'react';
import { cn } from './cn';

/** 卡片容器:surface-container 面 + 细描边,贴合"色层分层"而非阴影。 */
export function Card({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-lg border border-outline/60 bg-surface-container p-5',
        className
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

/** 内层小面板(卡片内的次级分区):更高一层的 surface。 */
export function Panel({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-md border border-outline/40 bg-surface-container-high p-4',
        className
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

/** 区块标题(卡片内子标题)。 */
export function SectionTitle({
  className,
  children,
  ...rest
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3 className={cn('font-heading text-lg font-semibold text-on-surface', className)} {...rest}>
      {children}
    </h3>
  );
}

type PageHeaderProps = {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  className?: string;
};

/** 页面大标题区:大标题 + 副标题 + 右侧操作区。 */
export function PageHeader({ title, subtitle, actions, className }: PageHeaderProps) {
  return (
    <div className={cn('mb-8 flex flex-wrap items-end justify-between gap-4', className)}>
      <div>
        <h1 className="font-heading text-3xl font-semibold tracking-tight text-on-surface">
          {title}
        </h1>
        {subtitle ? <p className="mt-2 text-sm text-muted">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** 表单/区块标签(label-md:大写 + 字距)。 */
export function FieldLabel({
  className,
  children,
  ...rest
}: LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      className={cn('text-xs font-medium uppercase tracking-[0.08em] text-muted', className)}
      {...rest}
    >
      {children}
    </label>
  );
}
