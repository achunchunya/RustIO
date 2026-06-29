import type {
  InputHTMLAttributes,
  TextareaHTMLAttributes,
  SelectHTMLAttributes,
  ReactNode
} from 'react';
import { cn } from './cn';
import { FieldLabel } from './Card';

const controlBase =
  'w-full rounded-md border border-outline bg-surface-lowest text-on-surface ' +
  'placeholder:text-muted/60 transition focus-visible:outline-none ' +
  'focus-visible:border-primary disabled:opacity-50';

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> & { size?: 'sm' | 'md' };

export function Input({ className, size = 'md', ...rest }: InputProps) {
  return (
    <input
      className={cn(controlBase, size === 'sm' ? 'h-9 px-2.5 text-xs' : 'h-10 px-3 text-sm', className)}
      {...rest}
    />
  );
}

export function Textarea({
  className,
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(controlBase, 'min-h-24 px-3 py-2 text-sm', className)} {...rest} />;
}

type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, 'size'> & { size?: 'sm' | 'md' };

export function Select({ className, size = 'md', children, ...rest }: SelectProps) {
  return (
    <select
      className={cn(controlBase, size === 'sm' ? 'h-9 px-2 text-xs' : 'h-10 px-3 text-sm', className)}
      {...rest}
    >
      {children}
    </select>
  );
}

type FieldProps = {
  label?: string;
  hint?: ReactNode;
  htmlFor?: string;
  className?: string;
  children: ReactNode;
};

/** 字段容器:大写标签在上 + 控件 + 可选提示。 */
export function Field({ label, hint, htmlFor, className, children }: FieldProps) {
  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      {label ? <FieldLabel htmlFor={htmlFor}>{label}</FieldLabel> : null}
      {children}
      {hint ? <span className="text-xs text-muted">{hint}</span> : null}
    </div>
  );
}
