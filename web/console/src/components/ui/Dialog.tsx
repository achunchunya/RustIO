import type { ReactNode } from 'react';
import { cn } from './cn';
import { IconX } from './icons';

type DialogProps = {
  open: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  footer?: ReactNode;
  children?: ReactNode;
  className?: string;
};

/** 模态对话框基座:遮罩 + 居中卡片 + 标题/正文/页脚槽。 */
export function Dialog({ open, onClose, title, description, footer, children, className }: DialogProps) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-on-surface/40 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className={cn(
          'w-full max-w-md rounded-lg border border-outline/60 bg-surface-container p-6 shadow-soft',
          className
        )}
        onClick={(event) => event.stopPropagation()}
      >
        {title ? (
          <div className="mb-4 flex items-start justify-between gap-4">
            <div>
              <h3 className="font-heading text-lg font-semibold text-on-surface">{title}</h3>
              {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
            </div>
            <button
              onClick={onClose}
              className="rounded p-1 text-muted transition hover:bg-surface-container-high hover:text-on-surface"
              aria-label="关闭"
            >
              <IconX size={18} />
            </button>
          </div>
        ) : null}
        {children}
        {footer ? <div className="mt-6 flex justify-end gap-2">{footer}</div> : null}
      </div>
    </div>
  );
}
