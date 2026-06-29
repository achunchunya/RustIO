import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import { Dialog } from './Dialog';
import { Button } from './Button';

export type ConfirmOptions = {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
};

type PendingConfirm = {
  options: ConfirmOptions;
  resolve: (result: boolean) => void;
};

const ConfirmContext = createContext<(opt: string | ConfirmOptions) => Promise<boolean>>(() =>
  Promise.resolve(false)
);

/**
 * 自研全局确认弹窗 —— Promise 式 useConfirm(),替代原生 window.confirm。
 * 调用:`if (!(await confirm('确认删除?'))) return;`
 */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const confirm = useCallback((opt: string | ConfirmOptions) => {
    const options = typeof opt === 'string' ? { message: opt } : opt;
    return new Promise<boolean>((resolve) => setPending({ options, resolve }));
  }, []);

  const settle = useCallback(
    (result: boolean) => {
      setPending((current) => {
        current?.resolve(result);
        return null;
      });
    },
    []
  );

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Dialog
        open={!!pending}
        onClose={() => settle(false)}
        title={pending?.options.title ?? '确认操作'}
        footer={
          <>
            <Button variant="tertiary" onClick={() => settle(false)}>
              {pending?.options.cancelLabel ?? '取消'}
            </Button>
            <Button
              variant={pending?.options.danger === false ? 'primary' : 'danger'}
              onClick={() => settle(true)}
            >
              {pending?.options.confirmLabel ?? '确认'}
            </Button>
          </>
        }
      >
        <p className="whitespace-pre-wrap text-sm text-on-surface">{pending?.options.message}</p>
      </Dialog>
    </ConfirmContext.Provider>
  );
}

export const useConfirm = () => useContext(ConfirmContext);
