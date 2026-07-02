import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { Dialog } from './Dialog';
import { Button } from './Button';
import { IconCheck, IconWarning } from './icons';
import { toBilingualNotice, toBilingualPrompt } from '../../utils/bilingual';

type ToastKind = 'success' | 'error';

type ToastState = {
  kind: ToastKind;
  message: string;
};

export type ToastApi = {
  /** 成功提示:居中弹窗,约 2.5s 自动消失,也可点击"确认"提前关闭。 */
  success: (message: string) => void;
  /** 失败提示:居中弹窗,不自动消失,须点击"确认"关闭。 */
  error: (message: string) => void;
};

const noop: ToastApi = { success: () => {}, error: () => {} };
const ToastContext = createContext<ToastApi>(noop);

const AUTO_DISMISS_MS = 2500;

/** 全局提示弹窗:成功(绿色对勾,自动消失+可提前确认关闭)与失败(黄色警示,须手动确认关闭)。 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastState | null>(null);
  const timerRef = useRef<number | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const close = useCallback(() => {
    clearTimer();
    setToast(null);
  }, [clearTimer]);

  const success = useCallback(
    (text: string) => {
      clearTimer();
      setToast({ kind: 'success', message: toBilingualNotice(text) });
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        setToast(null);
      }, AUTO_DISMISS_MS);
    },
    [clearTimer]
  );

  const error = useCallback(
    (text: string) => {
      clearTimer();
      setToast({ kind: 'error', message: toBilingualPrompt(text) });
    },
    [clearTimer]
  );

  const api = useMemo(() => ({ success, error }), [success, error]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <Dialog open={!!toast} onClose={close} className="max-w-sm">
        <div className="flex flex-col items-center gap-3 py-2 text-center">
          <span
            className={
              toast?.kind === 'error'
                ? 'grid h-12 w-12 place-items-center rounded-full bg-error/10 text-error'
                : 'grid h-12 w-12 place-items-center rounded-full bg-primary/10 text-primary'
            }
          >
            {toast?.kind === 'error' ? <IconWarning size={26} /> : <IconCheck size={26} />}
          </span>
          <p className="whitespace-pre-wrap text-sm font-medium text-on-surface">{toast?.message}</p>
          <Button variant={toast?.kind === 'error' ? 'danger' : 'primary'} size="sm" onClick={close}>
            确认
          </Button>
        </div>
      </Dialog>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
