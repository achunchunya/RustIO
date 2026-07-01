import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { Dialog } from './Dialog';
import { IconCheck } from './icons';
import { toBilingualNotice } from '../../utils/bilingual';

/** 全局成功提示:居中弹窗 + 绿色对勾,默认约 2.5s 自动消失,也可点击遮罩关闭。 */
const ToastContext = createContext<(message: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const close = useCallback(() => {
    clearTimer();
    setMessage(null);
  }, [clearTimer]);

  const showSuccess = useCallback(
    (text: string) => {
      clearTimer();
      setMessage(toBilingualNotice(text));
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        setMessage(null);
      }, 2500);
    },
    [clearTimer]
  );

  return (
    <ToastContext.Provider value={showSuccess}>
      {children}
      <Dialog open={!!message} onClose={close} className="max-w-sm">
        <div className="flex flex-col items-center gap-3 py-2 text-center">
          <span className="grid h-12 w-12 place-items-center rounded-full bg-primary/10 text-primary">
            <IconCheck size={26} />
          </span>
          <p className="whitespace-pre-wrap text-sm font-medium text-on-surface">{message}</p>
        </div>
      </Dialog>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
