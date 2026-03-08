import { useState } from 'react';

type ConfirmActionDialogProps = {
  title: string;
  description: string;
  actionLabel: string;
  onConfirm: (reason: string) => Promise<void>;
};

export function ConfirmActionDialog({
  title,
  description,
  actionLabel,
  onConfirm
}: ConfirmActionDialogProps) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);

  return (
    <>
      <button
        className="rounded-md border border-pulse-500/70 px-3 py-2 text-sm text-pulse-500 transition hover:bg-pulse-500/20"
        onClick={() => setOpen(true)}
      >
        {actionLabel}
      </button>

      {open ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-white/10 bg-ink-800 p-6 shadow-panel">
            <h3 className="font-heading text-xl text-white">{title}</h3>
            <p className="mt-2 text-sm text-slate-300">{description}</p>
            <label className="mt-4 block text-sm text-slate-300" htmlFor="reason">
              审计原因
            </label>
            <textarea
              id="reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              className="mt-2 h-24 w-full rounded-md border border-white/10 bg-ink-900 px-3 py-2 text-sm text-slate-100"
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                className="rounded-md border border-white/15 px-3 py-2 text-sm text-slate-200"
                onClick={() => setOpen(false)}
                disabled={loading}
              >
                取消
              </button>
              <button
                className="rounded-md bg-pulse-600 px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
                disabled={!reason || loading}
                onClick={async () => {
                  setLoading(true);
                  try {
                    await onConfirm(reason);
                    setOpen(false);
                    setReason('');
                  } finally {
                    setLoading(false);
                  }
                }}
              >
                {loading ? '提交中...' : '确认执行'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
