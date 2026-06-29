import { useState } from 'react';
import { Button } from './ui/Button';
import { Dialog } from './ui/Dialog';
import { Field, Textarea } from './ui/Field';

type ConfirmActionDialogProps = {
  title: string;
  description: string;
  actionLabel: string;
  onConfirm: (reason: string) => Promise<void>;
};

/** 危险操作二次确认弹窗:触发按钮 + 审计原因输入(reason 必填),保留 x-rustio-confirm 流程。 */
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
      <Button variant="danger" size="sm" onClick={() => setOpen(true)}>
        {actionLabel}
      </Button>

      <Dialog
        open={open}
        onClose={() => (loading ? undefined : setOpen(false))}
        title={title}
        description={description}
        footer={
          <>
            <Button variant="tertiary" onClick={() => setOpen(false)} disabled={loading}>
              取消
            </Button>
            <Button
              variant="danger"
              loading={loading}
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
            </Button>
          </>
        }
      >
        <Field label="审计原因" htmlFor="confirm-reason">
          <Textarea
            id="confirm-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="请填写本次操作的原因,用于审计追踪"
          />
        </Field>
      </Dialog>
    </>
  );
}
