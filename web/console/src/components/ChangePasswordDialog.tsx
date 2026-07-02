import { useState } from 'react';
import type { ApiClient } from '../api/client';
import { authService } from '../api/services';
import { Dialog } from './ui/Dialog';
import { Button } from './ui/Button';
import { Field, Input } from './ui/Field';
import { useToast } from './ui';
import { toBilingualPrompt } from '../utils/bilingual';

type ChangePasswordDialogProps = {
  open: boolean;
  onClose: () => void;
  client: ApiClient;
};

/** 自助修改本人密码:原密码 + 新密码 + 确认新密码,成功后弹窗提示并关闭。 */
export function ChangePasswordDialog({ open, onClose, client }: ChangePasswordDialogProps) {
  const toast = useToast();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setError('');
  };

  const close = () => {
    reset();
    onClose();
  };

  const submit = async () => {
    setError('');
    if (newPassword.length < 8) {
      setError('新密码长度不能少于 8 位');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致');
      return;
    }
    setBusy(true);
    try {
      await authService.changePassword(client, {
        current_password: currentPassword,
        new_password: newPassword
      });
      toast.success('密码修改成功');
      close();
    } catch (requestError) {
      setError(requestError instanceof Error ? toBilingualPrompt(requestError.message) : '密码修改失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      title="修改密码"
      description="修改当前登录账号的密码"
      footer={
        <>
          <Button variant="tertiary" onClick={close} disabled={busy}>
            取消
          </Button>
          <Button variant="primary" onClick={submit} disabled={busy}>
            {busy ? '提交中...' : '确认修改'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <Field label="原密码">
          <Input
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
          />
        </Field>
        <Field label="新密码" hint="长度不少于 8 位">
          <Input
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </Field>
        <Field label="确认新密码">
          <Input
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
          />
        </Field>
        {error ? <p className="text-sm text-error">{error}</p> : null}
      </div>
    </Dialog>
  );
}
