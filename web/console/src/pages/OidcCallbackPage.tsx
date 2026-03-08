import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';
import { authService } from '../api/services';
import type { LoginResponse } from '../types';
import { resolveSessionUsername } from '../utils/auth';
import { toBilingualPrompt } from '../utils/bilingual';

type OidcCallbackPageProps = {
  onLogin: (username: string, auth: LoginResponse) => void;
};

export function OidcCallbackPage({ onLogin }: OidcCallbackPageProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  const search = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const requestId = search.get('request_id')?.trim() ?? '';
  const callbackError = search.get('error')?.trim() ?? '';

  useEffect(() => {
    if (callbackError) {
      setError(callbackError);
      return;
    }

    if (!requestId) {
      setError('OIDC 登录回调缺少请求标识');
      return;
    }

    let cancelled = false;
    authService
      .redeemOidcSession(apiClient, requestId)
      .then((response) => {
        if (cancelled) return;
        onLogin(resolveSessionUsername('oidc', '', response), response);
        navigate('/dashboard', { replace: true });
      })
      .catch((requestError) => {
        if (cancelled) return;
        setError(requestError instanceof Error ? requestError.message : 'OIDC 登录失败');
      });

    return () => {
      cancelled = true;
    };
  }, [callbackError, navigate, onLogin, requestId]);

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-ink-800/75 p-8 shadow-panel">
        <h1 className="font-heading text-3xl text-white">OIDC 登录处理中</h1>
        <p className="mt-2 text-sm text-slate-300">正在完成浏览器授权码登录并换取控制台会话。</p>
        {error ? <p className="mt-4 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}
        {!error ? <p className="mt-4 text-sm text-slate-400">请稍候，系统会自动跳转到控制台。</p> : null}
      </div>
    </div>
  );
}
