import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiBase, apiClient } from '../api/client';
import { authService } from '../api/services';
import type { AuthProviderInfo, LoginResponse } from '../types';
import {
  isLoginProvider,
  loginProviderLabel,
  LoginProvider,
  resolveSessionUsername
} from '../utils/auth';
import { toBilingualPrompt } from '../utils/bilingual';

type LoginPageProps = {
  onLogin: (username: string, auth: LoginResponse) => void;
};

type ConfiguredLoginProvider = AuthProviderInfo & { id: LoginProvider };

const FALLBACK_PROVIDERS: ConfiguredLoginProvider[] = [
  {
    id: 'local',
    enabled: true,
    configured: true,
    supports_username_password: true,
    supports_browser_redirect: false,
    supports_id_token: false,
    authorize_url: null,
    missing_requirements: []
  },
  {
    id: 'oidc',
    enabled: false,
    configured: false,
    supports_username_password: false,
    supports_browser_redirect: true,
    supports_id_token: true,
    authorize_url: '/api/v1/auth/oidc/authorize',
    missing_requirements: []
  },
  {
    id: 'ldap',
    enabled: false,
    configured: false,
    supports_username_password: true,
    supports_browser_redirect: false,
    supports_id_token: false,
    authorize_url: null,
    missing_requirements: []
  }
];

export function LoginPage({ onLogin }: LoginPageProps) {
  const [provider, setProvider] = useState<LoginProvider>('local');
  const [providers, setProviders] = useState<ConfiguredLoginProvider[]>(FALLBACK_PROVIDERS);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [idToken, setIdToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [providersLoading, setProvidersLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    authService
      .providers(apiClient)
      .then((response) => {
        if (cancelled) {
          return;
        }
        const nextProviders = response.filter(
          (item): item is ConfiguredLoginProvider => isLoginProvider(item.id)
        );
        const orderedProviders =
          nextProviders.length > 0
            ? (['local', 'oidc', 'ldap'] as LoginProvider[])
                .map((id) => nextProviders.find((item) => item.id === id))
                .filter((item): item is ConfiguredLoginProvider => !!item)
            : FALLBACK_PROVIDERS;
        setProviders(nextProviders);
        setProvider((current) =>
          orderedProviders.some((item) => item.id === current && item.enabled)
            ? current
            : orderedProviders.find((item) => item.enabled)?.id ?? orderedProviders[0].id
        );
        setProviders(orderedProviders);
      })
      .catch(() => {
        if (cancelled) {
          return;
        }
        setProviders(FALLBACK_PROVIDERS);
        setProvider('local');
      })
      .finally(() => {
        if (!cancelled) {
          setProvidersLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const activeProvider =
    providers.find((item) => item.id === provider) ?? FALLBACK_PROVIDERS[0];
  const hasMultipleProviders = providers.length > 1;
  const providerGridClass =
    providers.length >= 3 ? 'grid-cols-3' : providers.length === 2 ? 'grid-cols-2' : 'grid-cols-1';

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload =
        provider === 'oidc'
          ? {
              username: username.trim(),
              password: '',
              provider: 'oidc',
              id_token: idToken.trim()
            }
          : provider === 'ldap'
            ? {
                username: username.trim(),
                password,
                provider: 'ldap'
              }
            : {
                username: username.trim(),
                password
              };
      const response = await authService.login(apiClient, payload);
      onLogin(resolveSessionUsername(provider, username, response), response);
      navigate('/dashboard');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : '登录失败');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form
        className="w-full max-w-md rounded-2xl border border-white/10 bg-ink-800/75 p-8 shadow-panel"
        onSubmit={handleSubmit}
      >
        <h1 className="font-heading text-3xl text-white">RustIO 管理控制台</h1>

        {hasMultipleProviders ? (
          <div
            className={`mt-6 grid ${providerGridClass} gap-2 rounded-xl border border-white/10 bg-black/10 p-2`}
            role="tablist"
            aria-label="登录方式"
          >
            {providers.map((item) => (
              <button
                key={item.id}
                type="button"
                disabled={!item.enabled}
                title={
                  item.enabled
                    ? loginProviderLabel(item.id)
                    : `${loginProviderLabel(item.id)}（未启用）`
                }
                onClick={() => {
                  if (item.enabled) {
                    setProvider(item.id);
                  }
                }}
                className={`min-h-12 rounded-lg px-3 py-2 text-sm transition ${
                  provider === item.id
                    ? 'bg-pulse-600 font-medium text-white'
                    : item.enabled
                      ? 'bg-transparent text-slate-300 hover:bg-white/5'
                      : 'cursor-not-allowed bg-transparent text-slate-500 opacity-70'
                }`}
              >
                <span className="block">{loginProviderLabel(item.id)}</span>
                {!item.enabled ? (
                  <span className="mt-1 block text-[11px] font-normal text-slate-500">
                    未启用
                  </span>
                ) : null}
              </button>
            ))}
          </div>
        ) : (
          <div className="mt-6 rounded-xl border border-white/10 bg-black/10 p-2">
            <div className="flex min-h-11 items-center justify-between gap-3 rounded-lg border border-pulse-500/30 bg-pulse-500/10 px-4 py-3">
              <div>
                <p className="text-sm font-medium text-white">{loginProviderLabel(activeProvider.id)}</p>
                <p className="mt-1 text-xs text-slate-300">当前环境只启用这一种登录方式</p>
              </div>
              <span className="rounded-full border border-pulse-500/30 bg-pulse-500/15 px-2.5 py-1 text-xs text-pulse-100">
                已启用
              </span>
            </div>
          </div>
        )}

        {providersLoading ? <p className="mt-3 text-xs text-slate-500">正在读取已启用的登录方式…</p> : null}

        {activeProvider.supports_username_password ? (
          <>
            <label className="mt-6 block text-sm text-slate-300" htmlFor="username">
              用户名
            </label>
            <input
              id="username"
              className="mt-2 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="请输入用户名"
            />

            <label className="mt-4 block text-sm text-slate-300" htmlFor="password">
              密码
            </label>
            <div className="relative mt-2">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                className="h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 pr-16 text-slate-100"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="请输入密码"
              />
              <button
                type="button"
                aria-label={showPassword ? '隐藏密码' : '显示密码'}
                onClick={() => setShowPassword((current) => !current)}
                className="absolute right-2 top-1/2 inline-flex h-8 min-w-12 -translate-y-1/2 items-center justify-center rounded-md border border-white/10 bg-white/5 px-2 text-xs text-slate-300 transition hover:bg-white/10 hover:text-white"
              >
                {showPassword ? '隐藏' : '显示'}
              </button>
            </div>
          </>
        ) : (
          <>
            {activeProvider.supports_browser_redirect ? (
              <>
                <label className="mt-6 block text-sm text-slate-300" htmlFor="id_token">
                  浏览器跳转登录
                </label>
                <button
                  type="button"
                  onClick={() =>
                    window.location.assign(
                      `${apiBase}${activeProvider.authorize_url ?? '/api/v1/auth/oidc/authorize'}`
                    )
                  }
                  className="mt-2 h-11 w-full rounded-md border border-pulse-500/60 bg-pulse-500/10 px-4 text-sm font-medium text-pulse-100 transition hover:bg-pulse-500/20"
                >
                  使用 OIDC 浏览器登录
                </button>
              </>
            ) : null}
            {activeProvider.supports_id_token ? (
              <>
                <p className="mt-2 text-xs text-slate-400">
                  推荐使用浏览器授权码 + PKCE 流；下方保留手工粘贴 ID Token 的兼容入口。
                </p>

                <label className="mt-5 block text-sm text-slate-300" htmlFor="id_token">
                  ID Token（兼容模式）
                </label>
                <textarea
                  id="id_token"
                  className="mt-2 min-h-40 w-full rounded-md border border-white/15 bg-ink-900 px-3 py-3 text-slate-100"
                  value={idToken}
                  onChange={(event) => setIdToken(event.target.value)}
                  placeholder="请粘贴 OIDC 身份提供方签发的 ID Token"
                />
                <label className="mt-4 block text-sm text-slate-300" htmlFor="oidc_username_hint">
                  用户名提示（可选）
                </label>
                <input
                  id="oidc_username_hint"
                  className="mt-2 h-11 w-full rounded-md border border-white/15 bg-ink-900 px-3 text-slate-100"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="仅在 Token 无法解析时作为回退显示"
                />
              </>
            ) : null}
          </>
        )}

        {error ? <p className="mt-3 text-sm text-rose-400">{toBilingualPrompt(error)}</p> : null}

        <button
          type="submit"
          disabled={loading}
          className="mt-6 h-11 w-full rounded-md bg-pulse-600 font-medium text-white disabled:opacity-60"
        >
          {loading ? '登录中...' : '登录'}
        </button>
      </form>
    </div>
  );
}
