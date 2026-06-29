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
import { Logo } from '../components/ui/Logo';
import { Button } from '../components/ui/Button';
import { Field, Input, Textarea } from '../components/ui/Field';
import { ThemeToggle } from '../components/ui/ThemeToggle';
import { cn } from '../components/ui/cn';
import { IconEye, IconEyeOff, IconKey, IconLock } from '../components/ui/icons';

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
  const [remember, setRemember] = useState(true);
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

  const activeProvider = providers.find((item) => item.id === provider) ?? FALLBACK_PROVIDERS[0];
  const hasMultipleProviders = providers.length > 1;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      const payload =
        provider === 'oidc'
          ? { username: username.trim(), password: '', provider: 'oidc', id_token: idToken.trim() }
          : provider === 'ldap'
            ? { username: username.trim(), password, provider: 'ldap' }
            : { username: username.trim(), password };
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
    <div className="bg-dot-grid grid min-h-screen place-items-center bg-surface px-4 py-10">
      <div className="absolute right-6 top-6">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="grid h-24 w-24 place-items-center rounded-xl border border-outline/60 bg-surface-lowest shadow-soft">
            <Logo size={22} />
          </div>
          <h1 className="mt-6 font-heading text-[2.1rem] font-semibold leading-tight tracking-tight text-on-surface">
            登录 RustIO 控制台
          </h1>
          <p className="mt-3 max-w-xs text-base text-muted">轻松管理你的高性能存储集群。</p>
        </div>

        <form
          className="rounded-lg border border-outline/60 bg-surface-container p-7 shadow-soft"
          onSubmit={handleSubmit}
        >
          {hasMultipleProviders ? (
            <div
              className="mb-6 grid gap-1.5 rounded-md border border-outline/50 bg-surface-container-high p-1"
              style={{ gridTemplateColumns: `repeat(${providers.length}, minmax(0, 1fr))` }}
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
                  onClick={() => item.enabled && setProvider(item.id)}
                  className={cn(
                    'min-h-11 rounded px-3 py-2 text-sm transition',
                    provider === item.id
                      ? 'bg-primary font-medium text-on-primary'
                      : item.enabled
                        ? 'text-muted hover:bg-surface-container'
                        : 'cursor-not-allowed text-muted/50'
                  )}
                >
                  <span className="block">{loginProviderLabel(item.id)}</span>
                  {!item.enabled ? (
                    <span className="mt-0.5 block text-[11px] font-normal text-muted/60">未启用</span>
                  ) : null}
                </button>
              ))}
            </div>
          ) : null}

          {providersLoading ? (
            <p className="mb-4 text-xs text-muted">正在读取已启用的登录方式…</p>
          ) : null}

          {activeProvider.supports_username_password ? (
            <div className="space-y-4">
              <Field label="用户名" htmlFor="username">
                <div className="relative">
                  <IconKey
                    size={18}
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                  />
                  <Input
                    id="username"
                    className="pl-10"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    placeholder="请输入用户名"
                  />
                </div>
              </Field>
              <Field label="密码" htmlFor="password">
                <div className="relative">
                  <IconLock
                    size={18}
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                  />
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    className="pl-10 pr-11"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="请输入密码"
                  />
                  <button
                    type="button"
                    aria-label={showPassword ? '隐藏密码' : '显示密码'}
                    onClick={() => setShowPassword((current) => !current)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted transition hover:text-on-surface"
                  >
                    {showPassword ? <IconEyeOff size={18} /> : <IconEye size={18} />}
                  </button>
                </div>
              </Field>
              <label className="flex cursor-pointer items-center gap-2 text-sm text-muted">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(event) => setRemember(event.target.checked)}
                  className="h-4 w-4 rounded border-outline accent-primary"
                />
                记住设备
              </label>
            </div>
          ) : (
            <div className="space-y-4">
              {activeProvider.supports_browser_redirect ? (
                <Button
                  type="button"
                  className="w-full"
                  variant="secondary"
                  onClick={() =>
                    window.location.assign(
                      `${apiBase}${activeProvider.authorize_url ?? '/api/v1/auth/oidc/authorize'}`
                    )
                  }
                >
                  使用 OIDC 浏览器登录
                </Button>
              ) : null}
              {activeProvider.supports_id_token ? (
                <>
                  <p className="text-xs text-muted">
                    推荐使用浏览器授权码 + PKCE 流;下方保留手工粘贴 ID Token 的兼容入口。
                  </p>
                  <Field label="ID Token(兼容模式)" htmlFor="id_token">
                    <Textarea
                      id="id_token"
                      className="min-h-32"
                      value={idToken}
                      onChange={(event) => setIdToken(event.target.value)}
                      placeholder="请粘贴 OIDC 身份提供方签发的 ID Token"
                    />
                  </Field>
                  <Field label="用户名提示(可选)" htmlFor="oidc_username_hint">
                    <Input
                      id="oidc_username_hint"
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      placeholder="仅在 Token 无法解析时作为回退显示"
                    />
                  </Field>
                </>
              ) : null}
            </div>
          )}

          {error ? <p className="mt-4 text-sm text-error">{toBilingualPrompt(error)}</p> : null}

          <Button type="submit" className="mt-6 w-full" loading={loading}>
            {loading ? '登录中...' : '登录'}
          </Button>
        </form>
      </div>
    </div>
  );
}
