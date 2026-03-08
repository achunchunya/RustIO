import type { LoginResponse } from '../types';

export type LoginProvider = 'local' | 'oidc' | 'ldap';

export function isLoginProvider(value: string): value is LoginProvider {
  return value === 'local' || value === 'oidc' || value === 'ldap';
}

export function loginProviderLabel(provider: LoginProvider): string {
  switch (provider) {
    case 'oidc':
      return 'OIDC';
    case 'ldap':
      return 'LDAP';
    case 'local':
    default:
      return '本地账号';
  }
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) {
    return null;
  }

  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    return JSON.parse(window.atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function resolveSessionUsername(
  provider: LoginProvider,
  username: string,
  response: LoginResponse
): string {
  const payload = decodeJwtPayload(response.access_token);
  const subject = typeof payload?.sub === 'string' ? payload.sub.trim() : '';
  if (subject) {
    return subject;
  }

  if (provider === 'oidc') {
    const preferredUsername =
      typeof payload?.preferred_username === 'string' ? payload.preferred_username.trim() : '';
    if (preferredUsername) {
      return preferredUsername;
    }
  }

  return username.trim() || 'unknown';
}
