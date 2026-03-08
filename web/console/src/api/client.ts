import type { ApiEnvelope } from '../types';
import { toBilingualPrompt } from '../utils/bilingual';

function resolveApiBase() {
  const configured = import.meta.env.VITE_API_BASE?.trim();
  if (configured) {
    return configured.replace(/\/+$/, '');
  }

  if (typeof window !== 'undefined') {
    const { protocol, hostname, host } = window.location;
    if (import.meta.env.DEV) {
      return `${protocol}//${hostname}:9000`;
    }
    return `${protocol}//${host}`;
  }

  return 'http://127.0.0.1:9000';
}

const API_BASE = resolveApiBase();

type AuthHooks = {
  getAccessToken: () => string | undefined;
  refreshAccessToken: () => Promise<string | null>;
  onAuthFailure?: () => void;
};

export class ApiClient {
  constructor(
    private readonly token?: string,
    private readonly authHooks?: AuthHooks
  ) {}

  withToken(token: string) {
    return new ApiClient(token, this.authHooks);
  }

  withAuth(authHooks: AuthHooks) {
    return new ApiClient(undefined, authHooks);
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: 'GET' });
  }

  async post<T>(path: string, body?: unknown, danger = false): Promise<T> {
    return this.request<T>(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
      headers: danger ? { 'x-rustio-confirm': 'true' } : undefined
    });
  }

  async patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, {
      method: 'PATCH',
      body: JSON.stringify(body)
    });
  }

  async put<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, {
      method: 'PUT',
      body: JSON.stringify(body)
    });
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: 'DELETE' });
  }

  async putBinary<T>(path: string, body: Blob | ArrayBuffer | Uint8Array): Promise<T> {
    const response = await this.requestRaw(path, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream'
      },
      body: body as BodyInit
    });

    if (!response.ok) {
      throw new Error(await this.resolveErrorMessage(response));
    }

    const json = (await response.json()) as ApiEnvelope<T>;
    return json.data;
  }

  async getBlob(path: string): Promise<Blob> {
    const response = await this.requestRaw(path, { method: 'GET' });
    if (!response.ok) {
      throw new Error(await this.resolveErrorMessage(response));
    }
    return response.blob();
  }

  async getText(path: string): Promise<string> {
    const response = await this.requestRaw(path, { method: 'GET' });
    if (!response.ok) {
      throw new Error(await this.resolveErrorMessage(response));
    }
    return response.text();
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.requestRaw(path, init);

    if (!response.ok) {
      throw new Error(await this.resolveErrorMessage(response));
    }

    const json = (await response.json()) as ApiEnvelope<T>;
    return json.data;
  }

  private async requestRaw(path: string, init: RequestInit, retried = false): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(init.headers as Record<string, string> | undefined)
    };

    const accessToken = this.authHooks?.getAccessToken() ?? this.token;
    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers
    });

    if (
      response.status === 401 &&
      !retried &&
      this.authHooks &&
      this.shouldAttemptTokenRefresh(path)
    ) {
      const refreshedAccessToken = await this.authHooks.refreshAccessToken();
      if (refreshedAccessToken) {
        return this.requestRaw(path, init, true);
      }
      this.authHooks.onAuthFailure?.();
    }

    if (response.status === 401 && retried) {
      this.authHooks?.onAuthFailure?.();
    }

    return response;
  }

  private shouldAttemptTokenRefresh(path: string): boolean {
    return !(
      path.startsWith('/api/v1/auth/login') ||
      path.startsWith('/api/v1/auth/refresh') ||
      path.startsWith('/api/v1/auth/logout') ||
      path.startsWith('/api/v1/auth/oidc/')
    );
  }

  private async resolveErrorMessage(response: Response): Promise<string> {
    const fallback = toBilingualPrompt(`请求失败（HTTP ${response.status}）`);
    const raw = (await response.text()).trim();
    if (!raw) {
      return fallback;
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      try {
        const payload = JSON.parse(raw) as { error?: { message?: string }; message?: string };
        const message = payload.error?.message ?? payload.message;
        if (typeof message === 'string' && message.trim()) {
          return toBilingualPrompt(message);
        }
      } catch {
        // Fall through to raw content.
      }
    }

    if (contentType.includes('application/xml') || raw.startsWith('<?xml')) {
      const xmlMessage = raw.match(/<Message>([\s\S]*?)<\/Message>/i)?.[1];
      if (xmlMessage) {
        return toBilingualPrompt(
          xmlMessage
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&apos;/g, "'")
            .replace(/&amp;/g, '&')
        );
      }
    }

    return toBilingualPrompt(raw);
  }
}

export const apiClient = new ApiClient();
export const apiBase = API_BASE;
