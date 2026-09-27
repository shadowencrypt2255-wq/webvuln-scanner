"use client";

const BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
const PREFIX = "/api/v1";

const ACCESS_KEY = "sx_access";
const REFRESH_KEY = "sx_refresh";

export function getToken(): string | null {
  try {
    return localStorage.getItem(ACCESS_KEY);
  } catch {
    return null;
  }
}

export function setTokens(access: string, refresh: string) {
  try {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  } catch {
    /* ignore */
  }
}

export function clearTokens() {
  try {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function refreshToken(): Promise<boolean> {
  let refresh: string | null = null;
  try {
    refresh = localStorage.getItem(REFRESH_KEY);
  } catch {
    return false;
  }
  if (!refresh) return false;
  const resp = await fetch(`${BASE}${PREFIX}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!resp.ok) return false;
  const data = await resp.json();
  setTokens(data.access_token, data.refresh_token);
  return true;
}

interface Options {
  method?: string;
  body?: unknown;
  retry?: boolean;
}

export async function api<T>(path: string, opts: Options = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;

  const resp = await fetch(`${BASE}${PREFIX}${path}`, {
    method: opts.method || "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  if (resp.status === 401 && opts.retry !== false) {
    if (await refreshToken()) {
      return api<T>(path, { ...opts, retry: false });
    }
  }

  if (!resp.ok) {
    let detail = `Request failed (${resp.status})`;
    try {
      const data = await resp.json();
      detail = data.detail || detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(resp.status, detail);
  }

  if (resp.status === 204) return undefined as T;
  const text = await resp.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export function downloadUrl(path: string): string {
  return `${BASE}${PREFIX}${path}`;
}

export { BASE, PREFIX };
