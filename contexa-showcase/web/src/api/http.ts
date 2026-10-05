/**
 * Calls to the portal's visitor API. Requests carry the visitor cookie (same origin) and, for writes, the CSRF token
 * the portal wrote into the readable XSRF-TOKEN cookie; the portal accepts the raw token in the header.
 */
export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const CSRF_COOKIE = 'XSRF-TOKEN';
const CSRF_HEADER = 'X-XSRF-TOKEN';

function readCookie(name: string): string | null {
  for (const part of document.cookie.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) {
      return decodeURIComponent(rest.join('='));
    }
  }
  return null;
}

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new HttpError(response.status, `GET ${path} failed with ${response.status}`);
  }
  return (await response.json()) as T;
}

export interface PostResult<T> {
  readonly status: number;
  readonly body: T | null;
}

/** Posts JSON; any status is returned to the caller, which decides what a refusal means. */
export async function postJson<T>(path: string, body: unknown): Promise<PostResult<T>> {
  const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': 'application/json' };
  const token = readCookie(CSRF_COOKIE);
  if (token) {
    headers[CSRF_HEADER] = token;
  }
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? (JSON.parse(text) as T) : null };
}
