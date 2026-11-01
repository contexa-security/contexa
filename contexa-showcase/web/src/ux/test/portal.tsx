import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { Where } from './Where';

/**
 * The portal's answers for a screen test, by request path (with its query): a body answers 200, a number answers
 * that status. Paths not listed answer 404, as the portal does for a record that does not exist. Writes (POST) are
 * kept in `posts` and answered from `postAnswers` by path, 404 otherwise.
 */
export interface PortalStub {
  readonly get: Readonly<Record<string, unknown>>;
  readonly postAnswers?: Readonly<Record<string, { readonly status: number; readonly body: unknown }>>;
  /** An answer that depends on the body (the rule engine decides each setting); tried before `postAnswers`. */
  readonly postReply?: (path: string, body: unknown) => { readonly status: number; readonly body: unknown } | undefined;
}

export interface Posted {
  readonly path: string;
  readonly body: unknown;
}

export function stubPortal(stub: PortalStub): Posted[] {
  const posts: Posted[] = [];
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const json = (status: number, body: unknown) =>
      Promise.resolve(
        new Response(body === null ? null : JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    if (init?.method === 'POST') {
      const body = init.body ? (JSON.parse(String(init.body)) as unknown) : null;
      posts.push({ path, body });
      const answer = stub.postReply?.(path, body) ?? stub.postAnswers?.[path];
      return answer ? json(answer.status, answer.body) : json(404, {});
    }
    const found = stub.get[path];
    if (found === undefined) {
      return json(404, {});
    }
    return typeof found === 'number' ? json(found, {}) : json(200, found);
  });
  return posts;
}

export function renderAt(address: string, element: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[address]}>
        {element}
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
