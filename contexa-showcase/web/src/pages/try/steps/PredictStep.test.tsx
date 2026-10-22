import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LabCase } from '../../../api/lab';
import '../../../i18n';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { required } from '../../../test/required';
import type { Role } from '../experience';
import { PredictStep } from './PredictStep';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

// The journey update and the live send as the screen calls them; sending runs the screen's preparation first.
const sent = vi.hoisted(() => ({ updates: [] as unknown[] }));
vi.mock('../../../api/journey', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../api/journey')>()),
  useJourneyUpdate: () => async (update: unknown) => {
    sent.updates.push(update);
    return null;
  },
}));
vi.mock('../../../hooks/useLiveSend', () => ({
  useLiveSend: () => ({
    ready: true,
    sending: false,
    waiting: false,
    refusal: null,
    turnstileRequired: false,
    turnstileContainer: () => undefined,
    send: async (prepare?: () => Promise<void>) => {
      await prepare?.();
    },
  }),
}));

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  sent.updates = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 404 })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function predict(role: Role) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/try/${role}/predict`]}>
        <PredictStep
          role={role}
          mode="sync"
          labCase={{ key: role === 'attacker' ? 'A3' : 'A3T', requests: [{}] } as unknown as LabCase}
          flow={{ back: null, next: null, teaser: null }}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/**
 * 1-2 and 2-1 (T3): one question, the three final responses (판정층 E-8b: ESCALATE hands the request to the second
 * analysis, so it is no choice), Send off until one is picked; only the judgment is asked.
 */
describe('pick first', () => {
  it.each([
    ['attacker', '1-2', 'E1'],
    ['owner', '2-1', 'E2'],
  ] as const)('asks the %s only for the judgment and stores just that', async (role, number, experience) => {
    predict(role);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(word(`screen.${number}.title`));
    const choices = screen.getAllByRole('radio');
    expect(choices).toHaveLength(3);
    const group = required(choices[0]?.closest('fieldset'), 'choices');
    expect(group).toHaveAttribute('data-count', 'exempt');
    for (const label of ['verdict.allow', 'verdict.verify', 'verdict.block']) {
      expect(within(group).getByText(word(label))).toBeInTheDocument();
    }
    expect(within(group).queryByText(word('verdict.review'))).toBeNull();
    // The old extra questions and the way to send without picking are gone.
    expect(screen.queryByText(word('e1.predict.existingShort'))).toBeNull();
    expect(screen.queryByText(word('e2.predict.numberRule'))).toBeNull();
    expect(screen.queryByText(word('e1.predict.sendWithout'))).toBeNull();

    const send = screen.getByRole('button', { name: word('p1.predict.send') });
    expect(send).toBeDisabled();
    await userEvent.click(within(group).getByText(word('verdict.block')));
    expect(send).toBeEnabled();
    await userEvent.click(send);
    expect(sent.updates).toEqual([{ prediction: { experience, engine: 'BLOCK' } }]);
  });
});
