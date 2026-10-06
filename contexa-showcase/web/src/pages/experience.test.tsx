import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../i18n';
import i18n from '../i18n';
import type { LiveLayer, LiveRunView } from '../api/types';
import { replayFixture } from '../test/replayFixture';
import { required } from '../test/required';
import ExperiencePage from './ExperiencePage';

type Handler = (init?: RequestInit) => { status: number; body: unknown };

let routes: Record<string, Handler>;
const calls: { url: string; init: RequestInit | undefined }[] = [];
let current: LiveRunView | null;
let started: number;

const attackScene = required(replayFixture.scenes[0]);
const ownerScene = required(replayFixture.scenes[1]);

function layersOf(scene: typeof attackScene): Partial<Record<'A' | 'B' | 'C1' | 'C2' | 'D', LiveLayer>> {
  return Object.fromEntries(
    scene.layers.map((layer) => [
      layer.control,
      {
        outcome: layer.outcome,
        httpStatus: layer.evidence.httpStatus,
        deliveredItems: layer.evidence.deliveredItems,
        elapsedMs: layer.evidence.responseMs ?? 0,
      },
    ]),
  );
}

function run(status: LiveRunView['status'], layers: LiveRunView['steps'][number]['layers'], key: string): LiveRunView {
  return {
    liveRunId: `live-${started}`,
    scenario: key,
    status,
    queuePosition: 0,
    runId: `run-${started}`,
    readyMs: 900,
    steps: [{ stepNo: 1, operation: 'EXPORT', layers }],
    challenge: null,
    failure: null,
  };
}

beforeEach(() => {
  calls.length = 0;
  current = null;
  started = 0;
  routes = {
    'GET /api/visitor': () => ({ status: 200, body: { predictions: {} } }),
    'GET /api/live/config': () => ({
      status: 200,
      body: { scenarios: [], turnstileSiteKey: null, dailyRuns: 10, remainingToday: 10 - started, paused: false },
    }),
    'GET /api/live/runs/current': () => (current ? { status: 200, body: current } : { status: 404, body: null }),
    'POST /api/live/combinations': (init) => {
      started += 1;
      const { key } = JSON.parse(String(init?.body)) as { key: string };
      current = run('RUNNING', {}, key);
      return { status: 202, body: current };
    },
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      const handler = routes[`${init?.method ?? 'GET'} ${url}`];
      const { status, body } = handler ? handler(init) : { status: 404, body: null };
      return new Response(body === null ? null : JSON.stringify(body), { status });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ExperiencePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function lane(section: string, control: string): HTMLElement {
  const scene = required(document.querySelector<HTMLElement>(`section[aria-labelledby="${section}"]`));
  return required(scene.querySelector<HTMLElement>(`li[data-control="${control}"]`));
}

/** Completes the visitor's current run with the answers of a recorded scene and serves its full result. */
function complete(scene: typeof attackScene) {
  const key = required(current).scenario;
  current = run('COMPLETED', layersOf(scene), key);
  routes['GET /api/live/runs/current/result'] = () => ({ status: 200, body: scene });
}

describe('the hands-on experience', () => {
  it('opens on the attacker scene: the system window, the button and the five approaches on standby', async () => {
    await i18n.changeLanguage('en');
    renderPage();

    expect(
      screen.getByRole('heading', { level: 1, name: 'A correct password can still carry a dangerous request' }),
    ).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: "You have stolen administrator A's password" })).toBeInTheDocument();
    expect(screen.getByText('Administrator A · admin role')).toBeInTheDocument();
    expect(screen.getByText('3:17 am, dawn')).toBeInTheDocument();
    expect(screen.getByText('4,831 GB-500 design documents')).toBeInTheDocument();
    expect(screen.getByText('Press the button and the same request goes to these five')).toBeInTheDocument();
    expect(screen.getAllByText('Waiting')).toHaveLength(5);
    expect(await screen.findByRole('button', { name: 'Send the request to export 4,831' })).toBeEnabled();
  });

  it('sends the export for real, shows each answer as it arrives, then the right answer and the reasons', async () => {
    await i18n.changeLanguage('en');
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Send the request to export 4,831' }));

    const posted = calls.find((call) => call.url === '/api/live/combinations');
    expect(posted?.init?.body).toBe(JSON.stringify({ key: 'adm-a.DAWN.4831.NONE.USUAL', turnstileToken: null }));
    current = run('RUNNING', { A: required(layersOf(attackScene).A) }, 'adm-a.DAWN.4831.NONE.USUAL');
    expect(await within(lane('scene-attack', 'A')).findByText('Passed · 4,831 documents left')).toBeInTheDocument();
    expect(within(lane('scene-attack', 'B')).getByText('Sending…')).toBeInTheDocument();
    expect(within(lane('scene-attack', 'D')).getByText('Waiting')).toBeInTheDocument();

    complete(attackScene);
    expect(await screen.findByText('All answers are in · a real run')).toBeInTheDocument();
    expect(screen.getByText('The right answer: this is an attack, so stop it')).toBeInTheDocument();
    expect(screen.getByText('2 of five got it right')).toBeInTheDocument();
    expect(screen.getByText('Contexa let it through. The data left.')).toBeInTheDocument();
    expect(within(lane('scene-attack', 'C1')).getByText('Right')).toBeInTheDocument();
    expect(within(lane('scene-attack', 'D')).getByText('Wrong')).toBeInTheDocument();
    expect(within(lane('scene-attack', 'C1')).getByText('HTTP 403 · 12 ms')).toBeInTheDocument();

    const contexa = lane('scene-attack', 'D');
    expect(await within(contexa).findByText('Permitted · short usual pattern · no concrete risk')).toBeInTheDocument();
    await userEvent.click(within(contexa).getByRole('button', { name: /Reasoning in detail/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('3522bb83-0f99-481d-9466-f1249f5094df')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scene 2: what if it is the real owner?' })).toBeInTheDocument();
  });

  it('shows a stored real run, said to be a record, when a live run cannot start', async () => {
    await i18n.changeLanguage('en');
    routes['POST /api/live/combinations'] = () => ({
      status: 429,
      body: {
        reason: 'VISITOR_LIMIT',
        fallback: {
          key: 'adm-a.DAWN.4831.NONE.USUAL',
          recorded: true,
          recordedAt: '2026-10-05T03:00:00Z',
          runId: 'run-0',
          result: attackScene,
        },
      },
    });
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Send the request to export 4,831' }));

    expect(
      await screen.findByText("You have used today's runs. Here is a real run record of the same conditions instead."),
    ).toBeInTheDocument();
    expect(screen.getByText(/Another visitor's real run/)).toBeInTheDocument();
    expect(within(lane('scene-attack', 'D')).getByText('Wrong')).toBeInTheDocument();
  });

  it('lets the attacker give up when Contexa asks for an identity check', async () => {
    await i18n.changeLanguage('en');
    routes['POST /api/live/runs/current/abandon'] = () => ({ status: 200, body: current });
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Send the request to export 4,831' }));
    current = {
      ...run('CHALLENGE', { ...layersOf(attackScene), D: { outcome: 'HELD', httpStatus: 401, deliveredItems: 0, elapsedMs: 1900 } }, 'adm-a.DAWN.4831.NONE.USUAL'),
      challenge: {
        stage: 'WAITING',
        code: null,
        secondsLeft: 120,
        attempts: 0,
        error: null,
        cause: null,
        codeRequestedMs: null,
        verifiedMs: null,
        reissueSentMs: null,
        reissueDoneMs: null,
        reissueStatus: null,
        reissueOutcome: null,
      },
    };

    expect(await within(lane('scene-attack', 'D')).findByText('Held · identity check required')).toBeInTheDocument();
    expect(screen.getByText(/which you as the attacker do not have/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Give up and see the result' }));
    expect(calls.some((call) => call.url === '/api/live/runs/current/abandon')).toBe(true);
  });

  it('runs the real owner, compares both scenes and sends again under a changed condition', async () => {
    await i18n.changeLanguage('en');
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Send the request to export 4,831' }));
    complete(attackScene);
    await userEvent.click(await screen.findByRole('button', { name: 'Scene 2: what if it is the real owner?' }));

    const owner = required(document.querySelector<HTMLElement>('section[aria-labelledby="scene-owner"]'));
    expect(within(owner).getByText('GB-500 recovery ticket · open')).toBeInTheDocument();
    expect(within(owner).getByText('Differs from scene 1')).toBeInTheDocument();
    await userEvent.click(within(owner).getByRole('button', { name: 'Send the request to export 4,831' }));
    expect(calls.filter((call) => call.url === '/api/live/combinations').at(-1)?.init?.body).toBe(
      JSON.stringify({ key: 'adm-a.DAWN.4831.MATCH.USUAL', turnstileToken: null }),
    );
    complete(ownerScene);
    expect(await within(owner).findByText('The right answer: this is legitimate work, so let it pass')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Compare the two scenes' }));
    expect(await screen.findByText('Got both right: Business record rule')).toBeInTheDocument();
    const row = required(document.querySelector<HTMLElement>('tr[data-control="C2"]'));
    expect(row).toHaveAttribute('data-both', 'true');

    const free = required(document.querySelector<HTMLElement>('section[aria-labelledby="scene-free"]'));
    await userEvent.click(within(free).getByRole('button', { name: '2:20 pm' }));
    await userEvent.click(within(free).getByRole('button', { name: 'Send the request to export 4,831' }));
    expect(calls.filter((call) => call.url === '/api/live/combinations').at(-1)?.init?.body).toBe(
      JSON.stringify({ key: 'adm-a.AFTERNOON.4831.MATCH.USUAL', turnstileToken: null }),
    );
    expect(within(free).getByText('Changed: Company time 3:17 am, dawn → 2:20 pm')).toBeInTheDocument();
    complete(attackScene);
    expect(await within(free).findByText('1 results changed from the previous send.')).toBeInTheDocument();
    expect(within(lane('scene-free', 'C2')).getByText('Changed · before: Passed · data left')).toBeInTheDocument();
  });
});
