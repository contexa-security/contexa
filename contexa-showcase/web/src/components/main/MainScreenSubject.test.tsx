import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Subject } from '../../domain/subject';
import i18n from '../../i18n';
import { MainScreen } from './MainScreen';

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 404 })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function screenAt(path: string, subject?: Subject) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="*"
            element={
              <MainScreen title="제목" intro="안내" {...(subject ? { subject } : {})}>
                <p>핵심</p>
              </MainScreen>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('the frame tells who sends the requests (AS-1)', () => {
  it('draws the subject chip on the place label line when the screen names a subject', () => {
    const { container } = screenAt('/agent/console', 'delegated');
    const chip = screen.getByLabelText('보내는 쪽: 위임 에이전트');
    expect(chip).toBeInTheDocument();
    const place = container.querySelector('[data-place]');
    expect(place, 'the place line').not.toBeNull();
    expect(place?.contains(chip), 'the chip sits on the same line as the place label').toBe(true);
  });

  it('names a person on the screens of the people track by itself, and nothing on the others', () => {
    for (const path of ['/attack/request', '/attack/console', '/attack/result', '/normal/diff', '/insider/reason']) {
      const { unmount } = screenAt(path);
      expect(screen.getByLabelText('보내는 쪽: 사람'), path).toBeInTheDocument();
      unmount();
    }
    for (const path of ['/', '/intro/map', '/evidence/map', '/compare/rule', '/summary']) {
      const { unmount } = screenAt(path);
      expect(screen.queryByLabelText(/보내는 쪽/), path).not.toBeInTheDocument();
      unmount();
    }
  });

  it('lets a screen name its own subject over the default', () => {
    screenAt('/attack/console', 'autonomous');
    expect(screen.getByLabelText('보내는 쪽: 단독 에이전트')).toBeInTheDocument();
    expect(screen.queryByLabelText('보내는 쪽: 사람')).not.toBeInTheDocument();
  });

  it('draws no chip on a screen that names no subject', () => {
    screenAt('/agent/console');
    expect(screen.queryByLabelText(/보내는 쪽/)).not.toBeInTheDocument();
  });

  it('keeps the headline zone as it was: the chip is outside the title block', () => {
    const { container } = screenAt('/attack/console', 'person');
    const title = container.querySelector('[data-zone="title"]');
    expect(title?.querySelector('[data-subject]')).toBeNull();
    expect(container.querySelector('[data-subject="person"]')).not.toBeNull();
  });
});
