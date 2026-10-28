import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { SnapshotBadge } from './SnapshotBadge';

const SNAPSHOT = {
  label: 'T5-confirm-approve',
  runId: 'run-d2ca817d4929',
  caseKey: 'T5',
  kind: 'DELEGATED',
  why: 'main case',
  capturedAt: '2026-10-24T14:07:35Z',
};

beforeEach(async () => {
  await i18n.changeLanguage('ko');
  vi.useFakeTimers({ toFake: ['Date'] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the badge of a stored real run (AC-5, D-7)', () => {
  it('says how long ago the run was made for real, the day it was recorded, and that no model is called', () => {
    vi.setSystemTime(Date.parse('2026-10-27T14:07:35Z'));
    render(
      <MemoryRouter>
        <SnapshotBadge snapshot={SNAPSHOT} />
      </MemoryRouter>,
    );

    expect(screen.getByText('3일 전 실제 실행 · 저장된 기록 2026-10-24 · 새 모델 호출 없음')).toBeInTheDocument();
  });

  it('counts hours below two days', () => {
    vi.setSystemTime(Date.parse('2026-10-24T19:07:35Z'));
    render(
      <MemoryRouter>
        <SnapshotBadge snapshot={SNAPSHOT} />
      </MemoryRouter>,
    );

    expect(screen.getByText(/^5시간 전 실제 실행/)).toBeInTheDocument();
  });

  it('is told in English too', async () => {
    await i18n.changeLanguage('en');
    vi.setSystemTime(Date.parse('2026-10-27T14:07:35Z'));
    render(
      <MemoryRouter>
        <SnapshotBadge snapshot={SNAPSHOT} />
      </MemoryRouter>,
    );

    expect(screen.getByText('A real run 3 days ago · stored record of 2026-10-24 · no new model call')).toBeInTheDocument();
  });
});
