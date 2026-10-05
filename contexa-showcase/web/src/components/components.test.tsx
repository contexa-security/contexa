import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import '../i18n';
import i18n from '../i18n';
import { EvidenceDrawer } from './EvidenceDrawer';
import { LayerCard } from './LayerCard';
import { StateScreen } from './StateScreen';
import { StreamMeter } from './StreamMeter';
import { VerdictChip } from './VerdictChip';

describe('VerdictChip', () => {
  it('shows the plain word and, on request, the standard code', async () => {
    await i18n.changeLanguage('ko');
    render(<VerdictChip verdict="BLOCK" showCode />);
    expect(screen.getByText('차단')).toBeInTheDocument();
    expect(screen.getByText('BLOCK')).toBeInTheDocument();
  });

  it('never relies on color alone: the word is present for every verdict', async () => {
    await i18n.changeLanguage('en');
    for (const [verdict, word] of [
      ['ALLOW', 'Allowed'],
      ['CHALLENGE', 'Verify'],
      ['ESCALATE', 'Under review'],
      ['BLOCK', 'Blocked'],
    ] as const) {
      const { unmount } = render(<VerdictChip verdict={verdict} />);
      expect(screen.getByText(word)).toBeInTheDocument();
      unmount();
    }
  });
});

describe('LayerCard', () => {
  it('shows the business outcome first and opens the evidence of its control', async () => {
    await i18n.changeLanguage('en');
    const onOpen = vi.fn();
    render(<LayerCard control="D" outcome="STOPPED" verdict="BLOCK" reason="Not assigned" highlighted onOpenEvidence={onOpen} />);
    expect(screen.getByRole('heading', { name: 'Contexa' })).toBeInTheDocument();
    expect(screen.getByText('Data stopped')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Evidence chain/ }));
    expect(onOpen).toHaveBeenCalledWith('D');
  });
});

describe('EvidenceDrawer', () => {
  it('lists the four linked records with the business outcome marked as the primary criterion', async () => {
    await i18n.changeLanguage('en');
    render(
      <EvidenceDrawer
        title="Contexa"
        evidence={{ decisionId: 'd-1', verdict: 'BLOCK', timing: 'Before response', httpStatus: 403, outcome: 'Data stopped' }}
        onClose={() => undefined}
      />,
    );
    expect(screen.getByText('Engine decision')).toBeInTheDocument();
    expect(screen.getByText('Enforcement timing')).toBeInTheDocument();
    expect(screen.getByText('HTTP response')).toBeInTheDocument();
    expect(screen.getByText('Primary criterion')).toBeInTheDocument();
    expect(screen.getByText('403')).toBeInTheDocument();
  });
});

describe('StateScreen', () => {
  it('offers only the actions the caller can really perform, and the first screen when there are none', async () => {
    await i18n.changeLanguage('en');
    const { unmount } = render(
      <MemoryRouter>
        <StateScreen kind="dailyLimit" recordTo="/replay/A3" />
      </MemoryRouter>,
    );
    expect(screen.getByRole('alert')).toHaveTextContent("You have used all of today's live runs.");
    expect(screen.getByRole('link', { name: 'See the stored real run' })).toHaveAttribute('href', '/replay/A3');
    expect(screen.queryByRole('button', { name: 'Sign in for more runs' })).not.toBeInTheDocument();
    unmount();

    render(
      <MemoryRouter>
        <StateScreen kind="challengeExpired" />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the start' })).toBeInTheDocument();
  });

  it('keeps the cause of a failed recovery one step away and runs the reset', async () => {
    await i18n.changeLanguage('ko');
    const onRetry = vi.fn();
    render(
      <MemoryRouter>
        <StateScreen kind="recoveryFailed" onRetry={onRetry} cause="재발행 시간 초과" />
      </MemoryRouter>,
    );
    expect(screen.getByText('업무를 이어가지 못했습니다.')).toBeInTheDocument();
    expect(screen.getByText('원인 보기')).toBeInTheDocument();
    expect(screen.getByText('재발행 시간 초과')).not.toBeVisible();
    await userEvent.click(screen.getByText('원인 보기'));
    expect(screen.getByText('재발행 시간 초과')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: '초기화 뒤 다시 시도' }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('tells waiting for the decision apart from a temporary fault', async () => {
    await i18n.changeLanguage('en');
    const { unmount } = render(
      <MemoryRouter>
        <StateScreen kind="waiting" remainingSeconds={12} recordTo="/replay/A3" />
      </MemoryRouter>,
    );
    expect(screen.getByRole('status')).toHaveTextContent('Waiting for the decision');
    expect(screen.getByText('About 12 s left')).toBeInTheDocument();
    unmount();
    render(
      <MemoryRouter>
        <StateScreen kind="outage" recordTo="/replay/A3" onRetry={() => undefined} />
      </MemoryRouter>,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('A temporary fault kept the decision from arriving');
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

describe('StreamMeter', () => {
  const cut = {
    total: 4831,
    delivered: 412,
    firstLineMs: 38,
    endMs: 2610,
    cut: true,
    interrupted: false,
    samples: [
      [38, 1],
      [140, 17],
      [2610, 412],
    ] as const,
  };

  it('shows what left before the cut, in items and seconds', async () => {
    await i18n.changeLanguage('en');
    render(<StreamMeter stream={cut} />);
    expect(screen.getByTestId('stream-count')).toHaveTextContent('412 / 4,831 items');
    expect(screen.getByText('Transfer cut')).toBeInTheDocument();
    expect(screen.getByText('412 items left before the block · 2.6 s')).toBeInTheDocument();
    expect(screen.getByRole('progressbar', { name: 'Items transferred' })).toHaveAttribute('aria-valuenow', '412');
  });

  it('never calls a broken connection a block', async () => {
    await i18n.changeLanguage('ko');
    render(<StreamMeter stream={{ ...cut, cut: false, interrupted: true }} />);
    expect(screen.getByText('전송 끊김')).toBeInTheDocument();
    expect(screen.queryByText('전송 중단')).not.toBeInTheDocument();
    expect(screen.getByText(/엔진의 차단 표시가 없어 차단으로 보지 않습니다/)).toBeInTheDocument();
  });

  it('replays the recorded pace and stops at the recorded count', async () => {
    await i18n.changeLanguage('en');
    vi.useFakeTimers();
    try {
      render(<StreamMeter stream={cut} play />);
      expect(screen.getByTestId('stream-count')).toHaveTextContent('1 / 4,831 items');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(200);
      });
      expect(screen.getByTestId('stream-count')).toHaveTextContent('17 / 4,831 items');
      expect(screen.getByText('Transferring')).toBeInTheDocument();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
      expect(screen.getByTestId('stream-count')).toHaveTextContent('412 / 4,831 items');
      expect(screen.getByText('412 items left before the block · 2.6 s')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
