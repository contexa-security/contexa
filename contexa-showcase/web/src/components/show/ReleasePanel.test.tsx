import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import '../../i18n';
import i18n from '../../i18n';
import type { LiveRelease } from '../../api/types';
import { ReleasePanel } from './ReleasePanel';

const base: LiveRelease = {
  stage: 'BLOCKED',
  code: null,
  secondsLeft: 118,
  attempts: 0,
  error: null,
  cause: null,
  reason: null,
  block: null,
  approverName: null,
  codeRequestedMs: null,
  verifiedMs: null,
  requestedMs: null,
  approvedMs: null,
  reissueSentMs: null,
  reissueDoneMs: null,
  reissueStatus: null,
  reissueOutcome: null,
  reissueDeliveredItems: null,
};

function panel(release: LiveRelease) {
  const handlers = { onStart: vi.fn(), onAnswer: vi.fn(), onRequest: vi.fn(), onApprove: vi.fn() };
  render(<ReleasePanel release={release} defaultReason="Approved transfer" {...handlers} />);
  return handlers;
}

describe('ReleasePanel', () => {
  it('walks the real employee from the block to the request, each step on its own press', async () => {
    await i18n.changeLanguage('ko');
    const blocked = panel(base);
    await userEvent.click(screen.getByRole('button', { name: '본인 확인하고 해제 요청하기' }));
    expect(blocked.onStart).toHaveBeenCalledOnce();
  });

  it('offers the code from the demo inbox and then files the reason the visitor may edit', async () => {
    await i18n.changeLanguage('ko');
    const shown = panel({ ...base, stage: 'CODE_SHOWN', code: 'ott-123' });
    expect(screen.getByTestId('release-code')).toHaveTextContent('ott-123');
    await userEvent.click(screen.getByRole('button', { name: '이 코드로 확인' }));
    expect(shown.onAnswer).toHaveBeenCalledWith('ott-123');
  });

  it('sends the edited reason, and nothing while it is empty', async () => {
    await i18n.changeLanguage('ko');
    const verified = panel({ ...base, stage: 'VERIFIED' });
    const reason = screen.getByLabelText('해제 요청 사유');
    expect(reason).toHaveValue('Approved transfer');
    await userEvent.clear(reason);
    expect(screen.getByRole('button', { name: '해제 요청 보내기' })).toBeDisabled();
    await userEvent.type(reason, 'GB-500 transfer approved by pm-11');
    await userEvent.click(screen.getByRole('button', { name: '해제 요청 보내기' }));
    expect(verified.onRequest).toHaveBeenCalledWith('GB-500 transfer approved by pm-11');
  });

  it('shows the administrator what the engine recorded, untranslated, before the approval', async () => {
    await i18n.changeLanguage('ko');
    const requested = panel({
      ...base,
      stage: 'REQUESTED',
      reason: 'GB-500 transfer approved by pm-11',
      approverName: 'Administrator B',
      block: {
        id: 41,
        username: 'v0123456789ab-adm-a',
        status: 'UNBLOCK_REQUESTED',
        reasoning: 'Bulk export of a restricted project at 03:17',
        blockedAt: '2026-10-06T03:17:02',
        unblockReason: 'GB-500 transfer approved by pm-11',
        mfaVerified: true,
        unblockRequestedAt: '2026-10-06T03:18:00',
      },
    });
    expect(screen.getByText('보안 담당자 화면 · Administrator B')).toBeInTheDocument();
    expect(screen.getByText('엔진 원문')).toBeInTheDocument();
    expect(
      screen.getByText('v0123456789ab-adm-a'),
      'the account as the engine recorded it',
    ).toBeInTheDocument();
    expect(screen.getByText('Bulk export of a restricted project at 03:17')).toHaveAttribute('lang', 'en');
    expect(screen.getByText('완료')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '보안 담당자로 승인' }));
    expect(requested.onApprove).toHaveBeenCalledOnce();
  });
});
