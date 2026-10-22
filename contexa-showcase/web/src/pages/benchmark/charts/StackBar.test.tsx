import { render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import i18n from '../../../i18n';
import { StackBar, type StackRow } from './StackBar';

/** Contexa's attack runs by how they ended, as the portal counts them (one bar). */
const ONE: readonly StackRow[] = [
  {
    key: 'D',
    label: 'Contexa',
    segments: [
      { key: 'BEFORE_RESPONSE', label: '응답 전에 판단해 막음', count: 30, tone: 'safe' },
      { key: 'NEXT_REQUEST', label: '다음 요청부터 막음', count: 40, tone: 'partial' },
      { key: 'JUDGED_ALLOW', label: '허용으로 판단해 놓침', count: 4, tone: 'loss' },
      { key: 'OTHER', label: '그 밖', count: 0, tone: 'neutral' },
    ],
  },
];

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

describe('the 100% bar', () => {
  it('grows each segment by its count, marks the wide ones inside and leaves an empty kind out of the bar', () => {
    const { container } = render(<StackBar rows={ONE} summary="공격 74회가 끝난 모양" rowHead="방식" />);
    expect(screen.getByRole('img', { name: '공격 74회가 끝난 모양' })).toBeInTheDocument();
    const segments = container.querySelectorAll<HTMLElement>('[role="img"] [data-kind]');
    expect([...segments].map((segment) => segment.dataset.kind)).toEqual([
      'BEFORE_RESPONSE',
      'NEXT_REQUEST',
      'JUDGED_ALLOW',
    ]);
    expect(segments.item(0).style.flexGrow).toBe('30');
    expect(segments.item(0)).toHaveTextContent('● 30');
    expect(segments.item(2)).toHaveTextContent('');
  });

  it('names every kind with its mark and count in the legend, and holds every count in the table', () => {
    const { container } = render(<StackBar rows={ONE} summary="공격 74회가 끝난 모양" rowHead="방식" />);
    const legend = container.querySelector('ul') as HTMLElement;
    expect(within(legend).getByText('허용으로 판단해 놓침')).toBeInTheDocument();
    expect(legend).toHaveTextContent('✕허용으로 판단해 놓침4회');
    expect(legend).toHaveTextContent('▪그 밖0회');
    const row = screen.getByRole('row', { name: /Contexa/ });
    expect(row).toHaveTextContent('Contexa3040' + '4' + '0');
  });
});
