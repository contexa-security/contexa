import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { subjectOfSender } from '../../domain/subject';
import i18n from '../../i18n';
import { SubjectChip } from './SubjectChip';

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

describe('the subject chip (AS-1)', () => {
  it('names each kind of sender in words and carries an icon of its own, never color alone', () => {
    const words = new Map<string, string>();
    const icons = new Map<string, string>();
    for (const [subject, word] of [
      ['person', '사람'],
      ['delegated', '위임 에이전트'],
      ['autonomous', '단독 에이전트'],
      ['session', '세션 에이전트'],
    ] as const) {
      const { container, unmount } = render(<SubjectChip subject={subject} />);
      expect(screen.getByText(word)).toBeInTheDocument();
      const icon = container.querySelector('svg path')?.getAttribute('d') ?? '';
      expect(icon, subject).not.toBe('');
      words.set(subject, word);
      icons.set(subject, icon);
      unmount();
    }
    expect(new Set(words.values()).size).toBe(4);
    expect(new Set(icons.values()).size, 'four different icons').toBe(4);
  });

  it('gives a screen reader the sender in one phrase and is a plain text tag (not a button or link)', () => {
    render(<SubjectChip subject="delegated" />);
    const chip = screen.getByLabelText('보내는 쪽: 위임 에이전트');
    expect(chip).toBeInTheDocument();
    expect(chip.tagName).toBe('SPAN');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('speaks English when the language is English', async () => {
    await i18n.changeLanguage('en');
    render(<SubjectChip subject="autonomous" />);
    expect(screen.getByText('Autonomous agent')).toBeInTheDocument();
    expect(screen.getByLabelText('Sender: Autonomous agent')).toBeInTheDocument();
  });

  it('is told apart from the result chip by its shape: an outlined tag, not a filled pill', () => {
    const { container } = render(<SubjectChip subject="person" />);
    expect(container.firstElementChild).toHaveAttribute('data-shape', 'tag');
  });
});

describe('the subject of a sender (AS-1)', () => {
  it('reads the portal sender as the four kinds the screens show', () => {
    expect(subjectOfSender('PERSON')).toBe('person');
    expect(subjectOfSender('DELEGATED_AGENT')).toBe('delegated');
    expect(subjectOfSender('DELEGATED_RELAY')).toBe('delegated');
    expect(subjectOfSender('AUTONOMOUS_AGENT')).toBe('autonomous');
    expect(subjectOfSender('INTERNAL_CLIENT')).toBe('autonomous');
    expect(subjectOfSender('AGENT_SESSION')).toBe('session');
  });

  it('takes a case without a sender as a person, and shows no chip for a sender it does not know', () => {
    expect(subjectOfSender(null)).toBe('person');
    expect(subjectOfSender(undefined)).toBe('person');
    // a new kind of sender is not told as a person by a guess: no chip until the screens know the kind
    expect(subjectOfSender('SOMETHING_NEW')).toBeNull();
  });
});
