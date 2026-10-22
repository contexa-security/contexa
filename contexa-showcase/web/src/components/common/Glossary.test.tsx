import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';
import i18n from '../../i18n';
import en from '../../i18n/en.json';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { GlossaryModal, Term, TermScope } from './Glossary';
import { GLOSSARY, GLOSSARY_GROUPS, glossaryKey, type GlossaryTerm } from './glossaryTerms';

const KO: Readonly<Record<string, string>> = ko;
const EN: Readonly<Record<string, string>> = en;

function word(key: string, dictionary: Readonly<Record<string, string>> = KO): string {
  return required(dictionary[key], key);
}

/** The old terms of the redesign's word tables (화면재편-기획안 11절, the 'now' column) and the unit words. */
const BANNED = [
  '계정을 훔친 사람',
  '진짜 직원',
  '본인 확인',
  '규칙 조여 보기',
  '정상 업무 막음',
  '업무를 막음',
  '평소 모습',
  '시간·건수 제한',
  '웹 방화벽',
  '로그인·권한 확인',
  '결재·담당 확인',
  '판정 자세히 보기',
  '응답 전에 막기',
  '다음 요청부터 막기',
  '내보내기',
  '보류(관리자 검토)',
  '출처 문장',
];

function Where() {
  const location = useLocation();
  return <output data-testid="where">{`${location.pathname}${location.search}`}</output>;
}

function at(path: string, element: ReactNode) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={element} />
      </Routes>
      <Where />
    </MemoryRouter>,
  );
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

/** The glossary (화면재편-기획안 11절, 구현계획 RO-6): the word tables' terms, in their groups, opened from the menu. */
describe('the glossary', () => {
  it('underlines a term only the first time on a screen and leads to its entry in the glossary', async () => {
    at(
      '/lab',
      <TermScope>
        <p>
          <Term term="permission">권한</Term>이 같으면 <Term term="permission">권한</Term>만으로는 모릅니다
        </p>
        <GlossaryModal />
      </TermScope>,
    );
    expect(screen.getAllByRole('button', { name: '권한' })).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: '권한' }));
    expect(screen.getByRole('tooltip')).toHaveTextContent(word(glossaryKey('permission', 'plain')));
    await userEvent.click(screen.getByRole('button', { name: word('glossary.more') }));
    expect(screen.getByTestId('where')).toHaveTextContent('modal=glossary&term=permission');
    expect(screen.getByRole('heading', { name: word('glossary.title') })).toBeInTheDocument();
    const entry = required(
      screen.getByText(word(glossaryKey('permission', 'term')), { selector: 'dt' }).parentElement,
      'the entry',
    );
    expect(entry).toHaveAttribute('data-focus');
  });

  it('lists every term in the groups and order of the word tables, each with its plain meaning', () => {
    at('/?modal=glossary', <GlossaryModal />);
    const groups = screen.getAllByRole('heading', { level: 3 }).map((heading) => heading.textContent);
    expect(groups).toEqual(GLOSSARY_GROUPS.map((group) => word(`space.r7.glossary.group.${group.id}`)));
    for (const group of GLOSSARY_GROUPS) {
      const section = required(
        screen
          .getByRole('heading', { level: 3, name: word(`space.r7.glossary.group.${group.id}`) })
          .closest('section'),
        group.id,
      );
      expect(
        within(section)
          .getAllByRole('term')
          .map((term) => term.textContent),
      ).toEqual(group.terms.map((term) => word(glossaryKey(term, 'term'))));
    }
    expect(screen.getAllByRole('term')).toHaveLength(GLOSSARY.length);
  });

  it("quotes the field's own names as the word tables write them, each marked as an original", () => {
    // The field's own name of each term, as the term table keeps it beside the term (설계서 43~45장).
    const industry: Readonly<Partial<Record<GlossaryTerm, string>>> = {
      waf: 'WAF',
      access: '접근 제어',
      limits: '임계값 규칙',
      approval: '맥락 기반 규칙',
      contexa: 'AI 보안 판단',
      session: '세션',
      identityCheck: 'MFA',
      hold: '에스컬레이션',
      expected: '기대 결과',
      rightStop: '탐지',
      missed: '미탐',
      falseBlock: '오탐',
      partly: '부분 차단',
      noDecision: '기술 오류',
      sync: '동기 판정',
      async: '비동기 판정',
      workRecord: '업무 맥락',
      workScope: '업무 프로필',
      hardLimit: '하드 제약',
      rules: '시스템 프롬프트',
      prompt: 'LLM 입력',
      original: '원문 로그',
      interval: '신뢰 구간',
      injection: '프롬프트 주입',
      judgment: '판정',
      pass: 'ALLOW',
      block: '차단',
      usual: '행동 기준선',
      learned: '관측 수',
      reason: '판정 근거',
    };
    at('/?modal=glossary', <GlossaryModal />);
    for (const [term, name] of Object.entries(industry) as [GlossaryTerm, string][]) {
      expect(word(glossaryKey(term, 'industry')), term).toBe(name);
      const entry = required(
        screen.getByText(word(glossaryKey(term, 'term')), { selector: 'dt' }).parentElement,
        term,
      );
      const original = required(entry.querySelector('[data-original]'), `${term} original`);
      expect(original).toHaveTextContent(name);
      expect(original.parentElement).toHaveTextContent(
        i18n.t('space.r7.glossary.industry', { name }).replace(/<\/?original>/g, ''),
      );
    }
    // Outside the originals the window shows no old term (the check of RC-2 reads it the same way).
    const dialog = required(document.querySelector('dialog[open]'), 'the glossary window').cloneNode(
      true,
    ) as HTMLElement;
    dialog.querySelectorAll('[data-original]').forEach((element) => element.remove());
    for (const banned of BANNED) {
      expect(dialog.textContent, banned).not.toContain(banned);
    }
  });

  it('names each thing as the main flow does: one name per thing (최종화면-구현계획 F0-5)', () => {
    const same: readonly (readonly [Parameters<typeof glossaryKey>[0], string])[] = [
      ['waf', 'main.lane.A'],
      ['access', 'main.lane.B'],
      ['limits', 'main.lane.C1'],
      ['approval', 'main.lane.C2'],
      ['contexa', 'main.lane.D'],
      ['pass', 'main.verdict.ALLOW'],
      ['identityCheck', 'main.verdict.CHALLENGE'],
      ['hold', 'main.verdict.ESCALATE'],
      ['block', 'main.verdict.BLOCK'],
      ['noDecision', 'main.verdict.failed'],
      ['missed', 'main.result.MISSED'],
      ['falseBlock', 'main.result.HALTED'],
      ['partly', 'main.result.PARTLY_STOPPED'],
    ];
    for (const dictionary of [KO, EN]) {
      for (const [term, key] of same) {
        expect(word(glossaryKey(term, 'term'), dictionary), term).toBe(word(key, dictionary));
      }
    }
  });

  it('holds both languages for every term and no old term in the Korean words', () => {
    for (const term of GLOSSARY) {
      for (const part of ['term', 'plain'] as const) {
        const korean = word(glossaryKey(term, part));
        expect(word(glossaryKey(term, part), EN), `${term} ${part}`).not.toMatch(/[가-힣]/);
        for (const banned of BANNED) {
          expect(korean, `${term} ${part}`).not.toContain(banned);
        }
      }
      expect(glossaryKey(term, 'industry') in KO).toBe(glossaryKey(term, 'industry') in EN);
    }
  });

  it('finds a term by its name, its meaning or its field name, and says when nothing matches', async () => {
    at('/?modal=glossary', <GlossaryModal />);
    const search = screen.getByLabelText(word('glossary.search'));
    await userEvent.type(search, word(glossaryKey('limits', 'industry')));
    expect(screen.getAllByRole('term').map((term) => term.textContent)).toEqual([
      word(glossaryKey('limits', 'term')),
    ]);
    await userEvent.clear(search);
    await userEvent.type(search, '없는 낱말 zzz');
    expect(screen.queryAllByRole('term')).toHaveLength(0);
    expect(screen.getByText(word('glossary.empty'))).toBeInTheDocument();
  });
});
