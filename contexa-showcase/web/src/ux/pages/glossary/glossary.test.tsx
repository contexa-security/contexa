import { fireEvent, screen, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import en from '../../../i18n/en.json';
import i18n from '../../../i18n';
import ko from '../../../i18n/ko.json';
import { GLOSSARY, OLD_GLOSSARY_TERMS } from '../../glossary/terms';
import { oldGlossaryTarget } from '../../routes';
import { renderAt, stubPortal } from '../../test/portal';
import GlossaryPage from './GlossaryPage';

const KO = ko as Record<string, string>;
const EN = en as Record<string, string>;
const TERMS = GLOSSARY.flatMap((group) => group.terms);

function open(address: string) {
  stubPortal({ get: {} });
  return renderAt(
    address,
    <Routes>
      <Route path="/glossary" element={<GlossaryPage />} />
    </Routes>,
  );
}

/** A page as wide as a phone: every media query of the drawer width matches. */
function narrow() {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query.includes('width < 1024px'),
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the security glossary', () => {
  it('holds the 62 terms of 기획안 9절 and 9 of the old glossary, each named and defined in both languages (DEC-69)', () => {
    expect(TERMS).toHaveLength(71);
    expect(new Set(TERMS.map((term) => term.id)).size).toBe(71);
    for (const term of TERMS) {
      for (const part of ['name', 'def']) {
        expect(KO[`ux.glossary.term.${term.id}.${part}`], `${term.id} ${part}`).toBeTruthy();
        expect(EN[`ux.glossary.term.${term.id}.${part}`], `${term.id} ${part}`).toBeTruthy();
      }
      expect(EN[`ux.glossary.term.${term.id}.name`], term.id).toBe(term.en);
    }
    expect(KO['ux.glossary.term.holdForReview.def']).toBe('응답 전에 멈추고 검토로 넘김(HTTP 423)');
    expect(KO['ux.glossary.term.existingControls.short']).toBe('기존 통제');
  });

  it('lists every term under its group, the official English name beside the Korean one', async () => {
    open('/glossary');
    expect(await screen.findByText('용어 71개')).toBeInTheDocument();
    const groups = screen.getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent);
    expect(groups).toEqual(['판정과 적용', '보안 통제', '판정 근거', '위협과 주체', '시나리오와 측정', '화면과 메뉴']);
    const controls = screen.getByRole('region', { name: '보안 통제' });
    expect(within(controls).getAllByRole('link')).toHaveLength(6);
    expect(within(controls).getByRole('link', { name: '웹 방화벽(WAF) Web application firewall (WAF)' })).toBeInTheDocument();
    expect(screen.getByText('목록에서 용어를 고르면 정의가 여기에 나옵니다.')).toBeInTheDocument();
  });

  it('finds a term by its Korean or English name or its definition, and says when nothing matches (ST-86)', async () => {
    open('/glossary');
    const box = await screen.findByRole('searchbox', { name: '용어 검색' });
    fireEvent.change(box, { target: { value: 'baseline' } });
    expect(screen.getByRole('link', { name: /^행위 기준선/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /^기준선 이탈/ })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^허용/ })).not.toBeInTheDocument();
    fireEvent.change(box, { target: { value: 'HTTP 423' } });
    expect(screen.getByText('검색 결과 1개')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /^검토 보류/ })).toBeInTheDocument();
    fireEvent.change(box, { target: { value: '없는 말' } });
    expect(screen.getByText('맞는 용어가 없습니다.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '검색 지우기' }));
    expect(screen.getByText('용어 71개')).toBeInTheDocument();
  });

  it('opens a chosen term on the right with its screen, and a term it does not know as no choice (ST-85)', async () => {
    const first = open('/glossary?term=baseline');
    const panel = await screen.findByRole('complementary', { name: '행위 기준선' });
    expect(panel).toHaveTextContent('주체의 학습된 정상 행위 범위');
    expect(panel).toHaveTextContent('Behavioral baseline');
    expect(panel).toHaveTextContent('판정 근거');
    expect(within(panel).getByRole('link', { name: '이 화면 열기' })).toHaveAttribute('href', '/engine?tab=baseline');
    expect(screen.getByRole('link', { name: /^행위 기준선/ })).toHaveAttribute('aria-current', 'true');
    first.unmount();
    vi.unstubAllGlobals();
    open('/glossary?term=nothing');
    expect(await screen.findByText('목록에서 용어를 고르면 정의가 여기에 나옵니다.')).toBeInTheDocument();
  });

  it('opens the chosen term in a drawer under 1024', async () => {
    narrow();
    open('/glossary?term=existingControls');
    const drawer = await screen.findByRole('dialog', { name: '기존 보안 통제' });
    expect(drawer).toHaveTextContent('웹 방화벽 · 인증 · 권한 · 임계값 규칙 · 승인 정책 규칙');
    expect(drawer).toHaveTextContent('기존 통제');
  });

  it('leads an old glossary link to the term of the same meaning, or to the glossary (ST-87)', () => {
    expect(oldGlossaryTarget('?modal=glossary&term=usual')).toBe('/glossary?term=baseline');
    expect(oldGlossaryTarget('?modal=glossary&term=hold')).toBe('/glossary?term=holdForReview');
    expect(oldGlossaryTarget('?modal=glossary&term=partly')).toBe('/glossary');
    expect(oldGlossaryTarget('?modal=detail&detailRun=run-1')).toBeNull();
    const ids = new Set(TERMS.map((term) => term.id));
    for (const target of Object.values(OLD_GLOSSARY_TERMS)) {
      expect(ids.has(target), target).toBe(true);
    }
  });
});
