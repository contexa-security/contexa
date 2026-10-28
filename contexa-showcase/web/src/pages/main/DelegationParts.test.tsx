import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it } from 'vitest';
import type { AgentDelegation, AgentRunStep } from '../../api/agentCase';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { requestOperation, requestTarget } from './agentGroup';
import { DelegationChain, DelegationCompare } from './DelegationParts';

const KO: Readonly<Record<string, string>> = ko;

function word(key: string): string {
  return required(KO[key], key);
}

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

const DELEGATION: AgentDelegation = {
  project: 'HX-310',
  purpose: 'REPORTING',
  summary: { ko: 'HX-310 주간 도면 변경 보고서 작성', en: 'Prepare the weekly HX-310 drawing change report' },
  operations: ['PROJECT_LIST', 'DOCUMENT_LIST', 'DOCUMENT_READ'],
  resources: ['HX-310'],
  validFromMinutes: -10080,
  validUntilMinutes: -120,
  status: 'ACTIVE',
  approvalRequired: false,
};

function step(tool: string, args: Record<string, unknown>, path: string): AgentRunStep {
  return {
    stepNo: 3,
    sentBy: 'AGENT_WORK',
    tool: { tool, arguments: args },
    path,
    companyTime: '2026-10-26T14:00:05Z',
    outcomes: {},
    decision: null,
  };
}

describe('the delegation chain (AS-4)', () => {
  it('reads who delegated, which agent works and on what, in that order', () => {
    render(
      <MemoryRouter>
        <DelegationChain delegator="엔지니어 K" agent="보고서 에이전트" target="HX-310" />
      </MemoryRouter>,
    );

    const chain = screen.getByRole('list', { name: word('main.agent.chain.label') });
    const nodes = within(chain).getAllByRole('listitem');
    expect(nodes.map((node) => node.textContent)).toEqual([
      `${word('main.agent.delegator')}엔지니어 K`,
      `${word('main.agent.agent')}보고서 에이전트`,
      `${word('main.agent.chain.target')}HX-310`,
    ]);
  });
});

describe('the request of an agent step, as the screens name it (AS-4)', () => {
  it('names the operation the tool sends', () => {
    expect(requestOperation(step('listDocuments', { projectKey: 'HX-310' }, '/api/projects/HX-310/documents'))).toBe(
      'DOCUMENT_LIST',
    );
    expect(requestOperation(step('exportDocuments', { projectKey: 'HX-310', items: 480 }, '/x'))).toBe('EXPORT');
    expect(requestOperation(step('somethingNew', {}, '/x'))).toBeNull();
    expect(requestOperation({ ...step('x', {}, '/x'), tool: null })).toBeNull();
  });

  it('names the resource the request asks for: the project, the document or the customer, else the address', () => {
    expect(requestTarget(step('listDocuments', { projectKey: 'HX-310' }, '/p'))).toBe('HX-310');
    expect(requestTarget(step('readDocument', { documentKey: 'DOC-7' }, '/d'))).toBe('DOC-7');
    expect(requestTarget(step('readCustomer', { customerKey: 'CUS-0001' }, '/c'))).toBe('CUS-0001');
    expect(requestTarget(step('listProjects', {}, '/api/projects'))).toBe('/api/projects');
  });
});

describe('the delegation and the request side by side (AS-4)', () => {
  it('puts the record and the request against each other row by row, from the same values the screens read', () => {
    render(
      <DelegationCompare
        delegation={DELEGATION}
        request={step('exportDocuments', { projectKey: 'HX-410', items: 480 }, '/api/projects/HX-410/export')}
        runCompanyTime="2026-10-26T14:00:00Z"
      />,
    );

    const compare = screen.getByRole('region', { name: word('main.agent.compare.title') });
    const rows = within(compare).getAllByRole('row');
    const text = rows.map((row) => row.textContent ?? '');
    expect(text[0]).toContain(word('main.agent.compare.record'));
    expect(text[0]).toContain(word('main.agent.compare.request'));
    expect(text.find((row) => row.startsWith(word('main.agent.compare.what')))).toContain(
      '프로젝트 목록 보기, 문서 목록 보기, 문서 열람',
    );
    expect(text.find((row) => row.startsWith(word('main.agent.compare.what')))).toContain('자료 내보내기');
    expect(text.find((row) => row.startsWith(word('main.agent.compare.target')))).toContain('HX-310');
    expect(text.find((row) => row.startsWith(word('main.agent.compare.target')))).toContain('HX-410');
    expect(text.find((row) => row.startsWith(word('main.agent.compare.when')))).toContain(
      '작업 시각 7일 전부터 2시간 전까지',
    );
    expect(within(compare).getByText('HX-310 주간 도면 변경 보고서 작성', { exact: false })).toBeInTheDocument();
  });

  /** AS-12: a delegation that states a quantity limit is set against the amount the request asks for. */
  it('sets the quantity limit the delegation states against the amount the request asks for', () => {
    render(
      <DelegationCompare
        delegation={{ ...DELEGATION, operations: ['EXPORT'], status: 'ACTIVE', validFromMinutes: -60, validUntilMinutes: 180, maxItemsPerRequest: 40 }}
        request={step('exportDocuments', { projectKey: 'HX-310', items: 400 }, '/api/projects/HX-310/exports?items=400')}
        runCompanyTime="2026-10-26T14:00:00Z"
      />,
    );

    const compare = screen.getByRole('region', { name: word('main.agent.compare.title') });
    const text = within(compare).getAllByRole('row').map((row) => row.textContent ?? '');
    const row = text.find((line) => line.startsWith(word('main.agent.compare.limit')));
    expect(row).toContain(word('main.agent.limit').replace('{{n}}', '40'));
    expect(row).toContain(word('main.agent.limit.asked').replace('{{n}}', '400'));
  });

  it('has no quantity row for a delegation that states no limit', () => {
    render(
      <DelegationCompare
        delegation={DELEGATION}
        request={step('exportDocuments', { projectKey: 'HX-310', items: 400 }, '/x')}
        runCompanyTime="2026-10-26T14:00:00Z"
      />,
    );

    const compare = screen.getByRole('region', { name: word('main.agent.compare.title') });
    expect(within(compare).queryByText(word('main.agent.compare.limit'))).not.toBeInTheDocument();
  });

  it('does not stress a difference: both columns read the same way and the engine names the difference elsewhere', () => {
    render(
      <DelegationCompare
        delegation={DELEGATION}
        request={step('listDocuments', { projectKey: 'HX-310' }, '/api/projects/HX-310/documents')}
        runCompanyTime="2026-10-26T14:00:00Z"
      />,
    );

    expect(document.querySelector('[data-mark], [data-differs]')).toBeNull();
  });
});
