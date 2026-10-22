import { render } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import '../../i18n';
import i18n from '../../i18n';
import ko from '../../i18n/ko.json';
import { required } from '../../test/required';
import { ReasonChain } from './ReasonChain';
import { contractOf, reasonCodeKey } from './reasonMeaning';

const KO: Readonly<Record<string, string>> = ko;

beforeEach(async () => {
  await i18n.changeLanguage('ko');
});

/**
 * SC-6 (변경 6 of docs/showcase/프롬프트-v21-구현계획.md): a code of the output contract v4 is read with the v4 meanings,
 * where a judgment code says what the model judged; a code of the contract v3 keeps the v3 meaning.
 */
describe('the meaning of a reason code by its contract', () => {
  it('picks the v4 meanings for a code of the output contract v4 only', () => {
    expect(reasonCodeKey({ code: 'ROLE_SCOPE_OUTSIDE', contract: 'V4' })).toBe('reasonCodeV4.ROLE_SCOPE_OUTSIDE');
    expect(reasonCodeKey({ code: 'ROLE_SCOPE_OUTSIDE', contract: null })).toBe('reasonCode.ROLE_SCOPE_OUTSIDE');
    expect(reasonCodeKey({ code: 'ROLE_SCOPE_OUTSIDE' })).toBe('reasonCode.ROLE_SCOPE_OUTSIDE');
    expect(contractOf([{ code: 'DEVIATION_TIME', fact: 'F1', contract: 'V4' }])).toBe('V4');
    expect(contractOf([{ code: 'DEVIATION_TIME', fact: 'F1' }])).toBeNull();
  });

  it('says that the AI judged a v4 judgment code, and states the v3 fact for a v3 one', () => {
    const v4 = render(
      <ReasonChain
        reasonCodes={[{ code: 'ROLE_SCOPE_OUTSIDE', fact: 'F8', contract: 'V4' }]}
        facts={null}
        verdict="ESCALATE"
      />,
    );
    expect(v4.container).toHaveTextContent(required(KO['reasonCodeV4.ROLE_SCOPE_OUTSIDE'], 'v4'));
    expect(v4.container).not.toHaveTextContent(required(KO['reasonCode.ROLE_SCOPE_OUTSIDE'], 'v3'));
    v4.unmount();

    const v3 = render(
      <ReasonChain reasonCodes={[{ code: 'ROLE_SCOPE_OUTSIDE', fact: 'F8' }]} facts={null} verdict="ESCALATE" />,
    );
    expect(v3.container).toHaveTextContent(required(KO['reasonCode.ROLE_SCOPE_OUTSIDE'], 'v3'));
  });
});
