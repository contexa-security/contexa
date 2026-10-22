import { useTranslation } from 'react-i18next';
import { useBeforeSend } from '../../api/anatomy';
import { useLabOptions } from '../../api/lab';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { count } from '../../journey/format';
import { caseOf, companyClock, MAIN_CASES, personName } from './mainCases';
import styles from './OpeningPage.module.css';

/**
 * 1-1, the start (설계서 1-1): the same account, the same time, the same request; one of the two is an attacker who took
 * over the account. Both cards are the case definitions the demo sends (the real user's approved transfer and the
 * attack), and both sign in the same way, so sign-in alone cannot tell them apart.
 */
export default function OpeningPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const options = useLabOptions();
  const attack = caseOf(options.data, MAIN_CASES.attacker);
  const normal = caseOf(options.data, MAIN_CASES.owner);
  const before = useBeforeSend(MAIN_CASES.attacker, 1);
  const clock = companyClock(t, before.data?.comparison?.companyTime);
  const request = attack?.labCase.requests[0] ?? null;
  const line =
    request && request.items !== null
      ? t('main.1-1.request', { project: request.project ?? '-', items: count(request.items, language) })
      : null;
  const cards = [
    { id: 'owner', found: normal, tone: 'normal' },
    { id: 'attacker', found: attack, tone: 'attack' },
  ] as const;
  return (
    <MainScreen title={t('main.1-1.title')} titleInCore nextNote={<OpeningNote />}>
      <div className={styles.layout}>
        <div className={styles.hero}>
          <p className={styles.statement} aria-hidden="true">
            {t('main.1-1.line1')}
            <br />
            {t('main.1-1.line2')}
            <br />
            {t('main.1-1.line3')}
          </p>
          <p className={styles.twist} aria-hidden="true">
            {t('main.1-1.twist')}
          </p>
          <p className={styles.what}>{t('main.1-1.what')}</p>
        </div>
        <div className={styles.side}>
          <ul className={styles.people}>
            {cards.map((card) => (
              <li key={card.id} className={styles.person} data-tone={card.tone}>
                <div className={styles.personHead}>
                  <b className={styles.personName}>
                    {card.found
                      ? t(`main.1-1.${card.id}.name`, { name: personName(t, card.found.employee) })
                      : t(`main.1-1.${card.id}.name`, { name: '…' })}
                  </b>
                  <Chip kind="allow">{t('main.1-1.signedIn')}</Chip>
                </div>
                <p className={styles.personLine}>{t(`main.1-1.${card.id}.line`)}</p>
                <p className={styles.log}>
                  {clock ? <span className={styles.time}>{clock}</span> : null}
                  {line ? <span>{line}</span> : null}
                </p>
              </li>
            ))}
          </ul>
          <p className={styles.cannot}>{t('main.1-1.cannot')}</p>
        </div>
      </div>
    </MainScreen>
  );
}

/** The footer's line about what comes next: the next screen and what the demo asks of the visitor. */
function OpeningNote() {
  const { t } = useTranslation();
  return (
    <>
      <b className={styles.noteWord}>{t('frame.next')}</b>
      {t('main.1-1.nextNote')}
    </>
  );
}
