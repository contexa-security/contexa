import { useTranslation } from 'react-i18next';
import { Card, DataTable, PageHead } from '../../ui';
import styles from './Privacy.module.css';

/** What the portal processes (DEC-70), each row checked against the portal's code (`RetentionJob`, `LiveQuota`, …). */
const DATA = ['visitor', 'expected', 'runs', 'quota', 'address'] as const;
type DataRow = (typeof DATA)[number];

/** The two cookies the portal sets, as its answers' `Set-Cookie` headers carry them. */
const COOKIES = [
  { name: 'SC_VISITOR', key: 'visitor' },
  { name: 'XSRF-TOKEN', key: 'csrf' },
] as const;
type CookieRow = (typeof COOKIES)[number];

/** What the screens keep in this browser (theme, language, the guide videos watched, an agent case's expectation). */
const STORAGE = [
  { name: 'showcase.theme', key: 'theme', place: 'local' },
  { name: 'showcase.language', key: 'language', place: 'local' },
  { name: 'contexa.guide.watched', key: 'watched', place: 'local' },
  { name: 'ux.agent.call.*', key: 'agentCall', place: 'session' },
] as const;
type StorageRow = (typeof STORAGE)[number];

/**
 * The privacy policy (기획안 4절 바닥, DEC-70): what is not collected, what is processed and kept for how long, the
 * cookies, the browser storage and the outside services — every sentence what the portal's code does now.
 */
export default function PrivacyPage() {
  const { t } = useTranslation();
  return (
    <>
      <PageHead title={t('ux.privacy.title')} desc={t('ux.privacy.desc')} />
      <div className={styles.stack}>
        <Card title={t('ux.privacy.none.title')}>
          <div className={styles.stack}>
            <p className={styles.line}>{t('ux.privacy.none.account')}</p>
            <p className={styles.line}>{t('ux.privacy.none.model')}</p>
          </div>
        </Card>
        <Card title={t('ux.privacy.data.title')} flush>
          <DataTable<DataRow>
            caption={t('ux.privacy.data.title')}
            stack
            rowKey={(row) => row}
            rows={DATA}
            columns={[
              { key: 'info', header: t('ux.privacy.col.info'), strong: true, render: (row) => t(`ux.privacy.data.${row}.info`) },
              { key: 'purpose', header: t('ux.privacy.col.purpose'), render: (row) => t(`ux.privacy.data.${row}.purpose`) },
              { key: 'kept', header: t('ux.privacy.col.kept'), render: (row) => t(`ux.privacy.data.${row}.kept`) },
            ]}
          />
        </Card>
        <Card title={t('ux.privacy.cookies.title')} flush>
          <DataTable<CookieRow>
            caption={t('ux.privacy.cookies.title')}
            stack
            rowKey={(row) => row.name}
            rows={COOKIES}
            columns={[
              {
                key: 'name',
                header: t('ux.privacy.col.name'),
                strong: true,
                render: (row) => (
                  <code className={styles.code} data-original="">
                    {row.name}
                  </code>
                ),
              },
              { key: 'role', header: t('ux.privacy.col.role'), render: (row) => t(`ux.privacy.cookies.${row.key}.role`) },
              { key: 'period', header: t('ux.privacy.col.period'), render: (row) => t(`ux.privacy.cookies.${row.key}.period`) },
            ]}
          />
        </Card>
        <Card title={t('ux.privacy.storage.title')} sub={t('ux.privacy.storage.sub')} flush>
          <DataTable<StorageRow>
            caption={t('ux.privacy.storage.title')}
            stack
            rowKey={(row) => row.name}
            rows={STORAGE}
            columns={[
              {
                key: 'name',
                header: t('ux.privacy.col.name'),
                strong: true,
                render: (row) => (
                  <code className={styles.code} data-original="">
                    {row.name}
                  </code>
                ),
              },
              { key: 'role', header: t('ux.privacy.col.role'), render: (row) => t(`ux.privacy.storage.${row.key}`) },
              { key: 'place', header: t('ux.privacy.col.place'), render: (row) => t(`ux.privacy.storage.${row.place}`) },
            ]}
          />
        </Card>
        <Card title={t('ux.privacy.external.title')}>
          <div className={styles.stack}>
            <p className={styles.line}>{t('ux.privacy.external.delete')}</p>
            <p className={styles.line}>{t('ux.privacy.external.turnstile')}</p>
            <p className={styles.line}>{t('ux.privacy.external.model')}</p>
            <p className={styles.line}>{t('ux.privacy.external.old')}</p>
          </div>
        </Card>
      </div>
    </>
  );
}
