import { useTranslation } from 'react-i18next';
import type { MenuId } from '../routes';
import { Note, PageHead } from '../ui';

/**
 * A menu whose screen a later stage of UX-R1 builds (구현계획서 4절). It keeps the menu's address, title and place in the
 * frame meanwhile; the I-10 gate requires that no address still opens it, and this file goes with the last one.
 */
const PENDING_STAGES: Readonly<Partial<Record<MenuId, string>>> = {
  home: 'I-3',
  person: 'I-3',
  agent: 'I-4',
  surge: 'I-4',
  policy: 'I-4',
  runs: 'I-5',
  engine: 'I-5',
  compare: 'I-5',
  benchmarks: 'I-6',
  validation: 'I-6',
  adopt: 'I-7',
  metrics: 'I-7',
  tour: 'I-7',
  glossary: 'I-7',
  privacy: 'I-7',
};

export function PendingScreen({ menu }: { readonly menu: MenuId }) {
  const { t } = useTranslation();
  return (
    <>
      <PageHead title={t(`ux.menu.${menu}`)} />
      <Note>{t('ux.pending.note', { stage: PENDING_STAGES[menu] ?? '' })}</Note>
    </>
  );
}
