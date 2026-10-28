import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { AgentSnapshotEntry } from '../../api/agentSnapshots';
import { ageOf } from '../../domain/age';
import { count } from '../../journey/format';
import { SourceBadge } from './SourceBadge';

/**
 * Says the screen shows a stored real run, not one made for the visitor now (docs/agent Agent중심-화면 AC-5, D-7): how
 * long ago the run was made for real, the day it was recorded, and that showing it calls no model. It names no run to
 * open: the stored copy is a file, and the decision details read the database, which a cleanup may have emptied.
 */
export function SnapshotBadge({ snapshot }: { readonly snapshot: AgentSnapshotEntry & { readonly capturedAt: string } }) {
  const { t, i18n } = useTranslation();
  // The age is read once when the badge is shown; it does not tick while the visitor reads.
  const [shownAt] = useState(() => Date.now());
  const age = ageOf(snapshot.capturedAt, shownAt);
  return (
    <SourceBadge
      kind="other"
      label={t('badge.snapshot', {
        age: t(`badge.age.${age.unit}`, { n: count(age.n, i18n.language) }),
        date: snapshot.capturedAt.slice(0, 10),
      })}
    />
  );
}
