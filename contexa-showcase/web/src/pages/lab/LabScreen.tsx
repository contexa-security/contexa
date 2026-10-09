import type { ReactNode } from 'react';
import { useVisitor } from '../../api/queries';
import { AppHeader } from '../../components/AppHeader';
import { TermScope } from '../../components/common/Glossary';
import { LabBar, type LabStep } from '../../components/journey/JourneyParts';
import { ActionBar, MoreRow, StepHeader } from '../../components/journey/StepParts';
import experience from '../try/Experience.module.css';

interface LabScreenProps {
  readonly step: LabStep;
  readonly title: ReactNode;
  readonly purpose: ReactNode;
  readonly source?: ReactNode;
  readonly children: ReactNode;
  /** The chips that open more of the content (windows, folds), right under it. */
  readonly more?: ReactNode;
  readonly back?: { readonly to: string; readonly label: string } | null;
  /** The one main action. */
  readonly main?: ReactNode;
}

/**
 * Every lab screen in the routes' one order and set of places (U-9): the lab's place band, the head (headline, purpose,
 * source), the content, the "more" row and the action area with the way back and the one main button. The lab has no
 * teaser band and no "skip"; its steps are its own.
 */
export function LabScreen({
  step,
  title,
  purpose,
  source = null,
  children,
  more = null,
  back = null,
  main = null,
}: LabScreenProps) {
  useVisitor();
  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page}>
        <LabBar step={step} />
        <TermScope>
          <div className={experience.step}>
            <StepHeader title={title} purpose={purpose} source={source} />
            {children}
            {more ? <MoreRow>{more}</MoreRow> : null}
            <ActionBar back={back} main={main} skip={false} />
          </div>
        </TermScope>
      </main>
    </>
  );
}
