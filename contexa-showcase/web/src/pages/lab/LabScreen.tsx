import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useVisitor } from '../../api/queries';
import { AppHeader } from '../../components/AppHeader';
import { TermScope } from '../../components/common/Glossary';
import { ScreenBody } from '../../components/journey/ScreenBody';
import experience from '../try/Experience.module.css';
import { barProgress, walkNumber, type LabStep } from './labPlace';

/** The screen types of the redesign (화면재편-기획안 6절) and the table screen of plan 5 (the rule tightening). */
export type LabScreenType = 'T1' | 'T2' | 'T3' | 'T4' | 'T5' | 'table';

interface LabScreenProps {
  readonly step: LabStep;
  readonly type: LabScreenType;
  readonly title: ReactNode;
  /** What the visitor does here, in one line (R-5). */
  readonly purpose: ReactNode;
  readonly children: ReactNode;
  /** The chips under the body that open more of it (the decision details); result screens only (R-2). */
  readonly more?: ReactNode;
  /** The screen's one source line (R-10), on screens with numbers. */
  readonly sourceLine?: ReactNode;
  /** The way back; the lab's steps name their own (none on the entrance). */
  readonly back: { readonly to: string; readonly label: string } | null;
  /** The one main action: the next step's question, or Send. */
  readonly main: ReactNode;
}

/**
 * Every lab screen in the redesigned frame (화면재편 R7, RO-2): the top bar names the lab and the step and shows how far
 * along the lab's walk the screen is, then the inside every screen shares (ScreenBody: title zone, body, source line,
 * action bar). The page carries the screen's type, which the automatic check (e2e/frame-audit.mjs) reads.
 */
export function LabScreen({
  step,
  type,
  title,
  purpose,
  children,
  more = null,
  sourceLine = null,
  back,
  main,
}: LabScreenProps) {
  const { t } = useTranslation();
  useVisitor();
  const name = t(`lab.r7.step.${step}`);
  // V-30: a step of the walk carries its number, as the entrance numbers the steps.
  const number = walkNumber(step);
  return (
    <>
      <AppHeader
        space={{
          name: t('frame.space.lab'),
          step: number ? t('lab.r7.stepOf', { name, n: number.n, total: number.total }) : name,
          progress: barProgress(step),
        }}
      />
      <main id="main" className={experience.page} data-type={type}>
        <TermScope>
          <ScreenBody
            title={title}
            purpose={purpose}
            more={more}
            sourceLine={sourceLine}
            back={back}
            main={main}
          >
            {children}
          </ScreenBody>
        </TermScope>
      </main>
    </>
  );
}
