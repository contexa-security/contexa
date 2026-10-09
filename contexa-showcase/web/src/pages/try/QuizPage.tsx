import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { answerQuiz, useQuizQuestions, type QuizResult } from '../../api/journey';
import { ActionChip } from '../../components/common/ActionChip';
import { Icon } from '../../components/Icon';
import { DifferenceMark } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import styles from './QuizPage.module.css';

/** The screen of the default route where each difference is seen (thread), where a wrong answer leads back to. */
const REVISIT: Readonly<Record<number, string>> = {
  1: '/try/timing/when',
  2: '/try/attacker/compare',
  3: '/try/owner/result',
  4: '/try/attacker/reason',
  5: '/try/attacker/after',
  6: '/try/stack',
};

/**
 * The understanding check (quiz, 7.4): three questions, one at a time (one input at a time, limits), scored by the
 * server, which keeps the answers; then how many were right, and for each wrong one the screen to see again. It can be
 * skipped: the main button goes on to the value screen either way.
 */
export default function QuizPage() {
  const { t } = useTranslation();
  const questions = useQuizQuestions();
  const [answers, setAnswers] = useState<Readonly<Record<string, string>>>({});
  const [index, setIndex] = useState(0);
  const [result, setResult] = useState<QuizResult | null>(null);
  const [failed, setFailed] = useState(false);
  const [sending, setSending] = useState(false);
  const list = questions.data ?? [];
  const question = list[index] ?? null;
  const last = index === list.length - 1;

  const submit = async () => {
    setSending(true);
    setFailed(false);
    try {
      const scored = await answerQuiz(answers);
      setResult(scored);
      setFailed(scored === null);
    } catch {
      setFailed(true);
    } finally {
      setSending(false);
    }
  };

  return (
    <RouteScreen title={t('quiz.title')} purpose={t('quiz.purpose')} nextLabel={t('quiz.next')}>
      {questions.isPending ? <StateScreen kind="loading" /> : null}
      {questions.isError ? <StateScreen kind="error" onRetry={() => void questions.refetch()} /> : null}
      {result === null && question ? (
        <div className={styles.question}>
          <fieldset className={styles.fieldset}>
            <legend className={styles.legend}>
              <span className={styles.counter}>
                {t('quiz.counter', { n: index + 1, total: list.length })}
              </span>
              {t(`quiz.${question.id}.question`)}
            </legend>
            <div className={styles.options}>
              {question.options.map((option) => (
                <label
                  key={option}
                  className={styles.option}
                  data-chosen={answers[question.id] === option || undefined}
                >
                  <input
                    type="radio"
                    name={question.id}
                    value={option}
                    checked={answers[question.id] === option}
                    onChange={() => setAnswers((current) => ({ ...current, [question.id]: option }))}
                  />
                  {t(`quiz.${question.id}.option.${option}`)}
                </label>
              ))}
            </div>
          </fieldset>
          <div className={styles.controls}>
            {index > 0 ? (
              <ActionChip icon="arrowLeft" variant="quiet" onClick={() => setIndex(index - 1)}>
                {t('quiz.previous')}
              </ActionChip>
            ) : null}
            <ActionChip
              icon={last ? 'check' : 'arrowRight'}
              variant="move"
              disabled={!answers[question.id] || sending}
              onClick={() => (last ? void submit() : setIndex(index + 1))}
            >
              {last ? t('quiz.score') : t('quiz.nextQuestion')}
            </ActionChip>
          </div>
          {failed ? <p className={styles.failed}>{t('quiz.failed')}</p> : null}
        </div>
      ) : null}
      {result ? (
        <section className={styles.result} aria-labelledby="quiz-score">
          <h2 id="quiz-score" className={styles.score}>
            {t('quiz.result', { right: result.right, total: result.total })}
          </h2>
          <ol className={styles.answers}>
            {result.answers.map((answer) => (
              <li key={answer.question} className={styles.answer} data-right={answer.right || undefined}>
                <span className={styles.mark} data-right={answer.right || undefined}>
                  <Icon name={answer.right ? 'check' : 'cross'} />
                  {answer.right ? t('quiz.right') : t('quiz.wrong')}
                </span>
                <span className={styles.answerText}>
                  <span className={styles.answerQuestion}>{t(`quiz.${answer.question}.question`)}</span>
                  <span>
                    {t('quiz.correct', { answer: t(`quiz.${answer.question}.option.${answer.correct}`) })}
                  </span>
                </span>
                {answer.right ? null : (
                  <ActionChip to={REVISIT[answer.revisit] ?? '/try/attacker/scene'} size="sm">
                    <span className={styles.revisit}>
                      <DifferenceMark difference={answer.revisit} seen />
                      {t('quiz.revisit', { difference: t(`difference.${answer.revisit}`) })}
                    </span>
                  </ActionChip>
                )}
              </li>
            ))}
          </ol>
        </section>
      ) : null}
    </RouteScreen>
  );
}
