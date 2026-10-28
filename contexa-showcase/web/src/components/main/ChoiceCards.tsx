import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Icon, type IconName } from '../Icon';
import { Fold } from './Fold';
import styles from './ChoiceCards.module.css';

/** One card of a choosing screen: a strong title, one line under it and where it leads. */
export interface Choice {
  /** Names the card for the automatic checks (data-choice). */
  readonly id: string;
  readonly title: ReactNode;
  readonly sub?: ReactNode;
  readonly to: string;
  readonly icon?: IconName;
  /** The card the screen suggests; it carries the mark in `badge`. */
  readonly recommended?: boolean;
}

interface ChoiceCardsProps {
  readonly cards: readonly Choice[];
  /** The list's name for screen readers. */
  readonly label: string;
  /** The word on the suggested card. */
  readonly badge?: string;
  /**
   * How many cards stand in view (구현계획 AC-N5: four at most); the rest wait under one line named by `more`, so a
   * screen never asks for more than four choices at once.
   */
  readonly limit?: number;
  /** The line that opens the cards kept back. */
  readonly more?: string;
}

/**
 * The cards of a choosing screen (T9, docs/showcase/첫화면-선택형-체험-개선기획안.md 4절, R-N1): big, one choice each,
 * every card a link, the title at 24 px and its line at 18 px (6절), so choosing is the whole job of the screen.
 */
export function ChoiceCards({ cards, label, badge, limit, more }: ChoiceCardsProps) {
  const shown = limit === undefined ? cards : cards.slice(0, limit);
  const kept = limit === undefined ? [] : cards.slice(limit);
  return (
    <>
      <CardList cards={shown} label={label} {...(badge === undefined ? {} : { badge })} />
      {kept.length > 0 ? (
        <Fold name="choose-more" summary={more ?? label}>
          <CardList cards={kept} label={more ?? label} />
        </Fold>
      ) : null}
    </>
  );
}

function CardList({
  cards,
  label,
  badge,
}: {
  readonly cards: readonly Choice[];
  readonly label: string;
  readonly badge?: string;
}) {
  return (
    <ul className={styles.cards} aria-label={label} data-count={cards.length}>
      {cards.map((card) => (
        <li key={card.id} className={styles.item}>
          <Link
            to={card.to}
            className={styles.card}
            data-choice={card.id}
            data-recommended={card.recommended || undefined}
          >
            {card.icon ? (
              <span className={styles.mark} aria-hidden="true">
                <Icon name={card.icon} className={styles.markIcon} />
              </span>
            ) : null}
            <span className={styles.text}>
              {card.recommended && badge ? <span className={styles.badge}>{badge}</span> : null}
              <span className={styles.title}>{card.title}</span>
              {card.sub ? <span className={styles.sub}>{card.sub}</span> : null}
            </span>
            <Icon name="arrowRight" className={styles.go} />
          </Link>
        </li>
      ))}
    </ul>
  );
}
