import type { VerdictIcon } from '../domain/verdict';

/** The verdict icons and the few pictograms the steps use to make a row readable at a glance. */
export type IconName =
  | VerdictIcon
  | 'user'
  | 'pin'
  | 'box'
  | 'mail'
  | 'arrowRight'
  | 'arrowLeft'
  | 'play'
  | 'info'
  | 'link'
  | 'chart'
  | 'search'
  | 'code'
  | 'chevronRight'
  | 'chevronDown'
  | 'refresh'
  | 'book'
  | 'download'
  | 'skip';

const PATHS: Record<IconName, string> = {
  check: 'M5 12.5l4.2 4.2L19 7',
  cross: 'M7 7l10 10M17 7L7 17',
  key: 'M14.5 9.5a4 4 0 1 1-1.2-2.9M13.3 6.6L20 13.3l-2 2-1.5-1.5-1.5 1.5-1.5-1.5',
  clock: 'M12 7v5l3 2M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z',
  lock: 'M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6z',
  hourglass: 'M7 3h10M7 21h10M8 3c0 5 8 5 8 9s-8 4-8 9M16 3c0 5-8 5-8 9s8 4 8 9',
  dash: 'M6 12h12',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
  pin: 'M12 21s-6-5.5-6-11a6 6 0 0 1 12 0c0 5.5-6 11-6 11zM12 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  box: 'M4 8l8-4 8 4v8l-8 4-8-4zM4 8l8 4 8-4M12 12v8',
  mail: 'M4 6h16v12H4zM4 7l8 6 8-6',
  arrowRight: 'M5 12h14M13 6l6 6-6 6',
  arrowLeft: 'M19 12H5M11 6l-6 6 6 6',
  play: 'M8 5l11 7-11 7z',
  info: 'M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18zM12 11v5M12 8h.01',
  link: 'M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1',
  chart: 'M4 20h16M7 16v-5M12 16V7M17 16v-8',
  search: 'M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14zM20 20l-4-4',
  code: 'M9 8l-4 4 4 4M15 8l4 4-4 4',
  chevronRight: 'M10 6l6 6-6 6',
  chevronDown: 'M6 10l6 6 6-6',
  refresh: 'M20 12a8 8 0 1 1-2.34-5.66M20 4v6h-6',
  book: 'M5 5a2 2 0 0 1 2-2h11v16H7a2 2 0 0 0-2 2zM5 21V5M9 7h6',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  skip: 'M5 6l8 6-8 6zM16 6v12',
};

interface IconProps {
  readonly name: IconName;
  readonly className?: string | undefined;
}

/** Decorative stroke icon; the meaning is always carried by adjacent text. */
export function Icon({ name, className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
