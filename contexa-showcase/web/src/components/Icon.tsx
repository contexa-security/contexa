import type { VerdictIcon } from '../domain/verdict';

const PATHS: Record<VerdictIcon, string> = {
  check: 'M5 12.5l4.2 4.2L19 7',
  cross: 'M7 7l10 10M17 7L7 17',
  key: 'M14.5 9.5a4 4 0 1 1-1.2-2.9M13.3 6.6L20 13.3l-2 2-1.5-1.5-1.5 1.5-1.5-1.5',
  clock: 'M12 7v5l3 2M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z',
  lock: 'M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6z',
  hourglass: 'M7 3h10M7 21h10M8 3c0 5 8 5 8 9s-8 4-8 9M16 3c0 5-8 5-8 9s8 4 8 9',
};

interface IconProps {
  readonly name: VerdictIcon;
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
