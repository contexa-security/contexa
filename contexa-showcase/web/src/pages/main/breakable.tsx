import type { ReactNode } from 'react';

/**
 * An engine name (`POLICY_NOT_SATISFIED_NO_RECORD`, `B1 BaselineStatus`) that may break only after an underscore or
 * before a capital that follows a small letter, so a narrow column never splits a word and leaves one letter alone.
 */
export function breakable(text: string): ReactNode[] {
  return text
    .split(/(?<=_)|(?<=[a-z])(?=[A-Z])/)
    .flatMap((part, index) => (index === 0 ? [part] : [<wbr key={index} />, part]));
}
