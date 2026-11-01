import { Fragment, type ReactNode } from 'react';

/**
 * A machine name (`important_instructions`, `FacebookManagerGetUserProfile`, `contexa-injecagent-v1`) with the places a
 * line may break: after `_ - : . /` and before a capital that follows a small letter. A narrow cell then breaks it at a
 * part of the name, never leaving one letter alone on a line.
 */
export function breakable(text: string): ReactNode {
  // A one-character piece stays with the one before it ("sonnet-5-5" breaks as "sonnet-" "5-5", never "5" alone).
  const parts = text.split(/(?<=[_\-:./])|(?<=[a-z])(?=[A-Z])/).reduce<string[]>((joined, part) => {
    const last = joined.length - 1;
    if (last >= 0 && part.length < 2) {
      joined[last] = `${joined[last] ?? ''}${part}`;
    } else {
      joined.push(part);
    }
    return joined;
  }, []);
  if (parts.length < 2) {
    return text;
  }
  return parts.map((part, index) => (
    <Fragment key={index}>
      {index > 0 ? <wbr /> : null}
      {part}
    </Fragment>
  ));
}
