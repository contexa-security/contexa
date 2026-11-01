import { Fragment, type ReactNode } from 'react';

/**
 * A machine name (`important_instructions`, `FacebookManagerGetUserProfile`, `contexa-injecagent-v1`) with the places a
 * line may break: after `_ - : . / +` and before a capital that follows a small letter. A narrow cell then breaks it at a
 * part of the name, never leaving one letter alone on a line.
 */
export function breakable(text: string): ReactNode {
  // A one-character piece stays with the one before it ("sonnet-5-5" breaks as "sonnet-" "5-5", never "5" alone).
  const parts = text.split(/(?<=[_\-:./+])|(?<=[a-z])(?=[A-Z])/).reduce<string[]>((joined, part) => {
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

/**
 * A hash or another run of letters and digits without punctuation, breakable only every `size` characters
 * (`3a7b85` `26b659`), so a narrow cell never leaves one or two characters alone on a line. A short tail stays with the
 * piece before it, and anything after the hex (an ellipsis) stays on the last piece.
 */
export function chunked(text: string, size = 6): ReactNode {
  const pieces: string[] = [];
  for (let at = 0; at < text.length; at += size) {
    pieces.push(text.slice(at, at + size));
  }
  const last = pieces.length - 1;
  if (last > 0 && (pieces[last]?.length ?? 0) < Math.ceil(size / 2)) {
    pieces[last - 1] = `${pieces[last - 1] ?? ''}${pieces.pop() ?? ''}`;
  }
  if (pieces.length < 2) {
    return text;
  }
  return pieces.map((piece, index) => (
    <Fragment key={index}>
      {index > 0 ? <wbr /> : null}
      {piece}
    </Fragment>
  ));
}
