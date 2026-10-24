// The guide videos' captions (가이드영상-계획.md): each scene's line of the dictionary is shown as short lines, one at a
// time, so a caption stays one row at the bottom of the video and never climbs over the recorded screen. A line never
// runs across a sentence end; inside a sentence it is cut at a comma or colon unless a cut at a space saves more than
// one line, and a cut lands after a punctuation mark or a Korean particle, or before an English joining word, where it
// can, and never inside a quoted name unless nothing else fits. Each line gets a share of its scene's time in
// proportion to its length.

/**
 * The longest line in characters. The site draws captions in proportion to the video's size (GuidePreview.module.css),
 * so a line that fits one row fits it on every screen; e2e/guide-caption-fit.mjs measures every line on the real page.
 */
export const LINE_LIMIT = { ko: 28, en: 54 };

const SENTENCE = /(?<=[.;!?])\s+/;
const CLAUSE = /(?<=[,:])\s+/;
const WORD = /\s+/;

const PUNCTUATION_END = /[,.;:!?]$/;
/** A Korean particle, a connective ending or '뒤' (예상한 뒤, "after"): a phrase ends there. */
const KOREAN_PHRASE_END = /[은는이가을를과와고며서에의도로면게만뒤]$/;
/** English words a line should not stop at: an article, a preposition or a joining word wants what follows it. */
const WEAK_ENGLISH_END =
  /\b(?:a|an|the|of|to|in|on|at|for|by|from|with|against|and|or|that|its|their|real)$/i;
/** English words a line may start with: a new phrase begins there. "of" belongs to the word before it. */
const ENGLISH_PHRASE_START = /^(?:with|since|and|or|then|to|for|while|when|because|against)\b/i;

/** A quoted name opens where a quote mark starts a word; an apostrophe inside a word ("Contexa's") opens nothing. */
const QUOTE_OPEN = /(?:^|\s)'/g;

/** Whether `row` opened a quoted name ('에이전트에게 맡기기', a name on the screen) and has not closed it yet. */
function insideQuote(row) {
  const opened = [...row.matchAll(QUOTE_OPEN)].at(-1);
  return opened !== undefined && !row.slice(opened.index + opened[0].length).includes("'");
}

/**
 * How bad a cut between `row` and the next part is: 0 at a phrase boundary, 1 between words, 2 inside a phrase, 3
 * inside a quoted name.
 */
function cutCost(row, next) {
  if (insideQuote(row)) return 3;
  if (PUNCTUATION_END.test(row)) return 0;
  if (/[가-힣]$/.test(row)) return KOREAN_PHRASE_END.test(row) ? 0 : 2;
  if (WEAK_ENGLISH_END.test(row) || /^of\b/i.test(next)) return 2;
  return ENGLISH_PHRASE_START.test(next) ? 0 : 1;
}

/**
 * Joins the parts into rows within the limit: the fewest rows, then the cheapest cuts ({@link cutCost}), then the
 * longest row as short as possible.
 */
function pack(parts, limit) {
  const best = new Array(parts.length + 1).fill(null);
  best[parts.length] = { count: 0, cost: 0, worst: 0, rows: [] };
  for (let from = parts.length - 1; from >= 0; from -= 1) {
    for (let to = from + 1; to <= parts.length; to += 1) {
      const row = parts.slice(from, to).join(' ');
      if (row.length > limit) break;
      const rest = best[to];
      if (rest === null) continue;
      const option = {
        count: rest.count + 1,
        cost: rest.cost + (to < parts.length ? cutCost(row, parts[to]) : 0),
        worst: Math.max(rest.worst, row.length),
        rows: [row, ...rest.rows],
      };
      const current = best[from];
      if (
        current === null ||
        option.count < current.count ||
        (option.count === current.count && option.cost < current.cost) ||
        (option.count === current.count && option.cost === current.cost && option.worst < current.worst)
      ) {
        best[from] = option;
      }
    }
  }
  return best[0]?.rows ?? null;
}

/** The rows of a text cut by the separator: parts that fit are packed together, longer parts are cut finer. */
function cut(text, limit, separator, finer) {
  const parts = text.split(separator);
  if (parts.length < 2) return null;
  const rows = [];
  let run = [];
  const flush = () => {
    if (run.length > 0) rows.push(...pack(run, limit));
    run = [];
  };
  for (const part of parts) {
    if (part.length <= limit) {
      run.push(part);
    } else {
      flush();
      rows.push(...finer(part));
    }
  }
  flush();
  return rows;
}

function words(text, limit) {
  return cut(text, limit, WORD, (part) => [part]) ?? [text];
}

function sentenceLines(text, limit) {
  if (text.length <= limit) return [text];
  const byWord = words(text, limit);
  const byClause = cut(text, limit, CLAUSE, (part) => words(part, limit));
  return byClause !== null && byClause.length <= byWord.length + 1 ? byClause : byWord;
}

/** A scene's line as caption lines of at most `limit` characters that read back as the line when joined by spaces. */
export function captionLines(text, limit) {
  if (text.length <= limit) return [text];
  return (
    cut(text, limit, SENTENCE, (sentence) => sentenceLines(sentence, limit)) ?? sentenceLines(text, limit)
  );
}

function stamp(seconds) {
  const total = Math.max(0, Math.round(seconds * 1000));
  const pad = (value, size = 2) => String(value).padStart(size, '0');
  return `${pad(Math.floor(total / 3_600_000))}:${pad(Math.floor(total / 60_000) % 60)}:${pad(Math.floor(total / 1000) % 60)}.${pad(total % 1000, 3)}`;
}

/**
 * The WebVTT of a recorded guide: `scenes` are the scene keys with the second each began, `end` the second the last
 * one ended; each scene's line from `dictionary` is cut into lines that share its time in proportion to their length.
 */
export function vtt(scenes, end, dictionary, limit) {
  const cues = [];
  scenes.forEach((scene, index) => {
    const until = index + 1 < scenes.length ? scenes[index + 1].start : end;
    const lines = captionLines(dictionary[scene.key], limit);
    const letters = lines.reduce((sum, line) => sum + line.length, 0);
    let at = scene.start;
    lines.forEach((line, row) => {
      const next = row + 1 < lines.length ? at + ((until - scene.start) * line.length) / letters : until;
      cues.push({ from: at, to: next, line });
      at = next;
    });
  });
  const blocks = cues.map(
    (cue, index) => `${index + 1}\n${stamp(cue.from)} --> ${stamp(cue.to)}\n${cue.line}`,
  );
  return `WEBVTT\n\n${blocks.join('\n\n')}\n`;
}
