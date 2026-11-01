"""UX-R1 I-10: the dictionary keys outside `ux.` (the old screens' words) that the code kept after the clean-up still
names, and the rest as deletion candidates for the user; and the `ux.` keys that no kept code names any more.

    python -X utf8 ux_old_keys.py <leftovers.json> <out.json>

<leftovers.json> is `ux_reach.py <out> --leftovers`: every web source file outside its `leftoverFiles` stays after the
clean-up (the application, the shared base, and every test and fixture that stays), and so do the web root's files
outside `leftoverRootTests`. A key counts as named when a string in those files is the key itself, the key without an
i18next plural suffix, or a prefix the code completes (a template's text before its first `${`, or a string ending in
a dot). Tests count too: a kept test of a kept function names the words that function gives (e.g. `evidenceRef.*`).
The count leans to "named": a key it cannot rule out stays, so the candidate list holds only keys whose code goes.
"""
import json
import pathlib
import re
import sys

SRC = pathlib.Path('E:/projects/contexa/contexa-showcase/web/src')
PLURAL = re.compile(r'_(zero|one|two|few|many|other)$')


def strings_of(source: str):
    """The string literals of a TS/TSX source as (text, is_template_head): comments are skipped (a backtick in a comment
    would otherwise pair with one in the code and hide the real strings between), a template gives its text up to its
    first `${` (marked as a head when an expression follows), and the code inside `${…}` is scanned like any code."""
    found = []
    i, n = 0, len(source)
    exprs = []  # brace depth of each open template expression
    last = ''  # the last code character that is not white space: a `/` after an operator opens a regex literal
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            end = source.find('\n', i)
            i = n if end < 0 else end
            continue
        if c == '/' and nxt == '*':
            end = source.find('*/', i + 2)
            i = n if end < 0 else end + 2
            continue
        # Not after `<`, `>` or `}`: in TSX `</tag>`, `/>` and `{value} />` close elements.
        if c == '/' and (last == '' or last in '(,=:[!&|?{;+-*%~^'):
            # A regex literal (its quotes and backticks are not strings): up to the closing slash outside a class.
            j, in_class = i + 1, False
            while j < n and source[j] != '\n':
                if source[j] == '\\':
                    j += 2
                    continue
                if source[j] == '[':
                    in_class = True
                elif source[j] == ']':
                    in_class = False
                elif source[j] == '/' and not in_class:
                    break
                j += 1
            i = j + 1
            last = '/'
            continue
        if not c.isspace():
            last = c
        if c in '\'"':
            j, buf = i + 1, []
            while j < n and source[j] != c and source[j] != '\n':
                if source[j] == '\\' and j + 1 < n:
                    buf.append(source[j + 1])
                    j += 2
                    continue
                buf.append(source[j])
                j += 1
            found.append((''.join(buf), False))
            last = c  # a value: a `/` after it divides or closes an element
            i = j + 1
            continue
        if c == '`' or (c == '}' and exprs and exprs[-1] == 0):
            starting = c == '`'
            if not starting:
                exprs.pop()
            j, buf = i + 1, []
            while j < n and source[j] != '`' and not (source[j] == '$' and j + 1 < n and source[j + 1] == '{'):
                if source[j] == '\\' and j + 1 < n:
                    buf.append(source[j + 1])
                    j += 2
                    continue
                buf.append(source[j])
                j += 1
            opens = j < n and source[j] == '$'
            if starting:
                found.append((''.join(buf), opens))
            last = '`'
            if opens:
                exprs.append(0)
                i = j + 2
            else:
                i = j + 1
            continue
        if c == '{' and exprs:
            exprs[-1] += 1
        elif c == '}' and exprs:
            exprs[-1] -= 1
        i += 1
    return found


def main():
    leftovers = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
    gone = set(leftovers['leftoverFiles'])
    gone_root = set(leftovers.get('leftoverRootTests', []))
    files = [path for path in SRC.rglob('*') if path.suffix in ('.ts', '.tsx')
             and path.relative_to(SRC).as_posix() not in gone]
    files += [path for path in SRC.parent.glob('*.ts') if path.name not in gone_root]
    exact, prefixes = set(), set()
    for path in files:
        for text, head in strings_of(path.read_text(encoding='utf-8')):
            if head:
                if text:
                    prefixes.add(text)
                continue
            if not text:
                continue
            exact.add(text)
            if text.endswith('.'):
                prefixes.add(text)
    dictionary = json.loads((SRC / 'i18n' / 'ko.json').read_text(encoding='utf-8'))
    old = [key for key in dictionary if not key.startswith('ux.')]

    def named(key: str) -> bool:
        base = PLURAL.sub('', key)
        return key in exact or base in exact or any(key.startswith(prefix) for prefix in prefixes)

    used = sorted(key for key in old if named(key))
    candidates = sorted(key for key in old if not named(key))
    # The new screens' own keys that no reached code can name any more (left behind by a change of wording or layout).
    ux_unused = sorted(key for key in dictionary if key.startswith('ux.') and not named(key))
    heads = {}
    for key in used:
        heads[key.split('.', 1)[0]] = heads.get(key.split('.', 1)[0], 0) + 1
    out = {'files': len(files), 'oldKeys': len(old), 'named': len(used), 'candidates': len(candidates),
           'namedByHead': dict(sorted(heads.items(), key=lambda item: -item[1])), 'namedKeys': used,
           'candidateKeys': candidates, 'uxUnused': ux_unused}
    pathlib.Path(sys.argv[2]).write_bytes((json.dumps(out, ensure_ascii=False, indent=1) + '\n').encode('utf-8'))
    print('files', len(files), 'old keys', len(old), 'named', len(used), 'candidates', len(candidates))
    print('named by head', out['namedByHead'])
    print('ux keys no reached code names', len(ux_unused), ux_unused[:12])


if __name__ == '__main__':
    main()
