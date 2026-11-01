"""Changes the words of the engine word families the new screens show as they are (DEC-84): the decision prompt's line
names and meanings, the reason codes, the hypotheses, the canonical reasons, the outcomes and the verdicts.

    python -I ux_engine_words.py words.json [--check]   # {"reasonCode.DEVIATION_TIME": ["…", "…"], ...}

Only existing keys of those families change (no key is added: the engine names them); both languages get every key.
The dictionaries are written as UTF-8 bytes with LF endings and the same two-space layout, under the same lock as
ux_keys_locked.py.
"""
import json
import msvcrt
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
WEB = HERE.parents[3] / 'contexa-showcase' / 'web' / 'src' / 'i18n'
HEADS = ('fact.label.', 'fact.meaning.', 'reasonCode.', 'reasonCodeV4.', 'hypothesis.', 'reason.canonical.',
         'outcome.', 'verdict.')


def dump(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def main():
    entries = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
    check = '--check' in sys.argv
    dictionaries = {language: json.loads((WEB / f'{language}.json').read_text(encoding='utf-8')) for language in ('ko', 'en')}
    bad = [key for key, value in entries.items()
           if not key.startswith(HEADS) or key not in dictionaries['ko'] or key not in dictionaries['en']
           or not isinstance(value, list) or len(value) != 2 or not all(isinstance(v, str) and v.strip() for v in value)]
    if bad:
        sys.exit(f'rejected keys (an existing key of the engine families and two non-empty strings): {bad}')
    with open(HERE / '.ux_keys.lock', 'a+b') as handle:
        for _ in range(300):
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                time.sleep(1)
        else:
            sys.exit('lock not taken in 300 s')
        try:
            for index, language in enumerate(('ko', 'en')):
                path = WEB / f'{language}.json'
                raw = path.read_bytes()
                data = json.loads(raw.decode('utf-8'))
                if dump(data) != raw:
                    sys.exit(f'{path} does not round-trip; refusing to rewrite it')
                changed = [key for key, value in entries.items() if data[key] != value[index]]
                for key in changed:
                    data[key] = entries[key][index]
                print(f'{language}: {len(changed)} changed, {len(data)} keys')
                if not check:
                    path.write_bytes(dump(data))
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == '__main__':
    main()
