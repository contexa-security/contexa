"""Adds or updates `ux.` keys in the showcase web dictionaries (src/i18n/ko.json, en.json) from one JSON file.

    python -I ux_keys.py keys.json            # {"ux.verdict.allow": ["허용", "Allow"], ...}
    python -I ux_keys.py keys.json --check    # print what would change, write nothing

Only keys that start with `ux.` are accepted (DEC-6: the new screens' words live under that head). Both languages get
every key, so the dictionaries keep the same key set. The files are written as UTF-8 bytes with LF endings and the
same two-space layout, which a JSON round-trip of the current files reproduces exactly (checked before writing).
"""
import json
import pathlib
import sys

WEB = pathlib.Path(__file__).resolve().parents[4] / "contexa-showcase" / "web" / "src" / "i18n"


def dump(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main():
    source = pathlib.Path(sys.argv[1])
    check = "--check" in sys.argv
    entries = json.loads(source.read_text(encoding="utf-8"))
    bad = [key for key, value in entries.items()
           if not key.startswith("ux.") or not isinstance(value, list) or len(value) != 2
           or not all(isinstance(v, str) and v.strip() for v in value)]
    if bad:
        sys.exit(f"rejected keys (need ux. head and two non-empty strings): {bad}")
    for index, language in enumerate(("ko", "en")):
        path = WEB / f"{language}.json"
        raw = path.read_bytes()
        data = json.loads(raw)
        if dump(data) != raw:
            sys.exit(f"{path} is not in the round-trip layout; refusing to rewrite it")
        added = changed = 0
        for key, value in entries.items():
            text = value[index]
            if key not in data:
                added += 1
            elif data[key] != text:
                changed += 1
            data[key] = text
        print(f"{language}: {added} added, {changed} changed, {len(data)} keys")
        if not check:
            path.write_bytes(dump(data))


if __name__ == "__main__":
    main()
