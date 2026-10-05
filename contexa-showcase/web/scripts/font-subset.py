"""Builds the demo's own Pretendard subset (P5-FE-01, approval Q-36).

The visitor screens otherwise load about fifteen unicode-range pieces of Pretendard (some 375 KB) for one Korean
page. This keeps every character the screens can show - the dictionaries, the web sources, the scenario and pair
texts the portal sends - in one variable WOFF2 file, preloaded by index.html. Any other character still comes from
the regular Pretendard pieces listed after it in the font stack, so nothing ever shows in a wrong font.

Run after changing visitor texts:  python web/scripts/font-subset.py   (needs fontTools and brotli)
The font is SIL OFL 1.1 (Copyright 2023 Kil Hyung-jin); the license text is in public/fonts/OFL.txt.
"""
import pathlib

from fontTools import subset

WEB = pathlib.Path(__file__).resolve().parents[1]
SHOWCASE = WEB.parent
SOURCE = WEB / "node_modules/pretendard/dist/public/variable/PretendardVariable.ttf"
TARGET = WEB / "public/fonts/pretendard-demo.woff2"
CHARS = WEB / "public/fonts/pretendard-demo.chars.txt"

# Latin, Latin-1, general punctuation, letterlike symbols, arrows and math operators the copy may use.
ALWAYS = [(0x20, 0x7E), (0xA0, 0xFF), (0x2000, 0x206F), (0x2100, 0x214F), (0x2190, 0x21FF), (0x2212, 0x2212)]


def visitor_text() -> str:
    parts = []
    for path in sorted((WEB / "src").rglob("*")):
        if path.suffix in {".json", ".ts", ".tsx"} and ".test." not in path.name:
            parts.append(path.read_text(encoding="utf-8"))
    resources = SHOWCASE / "showcase-portal/src/main/resources"
    for folder in ("pairs", "scenarios"):
        for path in sorted((resources / folder).glob("*.json")):
            parts.append(path.read_text(encoding="utf-8"))
    parts.append((WEB / "index.html").read_text(encoding="utf-8"))
    return "".join(parts)


def main() -> None:
    codepoints = {cp for low, high in ALWAYS for cp in range(low, high + 1)}
    codepoints |= {ord(ch) for ch in visitor_text() if ord(ch) >= 0x80 and not ch.isspace() or ch == " "}
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["*"]
    options.name_IDs = ["*"]
    options.notdef_outline = True
    font = subset.load_font(str(SOURCE), options)
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=sorted(codepoints))
    subsetter.subset(font)
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    subset.save_font(font, str(TARGET), options)
    covered = sorted(cp for cp in codepoints if cp >= 0x80)
    CHARS.write_text("".join(chr(cp) for cp in covered) + "\n", encoding="utf-8")
    hangul = sum(1 for cp in covered if 0xAC00 <= cp <= 0xD7A3)
    print(f"{TARGET.name}: {TARGET.stat().st_size // 1024} KB, {len(codepoints)} characters, {hangul} Hangul syllables")


if __name__ == "__main__":
    main()
