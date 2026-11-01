"""UX-R1 I-10: the hand-over list of what the user may remove after the redesign (files, code lines, old dictionary keys),
written as a Markdown page and two plain lists the removal commands read.

    python -X utf8 ux_leftover_report.py <leftovers.json> <old-keys.json> <out dir>

<leftovers.json> is `ux_reach.py <out> --leftovers`; <old-keys.json> is `ux_old_keys.py`. Nothing is removed here: the
page names each file and line, and the commands the user runs. Run it again after any change to the web sources.
"""
import collections
import datetime
import json
import pathlib
import sys

WEB = 'contexa-showcase/web'
# The development server's sample page of the new parts (`/design/ux`): kept unless the user decides otherwise.
DECIDE = ('ux/pages/design/',)
# `ux.` keys the count cannot see named but that are, checked by hand: a template whose start is a variable
# (`${key}Served`, ux/pages/simulate/agent/ResultPage.tsx) and the development-only parts page (DECIDE above).
UX_KEPT = {
    'ux.agentResult.confirm.otherServed': '`${key}Served`',
    'ux.agentResult.confirm.otherServed_one': '`${key}Served`',
    'ux.agentResult.confirm.reuseServed': '`${key}Served`',
    'ux.agentResult.confirm.reuseServed_one': '`${key}Served`',
    'ux.parts.desc': '개발 서버 부품 견본',
    'ux.parts.title': '개발 서버 부품 견본',
}
# Old e2e tools that open the old design pages (`/design/states`, `/design/parts`), found by a search of web/e2e.
# Files live only through a line section 2 takes out (main.tsx's import of the old tokens).
WITH_LINES = ['styles/tokens.css']
OLD_E2E = ['e2e/s2-parts.mjs', 'e2e/_clip.mjs', 'e2e/_overflow_find.mjs', 'e2e/visual/design-states.spec.ts']


def group(paths):
    counts = collections.Counter()
    for path in paths:
        parts = path.split('/')
        counts['/'.join(parts[:2]) if len(parts) > 2 else parts[0]] += 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def main():
    leftovers = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
    keys = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding='utf-8'))
    out = pathlib.Path(sys.argv[3])
    root = leftovers.get('leftoverRootTests', [])
    root_names = ', '.join(f'`{name}`' for name in root)
    files = sorted([path for path in leftovers['leftoverFiles'] if not path.startswith(DECIDE)] + WITH_LINES)
    decide = [path for path in leftovers['leftoverFiles'] if path.startswith(DECIDE)]
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')
    (out / 'leftover-files.txt').write_bytes(('\n'.join(files) + '\n').encode('utf-8'))
    ux_unused = [key for key in keys.get('uxUnused', []) if key not in UX_KEPT]
    removable = sorted(keys['candidateKeys'] + ux_unused)
    (out / 'leftover-keys.txt').write_bytes(('\n'.join(removable) + '\n').encode('utf-8'))
    lines = [
        '# UX-R1 정리 목록(사용자 삭제용)',
        '',
        f'만든 시각: {now} 세계 표준시. 만든 도구: `_tools/ux_leftover_report.py`(근거 `ux_reach.py --leftovers` · `ux_old_keys.py`).',
        '이 목록은 지우지 않고 이름만 적습니다. 지우기와 커밋은 사용자가 합니다. 웹 소스가 바뀌면 다시 만듭니다.',
        '',
        '## 1. 요약',
        '',
        '| 무엇 | 수 | 근거 |',
        '|---|---|---|',
        f'| 함께 지울 파일(`{WEB}/src` 아래, 시험 · 시험 자료 포함) | {len(files)} | 살아 있는 코드(진입점에서 닿는 파일, 타입 포함)와 살아 있는 시험이 하나도 부르지 않음 |',
        f'| 함께 지울 루트 시험(`{WEB}` 바로 아래) | {len(root)} | 옛 화면만 보는 시험(3절) |',
        f'| 함께 뺄 코드 줄 | 4곳 | 개발 서버 전용 옛 설계 화면 경로, 옛 토큰 파일 불러오기, 옛 루트 시험 이름 두 포함 목록 |',
        f'| 옛 사전 키(`ux.` 밖) | {keys["candidates"]} / {keys["oldKeys"]} | 운영 묶음 코드({keys["files"]}개 파일)가 부를 수 없는 키. 부를 수 있는지 애매하면 남김({keys["named"]}개 남김) |',
        f'| 따로 판단할 것 | {len(decide) + len(OLD_E2E) + 1} | 아래 4절 |',
        '',
        '## 2. 함께 뺄 코드 줄(파일을 지울 때 같이)',
        '',
        f'- `{WEB}/src/ux/UxApp.tsx`: `OldDesignStatesPage` · `OldDesignPartsPage` 두 상수와 그 경로 두 줄(`/design/states` · `/design/parts`). 개발 서버에서만 붙는 옛 설계 화면입니다.',
        f'- `{WEB}/src/main.tsx`: `import \'./styles/tokens.css\';` 한 줄. 옛 토큰 파일은 `:root` 변수만 정의하고, 새 화면은 그 변수를 쓰지 않습니다. 고정폭 글꼴 불러오기는 새 토큰 파일로 옮겨 두었습니다(2026-11-01). 그 파일(`src/styles/tokens.css`)은 3절 목록에 들어 있습니다.',
        f'- `{WEB}/vitest.config.ts`의 `include`와 `{WEB}/tsconfig.node.json`의 `include`: 3절의 루트 시험 {len(root)}개 이름({root_names}).',
        '',
        '## 3. 함께 지울 파일',
        '',
        '폴더별 수:',
        '',
        '| 폴더 | 파일 수 |',
        '|---|---|',
    ]
    lines += [f'| `{name}` | {count} |' for name, count in group(files)]
    lines += [
        '',
        f'전체 목록은 같은 폴더의 `leftover-files.txt`({len(files)}줄, `src` 기준 경로)에 있습니다. 목록 전체를 한꺼번에 지워야 타입 검사가 깨지지 않습니다(목록 안의 파일끼리 서로 부릅니다).',
        '',
        f'루트 시험(`{WEB}` 바로 아래, 옛 화면만 봄): {root_names}. 사전 항목 · 근거 코드 대조 가운데 새 화면이 쓰는 것은 `factKeySource.test.ts`로 옮겼습니다.',
        '',
        'PowerShell(`contexa-showcase/web`에서):',
        '',
        '```powershell',
        'Get-Content ..\\..\\docs\\showcase\\ux-r1-검수\\I-10\\leftover-files.txt | Where-Object { $_ } | ForEach-Object { Remove-Item -LiteralPath (Join-Path src $_) }',
        'Remove-Item -LiteralPath ' + ', '.join(root),
        '```',
        '',
        '## 4. 따로 판단할 것',
        '',
    ]
    lines += [f'- `{WEB}/src/{path}`: 새 부품 견본(개발 서버 `/design/ux`). 운영 묶음에는 없습니다. 개발 도구로 남길지 정합니다.' for path in decide]
    lines += [f'- `{WEB}/{path}`: 옛 설계 화면(`/design/states` · `/design/parts`)을 여는 옛 e2e 도구. 2절의 경로를 빼면 동작하지 않습니다.' for path in OLD_E2E]
    lines += [
        f'- `{WEB}/e2e` 폴더의 나머지 도구: 옛 화면 검수용 일회성 도구가 대부분입니다. 하나씩 판단이 필요해 이 목록에 넣지 않았습니다.',
        '- `docs/showcase/ux-r1-시안/_tools/_wide_tmp.mjs`: 2026-11-01 측정 중 잘못 복사된 임시 파일(삭제가 막혀 남음).',
        '',
        '## 5. 옛 사전 키',
        '',
        f'`leftover-keys.txt`({len(removable)}줄 = 옛 키 {keys["candidates"]} + 더 쓰이지 않는 `ux.` 키 {len(ux_unused)})의 키를 `src/i18n/ko.json` · `en.json`에서 함께 지웁니다(두 사전은 같은 키를 가져야 합니다, `dictionaries.test.ts`). 남기는 옛 키 {keys["named"]}개의 머리별 수: '
        + ', '.join(f'{head} {count}' for head, count in keys['namedByHead'].items())
        + '. 더 쓰이지 않는 `ux.` 키: '
        + (', '.join(f'`{key}`' for key in ux_unused) or '없음')
        + '. 셈이 못 보지만 쓰이는 `ux.` 키(손으로 확인해 남김): '
        + ', '.join(f'`{key}`({why})' for key, why in UX_KEPT.items())
        + '.',
        '',
        '```powershell',
        'python -c "import json,pathlib; d=pathlib.Path(\'src/i18n\'); k=set(pathlib.Path(r\'..\\..\\docs\\showcase\\ux-r1-검수\\I-10\\leftover-keys.txt\').read_text(encoding=\'utf-8\').split()); [ (p:=d/f\'{l}.json\').write_bytes((json.dumps({a:b for a,b in json.loads(p.read_text(encoding=\'utf-8\')).items() if a not in k}, ensure_ascii=False, indent=2)+\'\\n\').encode(\'utf-8\')) for l in (\'ko\',\'en\') ]"',
        '```',
        '',
        '## 6. 지운 뒤 확인',
        '',
        '```powershell',
        'npx tsc -b; npm run lint; npx vitest run; npm run build',
        'python scripts/font-subset.py   # 사전 글자가 줄었으므로 데모 글꼴을 다시 만듭니다',
        '```',
        '',
    ]
    (out / '사용자-정리목록.md').write_bytes(('\n'.join(lines)).encode('utf-8'))
    print('files', len(files), 'decide', len(decide), 'keys', keys['candidates'])


if __name__ == '__main__':
    main()
