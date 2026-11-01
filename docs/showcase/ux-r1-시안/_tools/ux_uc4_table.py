"""UX-R1 I-10 UC-4: the old screens' behaviours (완료판정기준 UC-4) by their run states (구현계획서 9절 ST-n), and the new
screens' tests that name each state in their title, as a Markdown table.

    python -X utf8 ux_uc4_table.py <out.md>

A state no test names is listed as such; it is then checked by hand (a test may cover it without naming it).
"""
import pathlib
import re
import sys

UX = pathlib.Path('E:/projects/contexa/contexa-showcase/web/src/ux')
PLAN = pathlib.Path('E:/projects/contexa/docs/showcase/UX-R1-구현계획서.md')
BEHAVIOURS = [
    ('사람 확인(턴스타일)', [1, 2]),
    ('하루 할당 거절 · 일시 중지', [3, 4, 21, 22]),
    ('앞선 실행 대기 뒤 자동 전송 · 대기열', [6, 7]),
    ('추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제', [9, 10, 11, 12, 13, 14, 15]),
    ('위임자 확인 승인 · 거절 · 응답 없이 끝남(신고는 저장된 실행으로 보임, DEC-26)', [24, 25, 26]),
    ('실행 실패 · 만료 · 판정 없음', [16, 17]),
]
TEST_TITLE = re.compile(r"""\bit(?:\.each\(\[(?:[^\[\]]|\[[^\[\]]*\])*\]\))?\(\s*(['"`])((?:(?!\1)[^\n])*)\1""")


def main():
    names = {}
    for line in PLAN.read_text(encoding='utf-8').splitlines():
        match = re.match(r'\| ST-(\d+) \| ([^|]+) \|', line)
        if match:
            names[int(match.group(1))] = match.group(2).strip()
    found = {}
    for path in sorted(UX.rglob('*.test.ts*')):
        source = path.read_text(encoding='utf-8')
        # Titles over several lines too (an it.each table before its title).
        for title in TEST_TITLE.finditer(source):
            number = source.count('\n', 0, title.start(2)) + 1
            text = title.group(2)
            states = {int(st) for st in re.findall(r'ST-(\d+)', text)}
            # A range in a title (ST-2~ST-5) names every state in it.
            for low, high in re.findall(r'ST-(\d+)\s*~\s*(?:ST-)?(\d+)', text):
                states.update(range(int(low), int(high) + 1))
            if 'DEC-26' in text:
                found.setdefault('DEC-26', []).append(f'`{path.relative_to(UX.parent.parent).as_posix()}:{number}`')
            for st in sorted(states):
                found.setdefault(st, []).append(f'`{path.relative_to(UX.parent.parent).as_posix()}:{number}`')
    rows = ['| 옛 동작 | 상태(9절) | 새 화면 시험(제목에 상태 번호) |', '|---|---|---|']
    missing = []
    for behaviour, states in BEHAVIOURS:
        for st in states:
            tests = found.get(st, [])
            if not tests:
                missing.append(st)
            rows.append(f"| {behaviour} | ST-{st} {names.get(st, '')} | {' · '.join(tests) if tests else '제목에 없음(손으로 확인)'} |")
    report = found.get('DEC-26', [])
    rows.append(
        '| 위임자 신고 | DEC-26: 방문자는 승인 · 거절로 답하고, 신고는 저장된 실제 실행(T5-confirm-report)으로 보인다 | '
        + (' · '.join(report) if report else '제목에 없음(손으로 확인)')
        + ' |'
    )
    text = '\n'.join([
        '# UC-4 옛 동작 대조표',
        '',
        '만든 도구: `_tools/ux_uc4_table.py`. 시험 제목에 상태 번호(ST-n)가 붙은 새 화면 시험을 찾는다. 경로는 `contexa-showcase/web` 기준.',
        '',
        *rows,
        '',
        f"제목에 없는 상태: {', '.join(f'ST-{st}' for st in missing) if missing else '없음'}",
        '',
    ])
    pathlib.Path(sys.argv[1]).write_bytes(text.encode('utf-8'))
    print('states', sum(len(states) for _, states in BEHAVIOURS), 'missing', missing)


if __name__ == '__main__':
    main()
