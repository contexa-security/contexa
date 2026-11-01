"""UX-R1 I-10: the hand-over commit bundle — the files this work changed or added (since T0), in groups, with the
commands to stage each group. Nothing is staged or committed here; the user commits.

    python -X utf8 ux_commit_bundle.py <out.md>

A file counts when git reports it changed or untracked under the web app or the showcase docs and it was written after
T0 (2026-10-31 15:24 UTC). Files changed before T0 belong to earlier work and are listed apart, not in a group. Secrets,
the keys lock and scratch files never enter a group.
"""
import datetime
import pathlib
import subprocess
import sys

REPO = pathlib.Path('E:/projects/contexa')
T0 = datetime.datetime(2026, 10, 31, 15, 24, tzinfo=datetime.timezone.utc).timestamp()
SCOPES = ['contexa-showcase/web', 'contexa-showcase/showcase-portal', 'docs/showcase']
NEVER = ('APIKEY', 'ANTHROPIC_API_KEY', '.env', '.ux_keys.lock', '_wide_tmp.mjs', 'showcase.env', 'signing-key',
         'client-secret')
GROUPS = [
    ('웹 앱 소스(새 화면 · 공용 부품 · 시험)', lambda p: p.startswith('contexa-showcase/web/src/')),
    ('웹 앱 설정 · 루트 시험 · 공개 자원(글꼴 · 벤치마크 묶음)', lambda p: p.startswith('contexa-showcase/web/')),
    ('포털 코드 · 시험(DEC-85 · DEC-86 ①)', lambda p: p.startswith('contexa-showcase/showcase-portal/')),
    ('계획 · 판정 · 장부 문서', lambda p: p.startswith('docs/showcase/UX-R1-')),
    ('검수 기록(측정 · 대조 · 사진 · 정리 목록)', lambda p: p.startswith('docs/showcase/ux-r1-검수/')),
    ('검수 도구', lambda p: p.startswith('docs/showcase/ux-r1-시안/')),
    ('그 밖의 쇼케이스 문서', lambda p: p.startswith('docs/showcase/')),
]


def status():
    out = subprocess.run(['git', '-c', 'core.quotepath=false', 'status', '--porcelain', '-uall', '-z', '--', *SCOPES],
                         cwd=REPO, capture_output=True, check=True).stdout.decode('utf-8')
    for entry in filter(None, out.split('\0')):
        yield entry[:2], entry[3:]


def main():
    groups = {name: [] for name, _ in GROUPS}
    before, held = [], []
    for code, path in status():
        if any(mark in path for mark in NEVER):
            held.append(path)
            continue
        full = REPO / path
        if full.exists() and full.stat().st_mtime < T0:
            before.append(path)
            continue
        for name, test in GROUPS:
            if test(path):
                groups[name].append((code.strip() or '?', path))
                break
    total = sum(len(files) for files in groups.values())
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')
    lines = [
        '# UX-R1 커밋 묶음(사용자 커밋용)',
        '',
        f'만든 시각: {now} 세계 표준시. 만든 도구: `_tools/ux_commit_bundle.py`. 스테이징 · 커밋은 하지 않았습니다.',
        f'T0(2026-10-31 15:24 세계 표준시) 뒤에 바뀌거나 새로 생긴 파일 {total}개를 묶음별로 적습니다. 사용자 커밋 f1b230d57(2026-11-01 10:15 KST)에 이미 들어간 것은 git이 바뀌지 않은 것으로 보아 여기 없습니다.',
        '정리 목록(`사용자-정리목록.md`)의 삭제는 이 커밋과 따로 합니다.',
        '',
    ]
    for name, files in groups.items():
        if not files:
            continue
        lines += [f'## {name} ({len(files)})', '', '```powershell']
        lines += [f'git add -- "{path}"' for _, path in files]
        lines += ['```', '']
    lines += [
        '## 넣지 않는 것',
        '',
        f'- 비밀 · 잠금 · 임시 파일 {len(held)}개(이름만): ' + (', '.join(f'`{path}`' for path in held) or '없음'),
        f'- T0 전부터 커밋되지 않은 파일 {len(before)}개: 이번 작업 전의 변경이라 이 묶음에 넣지 않았습니다.',
        '',
        '## 커밋 문장 제안',
        '',
        '- 웹: `UX-R1 demo redesign: intro, live-demo menu, I-9 numbers on the frozen re-measure, I-10 fact restoration and layout fixes`',
        '- 문서: `UX-R1 plan, gates, cost ledger and I-9/I-10 inspection records`',
        '',
    ]
    pathlib.Path(sys.argv[1]).write_bytes('\n'.join(lines).encode('utf-8'))
    print('files', total, {name: len(files) for name, files in groups.items()}, 'held', len(held), 'before', len(before))


if __name__ == '__main__':
    main()
