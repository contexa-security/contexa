"""UX-R1 I-10 deletion list: the files the application reaches from src/main.tsx (static and dynamic imports, tests left
out) against every file under web/src, and the old files outside src/ux the new application still uses.

    python -X utf8 ux_reach.py <out.json> [--production]

A file nothing reaches (and that is not a test) is a deletion candidate; a test whose subject is a candidate goes with it.
With --production the count is the production bundle's: an import only the development server takes
(`import.meta.env.DEV ? … import('…')`) and a type-only import (`import type …`, erased by the compiler) are left out.
With --leftovers the count is what may be removed together: only the development server's imports are left out (the
old design pages, whose routes go with them), type-only imports count, and every test that imports a live file stays
live with everything it imports (its fixtures too). `leftoverFiles` then lists the files (tests included) nothing live
needs, so removing them all at once keeps the type check and the remaining tests whole.
"""
import json
import pathlib
import re
import sys

WEB = pathlib.Path('E:/projects/contexa/contexa-showcase/web')
SRC = WEB / 'src'
IMPORT = re.compile(r"""(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|import\s+['"]([^'"]+)['"]""")
ARGS = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
PRODUCTION = '--production' in sys.argv[1:]
LEFTOVERS = '--leftovers' in sys.argv[1:]
DEV_ONLY = re.compile(r"""import\.meta\.env\.DEV\s*\?[^:]*?import\(\s*['"][^'"]+['"]\s*\)""")
TYPE_ONLY = re.compile(r"""^\s*(?:import|export)\s+type\s[^;]*?from\s+['"][^'"]+['"];?""", re.MULTILINE)
EXTS = ['', '.ts', '.tsx', '.json', '.css', '/index.ts', '/index.tsx']


def is_test(path: pathlib.Path) -> bool:
    """A test, a test fixture or test infrastructure (a folder named test, the vitest setup)."""
    parts = path.relative_to(SRC).parts
    return '.test.' in path.name or 'test' in parts[:-1] or path.name in ('setupTests.ts', 'vitest.setup.ts')


def resolve(base: pathlib.Path, spec: str):
    spec = spec.split('?')[0]
    if not spec.startswith('.'):
        return None
    target = (base.parent / spec).resolve()
    for ext in EXTS:
        candidate = pathlib.Path(str(target) + ext)
        if candidate.is_file():
            return candidate
    return None


def imports(path: pathlib.Path):
    if path.suffix not in ('.ts', '.tsx'):
        return []
    text = path.read_text(encoding='utf-8')
    if PRODUCTION:
        text = TYPE_ONLY.sub('', DEV_ONLY.sub('', text))
    elif LEFTOVERS:
        text = DEV_ONLY.sub('', text)
    found = []
    for match in IMPORT.finditer(text):
        spec = next(group for group in match.groups() if group)
        resolved = resolve(path, spec)
        # Only the web's own sources count; a test may read a fixture of the portal.
        if resolved is not None and SRC in resolved.parents:
            found.append(resolved)
    return found


entry = [SRC / 'main.tsx']
seen = set()
stack = list(entry)
while stack:
    current = stack.pop()
    if current in seen:
        continue
    seen.add(current)
    for target in imports(current):
        if not is_test(target):
            stack.append(target)

every = [path for path in SRC.rglob('*') if path.is_file()]
rel = lambda path: path.relative_to(SRC).as_posix()
reached = sorted(rel(path) for path in seen)
unreached = sorted(rel(path) for path in every if path not in seen and not is_test(path))
tests = sorted(rel(path) for path in every if is_test(path) and path.suffix in ('.ts', '.tsx'))
# A test goes with the files it imports when every one it imports is unreached.
tests_with_candidates = []
for test in tests:
    targets = [rel(target) for target in imports(SRC / test)]
    local = [target for target in targets if not target.startswith('ux/test/')]
    if local and all(target in unreached for target in local):
        tests_with_candidates.append(test)
old_used = sorted(path for path in reached if not path.startswith('ux/'))
out = {
    'reached': reached,
    'oldUsedByNewApp': old_used,
    'unreached': unreached,
    'testsOfUnreached': tests_with_candidates,
}
if LEFTOVERS:
    # A test stays when it tests something live: its same-name subject is live, it imports a live file outside the shared
    # base (an old component's test also imports api · domain · i18n, which alone does not keep it), or it sits in the
    # shared base itself. A test that stays keeps everything it imports, transitively (its fixtures too).
    SHARED = ('api', 'domain', 'hooks', 'i18n', 'styles')

    def shared(path: pathlib.Path) -> bool:
        return rel(path).split('/')[0] in SHARED

    def subject_of(test: pathlib.Path):
        stem = test.name.split('.test.')[0]
        for ext in ('.ts', '.tsx'):
            candidate = test.with_name(stem + ext)
            if candidate.is_file():
                return candidate
        return None

    def tests_something_live(path: pathlib.Path) -> bool:
        # A test of a same-name file lives with that file. Without one, a test in the shared base lives, and any other
        # lives only when everything it imports (fixtures aside) is live: an old screen's test also imports live words
        # or content, which alone does not keep it (PolicyPage.test imports content/policies, which fontCoverage reads).
        subject = subject_of(path)
        if subject is not None:
            return subject in live
        if shared(path):
            return True
        local = [target for target in imports(path) if not is_test(target)]
        return bool(local) and all(target in live for target in local)

    live = set(seen)
    # The test setup the vitest config names (setupFiles) is read without an import.
    config = (WEB / 'vitest.config.ts').read_text(encoding='utf-8')
    for setup in re.findall(r"""setupFiles:\s*\[([^\]]*)\]""", config):
        for name in re.findall(r"""['"]\./([^'"]+)['"]""", setup):
            live.add(WEB / name)
    # The tests at the web root (outside src) import src files or read them by path ('src/…', a folder too). They are few,
    # so the old ones are named by hand with the reason; every other root test is live and keeps all it names.
    OLD_ROOT = {
        'benchPromptPhone.test.ts': "reads the old benchmark screen's CSS",
        'frameStyles.test.ts': "reads the old tokens, header and timing CSS",
        'factWordsSource.test.ts': 'checks the old factWords; its checks the new screens need are in factKeySource.test.ts',
        'sourceExcerpts.test.ts': "checks the old show screen's code excerpts; the new adopt screen shows none",
    }
    READ = re.compile(r"""['"`](src/[^'"`$]+?)['"`]""")

    def root_targets(test: pathlib.Path):
        found = set(imports(test))
        for name in READ.findall(test.read_text(encoding='utf-8')):
            path = WEB / name
            if path.is_dir():
                found.update(child for child in path.rglob('*') if child.is_file())
            elif path.is_file():
                found.add(path)
        return found

    root_tests = sorted(WEB.glob('*.test.ts'))
    old_root_tests = []
    for test in root_tests:
        targets = root_targets(test)
        if test.name in OLD_ROOT:
            old_root_tests.append(test)
            continue
        for target in targets:
            stack = [target]
            while stack:
                current = stack.pop()
                if current in live:
                    continue
                live.add(current)
                stack.extend(imports(current))
    changed = True
    while changed:
        changed = False
        for test in tests:
            path = SRC / test
            if path in live:
                continue
            if tests_something_live(path):
                stack = [path]
                while stack:
                    current = stack.pop()
                    if current in live:
                        continue
                    live.add(current)
                    changed = True
                    stack.extend(imports(current))
    # A declaration file (.d.ts) is read by the type check without any import, so it never counts as left over.
    out['leftoverFiles'] = sorted(rel(path) for path in every if path not in live and not path.name.endswith('.d.ts'))
    out['liveTests'] = sorted(rel(path) for path in live if is_test(path) and SRC in path.parents)
    out['leftoverRootTests'] = [test.name for test in old_root_tests]
    print('leftover files', len(out['leftoverFiles']), 'live tests', len(out['liveTests']))
pathlib.Path(ARGS[0]).write_bytes((json.dumps(out, ensure_ascii=False, indent=1) + '\n').encode('utf-8'))
print('reached', len(reached), 'old used by the new app', len(old_used), 'unreached', len(unreached),
      'tests of unreached', len(tests_with_candidates), 'tests', len(tests))
