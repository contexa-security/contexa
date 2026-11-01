"""Captures real portal answers (GET only) as the UX-R1 screen tests' fixtures, trimmed to what the screens read."""
import json
import pathlib
import urllib.request

BASE = 'http://127.0.0.1:19180'
OUT = pathlib.Path('E:/projects/contexa/contexa-showcase/web/src/ux/test/fixtures')
OUT.mkdir(parents=True, exist_ok=True)


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=20) as response:
        return json.loads(response.read().decode('utf-8'))


def save(name, data):
    (OUT / f'{name}.test.json').write_bytes((json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(name, len(json.dumps(data)))


hook = get('/api/hook')
save('hook', hook)
attacker = hook['attacker']['runId']
owner = hook['owner']['runId']

stats = get('/api/stats')
save('stats', stats)

live = get('/api/live/config')
save('live-config', live)

options = get('/api/lab/options')
keep = {'S13', 'S13T', 'S16'}
options['cases'] = [c for c in options['cases'] if c['key'] in keep]
options['employees'] = [e for e in options['employees'] if e['key'] == 'eng-k']
save('lab-options', options)

for key in ('S13', 'S13T', 'S16'):
    save(f'before-{key}', get(f'/api/live/before/{key}?step=1'))

for name, run in (('attacker', attacker), ('owner', owner)):
    anatomy = get(f'/api/runs/{run}/steps/1/anatomy')
    save(f'anatomy-{name}', anatomy)
    save(f'received-{name}', get(f'/api/runs/{run}/steps/1/received'))
    save(f'result-{name}', get(f'/api/runs/{run}/steps/1/result'))
    save(f'score-{name}', get(f'/api/runs/{run}/score'))
    save(f'quality-{name}', get(f'/api/runs/{run}/steps/1/quality'))
    save(f'facts-{name}', get(f'/api/runs/{run}/steps/1/facts'))
print('attacker', attacker, 'owner', owner)
