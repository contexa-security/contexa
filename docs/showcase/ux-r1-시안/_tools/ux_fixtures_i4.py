"""Captures the I-4 screens' fixtures from the real portal (GET, and POST /api/rules/evaluate which only runs the
server's rule engine: no model is called, nothing is sent), trimmed to what the screens read.

    python -I -X utf8 ux_fixtures_i4.py
"""
import http.cookiejar
import json
import pathlib
import urllib.request

BASE = 'http://127.0.0.1:19180'
OUT = pathlib.Path('E:/projects/contexa/contexa-showcase/web/src/ux/test/fixtures')
OUT.mkdir(parents=True, exist_ok=True)
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def get(path):
    with opener.open(BASE + path, timeout=30) as response:
        return json.loads(response.read().decode('utf-8'))


def post(path, body):
    token = next((cookie.value for cookie in jar if cookie.name == 'XSRF-TOKEN'), None)
    request = urllib.request.Request(BASE + path, data=json.dumps(body).encode('utf-8'), method='POST', headers={
        'Content-Type': 'application/json', 'Accept': 'application/json', 'X-XSRF-TOKEN': token or ''})
    with opener.open(request, timeout=60) as response:
        return json.loads(response.read().decode('utf-8'))


def save(name, data):
    (OUT / f'{name}.test.json').write_bytes((json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(name, len(json.dumps(data)))


get('/api/visitor')

for key in ('T5', 'N1', 'M22A', 'M10A', 'M14A', 'ED1', 'M41A'):
    save(f'agent-case-{key}', get(f'/api/agent-cases/{key}'))

save('agent-run-t5-approve', get('/api/runs/run-d2ca817d4929/agent'))
n1 = get('/api/runs/run-297ce7886727/agent')
save('agent-run-n1', n1)
last = n1['steps'][-1]['stepNo']
save('anatomy-n1-last', get(f'/api/runs/run-297ce7886727/steps/{last}/anatomy'))
save('quality-n1-last', get(f'/api/runs/run-297ce7886727/steps/{last}/quality'))
save('facts-n1-last', get(f'/api/runs/run-297ce7886727/steps/{last}/facts'))

save('snapshot-t5-report', get('/api/agent-snapshots/T5-confirm-report'))
for burst in ('M41A', 'M41T', 'M41X'):
    for flights in ('on', 'off'):
        snap = get(f'/api/agent-snapshots/{burst}-flights-{flights}')
        # The screens read the summary and the run's id; the steps are long and unread here.
        snap['run'] = {**snap['run'], 'steps': []}
        save(f'snapshot-{burst.lower()}-{flights}', snap)

cases = get('/api/rules/cases')
defaults = cases['defaults']['settings']
# The screens read each case's key, kind and title, and each result's tallies and changes.
save('rules-cases', {**cases, 'cases': [{k: c[k] for k in ('scenario', 'classification', 'title')} for c in cases['cases']]})


def tallies(result):
    return {k: result[k] for k in ('tallies', 'changed') if k in result}


save('rules-default', tallies(post('/api/rules/evaluate', defaults)))
for value in (0, 50, 100, 200, 300, 400, 1000):
    save(f'rules-volume-{value}', tallies(post('/api/rules/evaluate', {**defaults, 'volumeLimit': value})))

menu = get('/api/agent-menu')
save('agent-menu', menu)
first = next(item for item in menu['items'] if item['choice'] is None)
answer = get(f"/api/agent-menu/{first['caseKey']}/{first['path']}")
answer['run'] = {**answer['run'], 'steps': answer['run']['steps'][:4]}
save('agent-menu-answer', answer)
print('menu answer', first['caseKey'], first['path'])

for key in ('A6', 'A6T'):
    measured = get(f'/api/cases/{key}/measured')
    save(f'measured-{key}', measured)
    run = measured['middleRun']
    trimmed = []
    for step in range(1, 6):
        anatomy = get(f'/api/runs/{run}/steps/{step}/anatomy')
        trimmed.append({'interpretation': {'recorded': {'finalAction': anatomy['interpretation']['recorded'].get('finalAction')}},
                        'figures': {'baselineBefore': anatomy.get('figures', {}).get('baselineBefore'),
                                    'baselineAfter': anatomy.get('figures', {}).get('baselineAfter')}})
    save(f'anatomies-{key}', {'runId': run, 'steps': trimmed})
    results = []
    for step in range(1, 6):
        result = get(f'/api/runs/{run}/steps/{step}/result')
        # The cell reads control D's outcome and whether an earlier decision answered it (evidence.timing).
        results.append({**result, 'layers': [layer for layer in result['layers'] if layer['control'] == 'D']})
    save(f'results-{key}', {'runId': run, 'steps': results})

# The I-4 real runs (2026-10-31 18:43~18:46 UTC): the live burst's own counts and the composed run's comparison.
burst = get('/api/runs/run-ba24973a7a9a/agent')
save('agent-run-burst', {**burst, 'steps': burst['steps'][:2]})
save('versus-lab', get('/api/runs/run-43bf870226e7/versus?against=run-2856ed7c3563'))
