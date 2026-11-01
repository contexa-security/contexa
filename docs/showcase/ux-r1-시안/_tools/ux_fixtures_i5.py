"""Captures the I-5 screens' fixtures from the real portal (GET only), trimmed to what the screens read.

    python -I -X utf8 ux_fixtures_i5.py
"""
import json
import pathlib
import urllib.request

BASE = 'http://127.0.0.1:19180'
OUT = pathlib.Path('E:/projects/contexa/contexa-showcase/web/src/ux/test/fixtures')


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        return json.loads(response.read().decode('utf-8'))


def save(name, data):
    (OUT / f'{name}.test.json').write_bytes((json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(name, len(json.dumps(data)))


hook = get('/api/hook')
attacker = hook['attacker']['runId']

# The decision log: four measured runs (two attacks, two normal), the pairs and the recorded replay.
runs = get('/api/benchmark/runs')
threats = [run for run in runs['runs'] if run['truth']['classification'] == 'THREAT'][:2]
normals = [run for run in runs['runs'] if run['truth']['classification'] == 'NORMAL'][:2]
save('benchmark-runs', {'settingHash': runs['settingHash'], 'runs': threats + normals})
save('pairs', get('/api/pairs'))
replay = get('/api/replays/A3')
save('replay-A3', {'key': replay['key'], 'question': replay['question'],
                   'scenes': [{'runId': scene['runId'], 'recordedAt': scene['recordedAt']} for scene in replay['scenes']]})

# The decision details of the public recorded run: the model exchange (the others are I-3's fixtures).
save('exchanges-attacker', get(f'/api/runs/{attacker}/steps/1/exchanges'))

# The engine and the comparison.
bench = get('/api/benchmark')
save('benchmark', {
    'scope': bench['scope'],
    'controls': bench['controls'],
    'cases': [{'key': case['key'], 'classification': case['classification'], 'runResults': case.get('runResults', {})}
              for case in bench['cases']],
})
save('settings', get('/api/settings'))
baseline = get('/api/live/baseline/eng-k')
save('baseline-eng-k', {**baseline, 'requests': baseline['requests'][:2]})
save('engine-actions', get('/api/engine/actions'))
for key in ('A3', 'A3A'):
    save(f'measured-{key}', get(f'/api/cases/{key}/measured'))
print('attacker', attacker)
