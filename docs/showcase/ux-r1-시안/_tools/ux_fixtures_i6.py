"""Captures the I-6 scenario-validation fixtures from the real portal (GET only), trimmed to what the screens read.

    python -I -X utf8 ux_fixtures_i6.py
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


bench = get('/api/benchmark')
save('benchmark-full', bench)
setting = bench['spec']['settingHash']
save('benchmark-agent', get('/api/benchmark/agent'))
save('prompt-quality', get('/api/benchmark/prompt-quality'))
save('decision-quality', get(f'/api/benchmark/decision-quality?setting={setting}'))
cases = get('/api/cases')
save('cases', {**cases, 'cases': [{key: case[key] for key in ('key', 'version', 'title', 'protagonist', 'classification', 'steps',
                                                               'frozenOn', 'sha256', 'allowedActions', 'rationale', 'counterpoint')}
                                  for case in cases['cases']]})
print('setting', setting)
