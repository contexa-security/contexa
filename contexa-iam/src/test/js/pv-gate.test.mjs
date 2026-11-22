// Quality plan 3.4 and the approved mockup (second round): what the confirmation of "use for decisions" and of a canary
// shows of the quality gate, as PV.gatePlan of the version screens' shared script computes it from the use check the
// server answers: the state, the rows left open and the rows folded by result, the link to the comparison of the two
// versions in place of the newly missed cases, the box to tick, the reason an override takes, and the way to measure a
// stale version again. Runs the script in a context of its own with the real messages of both languages.
// Run: node --test contexa-iam/src/test/js
// PV_COMMON=<path> runs it on another copy of the script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const SCRIPT = process.env.PV_COMMON
    ?? fileURLToPath(new URL('../../main/resources/static/contexa/js/admin/prompt-version/pv-common.js', import.meta.url));
const MESSAGES = {
    ko: fileURLToPath(new URL('../../main/resources/contexa/i18n/messages_ko.properties', import.meta.url)),
    en: fileURLToPath(new URL('../../main/resources/contexa/i18n/messages.properties', import.meta.url)),
};
const ROWS = ['COMPARABLE_MEASUREMENTS', 'MUST_CATCH_NEVER_ALLOWED', 'MUST_NOT_BLOCK_NEVER_BLOCKED', 'MISS_NOT_INCREASED',
    'STOPPING_NOT_INCREASED', 'MODEL_USED_AND_CITATIONS_ACCURATE', 'NO_NEWLY_MISSED_OR_STOPPED_CASES', 'ENOUGH_CASES',
    'NOT_WORSE_ON_LATER_CASES_ONLY'];

function words(language) {
    const map = {};
    for (const line of readFileSync(MESSAGES[language], 'utf8').split(/\r?\n/)) {
        const at = line.indexOf('=');
        if (!line || line.startsWith('#') || at < 0) {
            continue;
        }
        map[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
    return map;
}

/** The shared script of the version screens over the console's words and numbers, as console-common.js gives them. */
function load(language, search = '') {
    const messages = words(language);
    const t = (key, ...args) => {
        const text = messages[key];
        return text == null ? key
            : text.replace(/\{(\d+)\}/g, (match, index) => (args[index] == null ? '' : String(args[index])));
    };
    const ZT = {
        t,
        el: () => {
            throw new Error('the plan draws nothing');
        },
        count: value => (value == null ? '—' : new Intl.NumberFormat(language).format(value)),
        percent: (ratio, digits = 1) => (ratio == null ? '—'
            : new Intl.NumberFormat(language, {style: 'percent', maximumFractionDigits: digits}).format(ratio)),
        time: value => String(value),
    };
    const window = {ZT, location: {search, origin: 'http://localhost', pathname: '/contexa/admin/prompt-quality/versions'}};
    const context = vm.createContext({window, document: {getElementById: () => null, querySelector: () => null},
        URLSearchParams, URL, Intl});
    vm.runInContext(readFileSync(SCRIPT, 'utf8'), context);
    const PV = window.PV;
    // The plan is plain data: copied out of the script's context, it compares as this context's objects do.
    return {
        gatePlan: (given, kind) => {
            const plan = PV.gatePlan(given, kind);
            return plan == null ? plan : JSON.parse(JSON.stringify(plan));
        },
    };
}

function rate(metric, current, candidate, verdict = 'SAME', noise = 0.044) {
    return {metric, verdict, currentValue: current, candidateValue: candidate, difference: candidate - current,
        noiseWidth: noise, pairedCases: 70, pairedRoots: 35, worseRoots: 0, betterRoots: 0, worseProbability: null,
        betterProbability: null};
}

function row(condition, status, figures = {}, comparisons = [], cases = []) {
    return {condition, status, figures, comparisons, cases};
}

/** The nine rows of a candidate that passes everything, with the numbers the gate computes. */
function passedRows() {
    return [
        row('COMPARABLE_MEASUREMENTS', 'PASSED', {currentScoredAnswers: 70, candidateScoredAnswers: 70,
            sameCaseSetVersion: 1, sameModelSetting: 1, currentRepeats: 1, candidateRepeats: 1}),
        row('MUST_CATCH_NEVER_ALLOWED', 'PASSED', {gradedCases: 10, unmeasuredCases: 0, failedCases: 0, failedAnswers: 0}),
        row('MUST_NOT_BLOCK_NEVER_BLOCKED', 'PASSED', {gradedCases: 0, unmeasuredCases: 0, failedCases: 0, failedAnswers: 0}),
        row('MISS_NOT_INCREASED', 'PASSED', {worseRates: 0}, [rate('MISS', 14 / 55, 10 / 55)]),
        row('STOPPING_NOT_INCREASED', 'PASSED', {worseRates: 0}, [rate('FALSE_STOP', 0, 0), rate('OVER_BLOCK', 0, 0),
            rate('FRICTION', 10 / 15, 9 / 15), rate('DEFERRAL', 0, 1 / 70)]),
        row('MODEL_USED_AND_CITATIONS_ACCURATE', 'PASSED', {modelLessAnswers: 0, answers: 70, modelLessRate: 0,
            modelLessLimit: 0.05}, [rate('CITATION_ACCURACY', 0.728, 0.811)]),
        row('NO_NEWLY_MISSED_OR_STOPPED_CASES', 'PASSED', {newlyMissedCases: 0, newlyStoppedCases: 0}),
        row('ENOUGH_CASES', 'PASSED', {stopRoots: 212, stopRootsNeeded: 200, stopRootsShort: 0, allowRoots: 318,
            allowRootsNeeded: 300, allowRootsShort: 0, undecidableRates: 0, ratesWithoutNoise: 0}),
        row('NOT_WORSE_ON_LATER_CASES_ONLY', 'PASSED', {laterCases: 0, earlierCases: 70})];
}

function replaced(rows, changes) {
    return rows.map(item => (changes[item.condition] ? Object.assign({}, item, changes[item.condition]) : item));
}

/** The rows the gate could not look at: their numbers are not there. */
function notEvaluated(rows, conditions) {
    return replaced(rows, Object.fromEntries(conditions.map(condition => [condition,
        {status: 'NOT_EVALUATED', figures: {}, comparisons: [], cases: []}])));
}

const CHANGED_WARNS = {status: 'WARNING', figures: {newlyMissedCases: 1, newlyStoppedCases: 1}, cases: ['S11', 'A1T']};
const TOO_FEW = {status: 'WARNING', figures: {stopRoots: 25, stopRootsNeeded: 200, stopRootsShort: 175, allowRoots: 10,
    allowRootsNeeded: 300, allowRootsShort: 290, undecidableRates: 0, ratesWithoutNoise: 6}};
const MUST_CATCH_FAILS = {status: 'BLOCKED', figures: {gradedCases: 10, unmeasuredCases: 0, failedCases: 1,
    failedAnswers: 1}, cases: ['VER-A1T']};
const MISS_WORSE = {status: 'BLOCKED', figures: {worseRates: 1}, comparisons: [rate('MISS', 14 / 55, 23 / 55, 'WORSE', 0.055)]};

function quality(change) {
    return Object.assign({mode: 'WARN', measurement: 'MEASURED', measurementSides: [], measurementDetail: null,
        verdict: 'PASSED', applied: 'PASSED', rollback: false, overridable: false, rows: passedRows(),
        changes: {newlyMissed: [], newlyCaught: [], newlyStopped: [], newlyReleased: []}}, change);
}

function check(gate) {
    return {version: 'v2.0', current: 'v1.0', ready: gate == null || gate.applied !== 'BLOCKED', blockers: [],
        latestTrial: null, productPolicyGaps: [], quality: gate, outsideGate: null};
}

const conditions = rows => rows.map(item => item.condition);
const folded = plan => plan.folds.map(fold => [fold.status, fold.rows.length]);

/** No word of the plan is a message key the messages miss. */
function allWordsFound(plan) {
    assert.doesNotMatch(JSON.stringify(plan), /"pv\.|[ (]pv\.[a-z]/);
}

const ko = load('ko');

test('all nine passed: one line "9 passed" folds every row, nothing to tick, no reason', () => {
    const plan = ko.gatePlan(check(quality({})), 'use');

    assert.equal(plan.state, 'pass');
    assert.equal(plan.chip, 'GOOD');
    assert.equal(plan.label, '통과');
    assert.equal(plan.line, '아홉 조건을 모두 통과했습니다.');
    assert.deepEqual(plan.open, []);
    assert.deepEqual(folded(plan), [['PASSED', 9]]);
    assert.equal(plan.folds[0].label, '통과 9줄');
    assert.deepEqual(conditions(plan.folds[0].rows), ROWS);
    assert.equal(plan.override, false);
    assert.equal(plan.seen, false);
    assert.equal(plan.remeasure, null);
    assert.equal(plan.subhead, '품질 관문 · 경고 방식 · 반복 1회');
    assert.equal(plan.folds[0].rows[0].evidence, '같은 사례 묶음 판 · 같은 모델 설정 · 반복 1회 · 채점된 답 지금 판 70 · 후보 판 70');
    assert.equal(plan.folds[0].rows[3].evidence, '놓침 25.5% → 18.2% · 같음 (흔들림 폭 ±4.4%)');
    allWordsFound(plan);
});

test('going back to a version used before passes with no row: a rollback takes no quality condition', () => {
    const plan = ko.gatePlan(check(quality({rollback: true, measurement: null, verdict: 'NOT_EVALUATED', rows: [],
        changes: null})), 'use');

    assert.equal(plan.state, 'rollback');
    assert.equal(plan.chip, 'GOOD');
    assert.equal(plan.label, '통과(되돌리기)');
    assert.match(plan.line, /판정에 쓰인 적이 있는 판으로 돌아갑니다/);
    assert.deepEqual(plan.open, []);
    assert.deepEqual(plan.folds, []);
    allWordsFound(plan);
});

test('a warning: the warning rows open, the passed ones fold, the newly missed cases are a link to the comparison', () => {
    const plan = ko.gatePlan(check(quality({verdict: 'WARNING', applied: 'WARNING',
        rows: replaced(passedRows(), {NO_NEWLY_MISSED_OR_STOPPED_CASES: CHANGED_WARNS, ENOUGH_CASES: TOO_FEW})})), 'use');

    assert.equal(plan.state, 'warn');
    assert.equal(plan.chip, 'WARN');
    assert.equal(plan.line, '막는 조건은 없습니다. 경고 2건을 확인한 뒤 진행하십시오.');
    assert.deepEqual(conditions(plan.open), ['NO_NEWLY_MISSED_OR_STOPPED_CASES', 'ENOUGH_CASES']);
    assert.deepEqual(folded(plan), [['PASSED', 7]]);
    const changed = plan.open[0];
    assert.deepEqual(changed.compare, {href: '/contexa/admin/prompt-quality/measure/compare?candidate=2&reference=1',
        label: '새로 놓친 사례 1건 보기'});
    assert.equal(changed.cases, null, 'the newly missed cases are not listed in the confirmation');
    assert.equal(changed.evidence, '새로 놓친 사례 1건 · 새로 멈춘 사례 1건');
    assert.equal(plan.open[1].evidence, '판단 불가: 멈춰야 할 뿌리 25 / 200 · 허용해야 할 뿌리 10 / 300 · 흔들림을 모르는 지표 6개');
    assert.equal(plan.seen, true);
    assert.equal(plan.override, false);
    allWordsFound(plan);
});

test('blocked: only the blocking rows open, the warnings fold into "N warnings", and a reason overrides it', () => {
    const rows = replaced(passedRows(), {MUST_CATCH_NEVER_ALLOWED: MUST_CATCH_FAILS, MISS_NOT_INCREASED: MISS_WORSE,
        NO_NEWLY_MISSED_OR_STOPPED_CASES: {status: 'WARNING', figures: {newlyMissedCases: 10, newlyStoppedCases: 0}},
        ENOUGH_CASES: TOO_FEW});
    const plan = ko.gatePlan(check(quality({mode: 'BLOCK', verdict: 'BLOCKED', applied: 'BLOCKED', overridable: true,
        rows})), 'use');

    assert.equal(plan.state, 'block');
    assert.equal(plan.chip, 'BAD');
    assert.equal(plan.line, '막는 조건 2건에 걸렸습니다. 사유를 적으면 넘길 수 있고, 누가 왜 넘겼는지 감사 기록에 남습니다.');
    assert.deepEqual(conditions(plan.open), ['MUST_CATCH_NEVER_ALLOWED', 'MISS_NOT_INCREASED']);
    assert.deepEqual(folded(plan), [['WARNING', 2], ['PASSED', 5]]);
    assert.equal(plan.folds[0].label, '경고 2줄');
    assert.equal(plan.open[0].evidence, '반드시 잡을 사례 10건 가운데 허용 1건(답 1개)');
    assert.equal(plan.open[0].cases, '사례 VER-A1T');
    assert.equal(plan.open[1].evidence, '놓침 25.5% → 41.8% · 나빠짐 (흔들림 폭 ±5.5%)');
    assert.equal(plan.folds[0].rows[0].compare.label, '새로 놓친 사례 10건 보기');
    assert.equal(plan.override, true);
    assert.equal(plan.seen, false, 'the reason stands for the reading of the cases');
    assert.equal(plan.subhead, '품질 관문 · 막기 방식 · 반복 1회');
    allWordsFound(plan);
});

test('blocked by something besides quality: no reason lets it through', () => {
    const plan = ko.gatePlan(check(quality({mode: 'BLOCK', verdict: 'BLOCKED', applied: 'BLOCKED', overridable: false,
        rows: replaced(passedRows(), {MUST_CATCH_NEVER_ALLOWED: MUST_CATCH_FAILS})})), 'canary');

    assert.equal(plan.kind, 'canary');
    assert.equal(plan.override, false);
    assert.equal(plan.line, '막는 조건 1건에 걸렸습니다. 품질 밖의 막는 사유가 있어 사유를 적어도 넘길 수 없습니다.');
    allWordsFound(plan);
});

test('the warning mode applies a blocked verdict as a warning, and says so; the blocking and warning rows open', () => {
    const rows = replaced(passedRows(), {MUST_CATCH_NEVER_ALLOWED: MUST_CATCH_FAILS, MISS_NOT_INCREASED: MISS_WORSE,
        NO_NEWLY_MISSED_OR_STOPPED_CASES: CHANGED_WARNS, ENOUGH_CASES: TOO_FEW});
    const plan = ko.gatePlan(check(quality({mode: 'WARN', verdict: 'BLOCKED', applied: 'WARNING', rows})), 'use');

    assert.equal(plan.state, 'warn');
    assert.equal(plan.chip, 'WARN');
    assert.equal(plan.line, '막는 조건 2건에 걸렸습니다. 관문이 경고 방식이라 막는 조건 2건도 경고로 적용됩니다.');
    assert.deepEqual(conditions(plan.open), ['MUST_CATCH_NEVER_ALLOWED', 'MISS_NOT_INCREASED',
        'NO_NEWLY_MISSED_OR_STOPPED_CASES', 'ENOUGH_CASES']);
    assert.deepEqual(plan.open.map(item => item.status), ['BLOCKED', 'BLOCKED', 'WARNING', 'WARNING']);
    assert.deepEqual(folded(plan), [['PASSED', 5]]);
    assert.equal(plan.override, false);
    assert.equal(plan.seen, true);
    allWordsFound(plan);
});

test('no measurement of the candidate: the first row blocks, the rows not looked at fold, a reason overrides it', () => {
    const rows = notEvaluated(replaced(passedRows(), {COMPARABLE_MEASUREMENTS: {status: 'BLOCKED',
        figures: {currentScoredAnswers: 70, candidateScoredAnswers: 0}}}), ROWS.slice(1));
    const plan = ko.gatePlan(check(quality({mode: 'BLOCK', measurement: 'MISSING', measurementSides: ['CANDIDATE'],
        measurementDetail: 'MEASURING', verdict: 'BLOCKED', applied: 'BLOCKED', overridable: true, rows})), 'use');

    assert.equal(plan.state, 'missing');
    assert.equal(plan.label, '측정 없음');
    assert.equal(plan.line, '후보 판 v2.0 을 잰 측정이 없습니다. 측정이 줄에 있거나 도는 중입니다. 사유를 적으면 넘길 수 있고,'
        + ' 누가 왜 넘겼는지 감사 기록에 남습니다.');
    assert.deepEqual(conditions(plan.open), ['COMPARABLE_MEASUREMENTS']);
    assert.equal(plan.open[0].evidence, '후보 판 v2.0 을 잰 측정이 없습니다.');
    assert.deepEqual(folded(plan), [['NOT_EVALUATED', 8]]);
    assert.equal(plan.folds[0].label, '보지 못함 8줄');
    assert.equal(plan.folds[0].rows[0].evidence, '측정 뒤에 견줍니다');
    assert.equal(plan.folds[0].rows[0].chip, null);
    assert.equal(plan.folds[0].rows[0].result, '보지 못함');
    assert.equal(plan.override, true);
    allWordsFound(plan);
});

test('an installation that cannot measure warns only: every row folds as not looked at, with why', () => {
    const plan = ko.gatePlan(check(quality({measurement: 'UNMEASURABLE', measurementDetail: 'NO_MEASUREMENT_RUNNER',
        verdict: 'NOT_EVALUATED', applied: 'WARNING', rows: notEvaluated(passedRows(), ROWS)})), 'use');

    assert.equal(plan.state, 'unmeasurable');
    assert.equal(plan.chip, 'WARN');
    assert.equal(plan.label, '측정 불능');
    assert.equal(plan.line, '이 설치에서는 재현을 돌릴 수 없어 잴 수 없습니다. "미달"이 아니며 경고만 합니다.'
        + ' 이 앱에는 판정을 다시 돌려 잴 실행기가 없습니다.');
    assert.deepEqual(plan.open, []);
    assert.deepEqual(folded(plan), [['NOT_EVALUATED', 9]]);
    assert.equal(plan.folds[0].rows[0].evidence, '잴 수 없음');
    assert.equal(plan.override, false);
    allWordsFound(plan);
});

test('the version in use waits for its first measurement: row 1 warns as the gate applies it, and no override', () => {
    const rows = notEvaluated(replaced(passedRows(), {COMPARABLE_MEASUREMENTS: {status: 'BLOCKED',
        figures: {currentScoredAnswers: 0, candidateScoredAnswers: 70}}, ENOUGH_CASES: TOO_FEW}),
    ['MISS_NOT_INCREASED', 'STOPPING_NOT_INCREASED', 'MODEL_USED_AND_CITATIONS_ACCURATE', 'NO_NEWLY_MISSED_OR_STOPPED_CASES']);
    const plan = ko.gatePlan(check(quality({measurement: 'BASELINE_PENDING', measurementSides: ['CURRENT'],
        measurementDetail: 'MEASURING', verdict: 'BLOCKED', applied: 'WARNING', rows})), 'use');

    assert.equal(plan.state, 'pending');
    assert.equal(plan.label, '기준 판 측정 대기');
    assert.equal(plan.line, '지금 쓰는 판 v1.0 의 측정이 아직 없습니다. 자동으로 한 번 재는 중이며, 그 전에는 경고만 합니다.'
        + ' 측정이 줄에 있거나 도는 중입니다.');
    assert.deepEqual(conditions(plan.open), ['COMPARABLE_MEASUREMENTS', 'ENOUGH_CASES']);
    assert.deepEqual(plan.open.map(item => item.status), ['WARNING', 'WARNING']);
    assert.equal(plan.open[0].evidence, '기준 판 v1.0 측정 대기 중');
    assert.deepEqual(folded(plan), [['NOT_EVALUATED', 4], ['PASSED', 3]]);
    assert.equal(plan.folds[0].rows[0].evidence, '기준 판 측정 뒤에 견줍니다');
    assert.equal(plan.override, false);
    allWordsFound(plan);
});

test('a stale measurement asks for the version to be measured again, unless it is being measured', () => {
    const rows = notEvaluated(replaced(passedRows(), {COMPARABLE_MEASUREMENTS: {status: 'BLOCKED',
        figures: {currentScoredAnswers: 70, candidateScoredAnswers: 70, sameCaseSetVersion: 1, sameModelSetting: 0,
            currentRepeats: 1, candidateRepeats: 1}}, ENOUGH_CASES: TOO_FEW}),
    ['MISS_NOT_INCREASED', 'STOPPING_NOT_INCREASED', 'MODEL_USED_AND_CITATIONS_ACCURATE', 'NO_NEWLY_MISSED_OR_STOPPED_CASES']);
    const stale = quality({mode: 'BLOCK', measurement: 'STALE', measurementSides: ['CURRENT'], verdict: 'BLOCKED',
        applied: 'BLOCKED', overridable: true, rows});
    const plan = ko.gatePlan(check(stale), 'use');

    assert.equal(plan.state, 'stale');
    assert.equal(plan.label, '측정이 낡음');
    assert.match(plan.line, /^모델 설정이 바뀌어 지금 판 v1\.0 의 측정이 낡았습니다\. 다시 재야 견줄 수 있습니다\./);
    assert.deepEqual(conditions(plan.open), ['COMPARABLE_MEASUREMENTS']);
    assert.equal(plan.open[0].evidence, '지금 판 v1.0 의 측정은 이전 모델 설정의 것입니다');
    assert.deepEqual(folded(plan), [['WARNING', 1], ['NOT_EVALUATED', 4], ['PASSED', 3]]);
    assert.equal(plan.folds[1].rows[0].evidence, '다시 잰 뒤에 견줍니다');
    assert.equal(plan.remeasure, '/contexa/admin/prompt-quality/measure?candidate=1');
    assert.equal(ko.gatePlan(check(Object.assign({}, stale, {measurementDetail: 'MEASURING'})), 'use').remeasure, null);
    allWordsFound(plan);
});

test('the links keep the scope of the page; a prompt without a quality gate has no plan', () => {
    const scoped = load('ko', '?scope=tenant-a&prompt=cortex.security-decision');
    const plan = scoped.gatePlan(check(quality({verdict: 'WARNING', applied: 'WARNING',
        rows: replaced(passedRows(), {NO_NEWLY_MISSED_OR_STOPPED_CASES: CHANGED_WARNS})})), 'use');

    assert.equal(plan.open[0].compare.href, '/contexa/admin/prompt-quality/measure/compare'
        + '?prompt=cortex.security-decision&scope=tenant-a&candidate=2&reference=1');
    assert.equal(scoped.gatePlan(check(null), 'use'), null);
});

test('in English: the words of the same warning', () => {
    const en = load('en');
    const plan = en.gatePlan(check(quality({verdict: 'WARNING', applied: 'WARNING',
        rows: replaced(passedRows(), {NO_NEWLY_MISSED_OR_STOPPED_CASES: CHANGED_WARNS, ENOUGH_CASES: TOO_FEW})})), 'use');

    assert.equal(plan.label, 'Warning');
    assert.equal(plan.line, 'Nothing blocks it. Read the warnings (2) before you go on.');
    assert.equal(plan.folds[0].label, '7 passed');
    assert.equal(plan.open[0].compare.label, 'Show the 1 newly missed cases');
    assert.equal(plan.subhead, 'Quality gate · warning mode · runs: 1');
    allWordsFound(plan);
});
