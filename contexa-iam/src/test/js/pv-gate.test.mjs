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
const ROWS = ['COMPARABLE_MEASUREMENTS', 'MUST_CATCH_NEVER_ALLOWED', 'MUST_CATCH_NOT_WEAKENED',
    'MUST_NOT_BLOCK_NEVER_BLOCKED', 'MISS_NOT_INCREASED', 'STOPPING_NOT_INCREASED', 'FRICTION_INCREASE_WITHIN_LIMIT',
    'MODEL_USED_AND_CITATIONS_ACCURATE', 'NO_NEWLY_MISSED_OR_STOPPED_CASES', 'ENOUGH_CASES',
    'NOT_WORSE_ON_LATER_CASES_ONLY'];
/** The rows that read the comparison of the two versions, which a missing or stale measurement does not give. */
const COMPARED_ROWS = ['MISS_NOT_INCREASED', 'STOPPING_NOT_INCREASED', 'FRICTION_INCREASE_WITHIN_LIMIT',
    'MODEL_USED_AND_CITATIONS_ACCURATE', 'NO_NEWLY_MISSED_OR_STOPPED_CASES'];

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

/** The rows of a candidate that passes everything, with the numbers the gate computes. */
function passedRows() {
    return [
        row('COMPARABLE_MEASUREMENTS', 'PASSED', {currentScoredAnswers: 70, candidateScoredAnswers: 70,
            sameCaseSetVersion: 1, sameModelSetting: 1, currentRepeats: 1, candidateRepeats: 1}),
        row('MUST_CATCH_NEVER_ALLOWED', 'PASSED', {gradedCases: 10, unmeasuredCases: 0, failedCases: 0, failedAnswers: 0}),
        row('MUST_CATCH_NOT_WEAKENED', 'PASSED', {gradedCases: 10, unmeasuredCases: 0, weakenedCases: 0, weakenedAnswers: 0,
            currentAlsoOutsideCases: 0, comparedWithCurrent: 1}),
        row('MUST_NOT_BLOCK_NEVER_BLOCKED', 'PASSED', {gradedCases: 0, unmeasuredCases: 0, failedCases: 0, failedAnswers: 0}),
        row('MISS_NOT_INCREASED', 'PASSED', {worseRates: 0}, [rate('MISS', 14 / 55, 10 / 55)]),
        row('STOPPING_NOT_INCREASED', 'PASSED', {worseRates: 0}, [rate('FALSE_STOP', 0, 0), rate('OVER_BLOCK', 0, 0),
            rate('FRICTION', 10 / 15, 9 / 15), rate('DEFERRAL', 0, 1 / 70)]),
        row('FRICTION_INCREASE_WITHIN_LIMIT', 'PASSED', {pairedCases: 15, currentRate: 10 / 15, candidateRate: 9 / 15,
            increase: -1 / 15, limit: 0.3, newlyStoppedCases: 0}, [rate('FRICTION', 10 / 15, 9 / 15)]),
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
/** Quality P35: the ten control cases the version in use blocks, all challenged by the candidate. */
const CONTROLS = ['VER-A1T', 'VER-S01', 'VER-S02', 'VER-K2', 'VER-A5T', 'VER-S03', 'VER-A3', 'VER-A6', 'VER-A1', 'VER-S04'];
const CONTROLS_WEAKENED = {status: 'BLOCKED', figures: {gradedCases: 10, unmeasuredCases: 0, weakenedCases: 10,
    weakenedAnswers: 10, currentAlsoOutsideCases: 0, comparedWithCurrent: 1}, cases: CONTROLS};

/** What the use check reads beside the verdict, as the store of measurements has it. */
const DETAILS = {caseSetVersion: '3ccbfed8b2f4a1c9', models: 'qwen3:8b', modelsBefore: null, modelsNow: 'qwen3:8b',
    measuring: null, caseNames: [{key: 'VER-A1T', name: 'GET /api/documents/HX-310-DWG-00004 (VER-A1T)'}]};

function details(change) {
    return Object.assign({}, DETAILS, change);
}

function quality(change) {
    return Object.assign({mode: 'WARN', measurement: 'MEASURED', measurementSides: [], measurementDetail: null,
        verdict: 'PASSED', applied: 'PASSED', rollback: false, overridable: false, rows: passedRows(),
        changes: {newlyMissed: [], newlyCaught: [], newlyStopped: [], newlyReleased: []}, details: DETAILS}, change);
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

test('all passed: one line "N passed" folds every row, nothing to tick, no reason', () => {
    const plan = ko.gatePlan(check(quality({})), 'use');

    assert.equal(plan.state, 'pass');
    assert.equal(plan.chip, 'GOOD');
    assert.equal(plan.label, '통과');
    assert.equal(plan.line, `조건 ${ROWS.length}개를 모두 통과했습니다.`);
    assert.deepEqual(plan.open, []);
    assert.deepEqual(folded(plan), [['PASSED', ROWS.length]]);
    assert.equal(plan.folds[0].label, `통과 ${ROWS.length}줄`);
    assert.deepEqual(conditions(plan.folds[0].rows), ROWS);
    assert.equal(plan.override, false);
    assert.equal(plan.seen, false);
    assert.equal(plan.remeasure, null);
    assert.equal(plan.subhead, '품질 관문 · 사례 묶음 3ccbfed8 · qwen3:8b · 1회');
    assert.equal(plan.modeTip, '경고 방식: 경고 방식에서는 막는 조건도 경고만 합니다.'
        + ' 설정 contexa.pqa.oss.quality.gate.mode 로 막기 방식으로 바꿀 수 있습니다.');
    assert.equal(plan.folds[0].rows[0].evidence, 'v1.0 과 v2.0 · 사례 묶음 3ccbfed8 · qwen3:8b · 1회');
    assert.equal(plan.folds[0].rows[2].evidence, '반드시 잡을 사례 10건 가운데 허용 조치 밖으로 새로 답한 사례 0건(답 0개)');
    assert.equal(plan.folds[0].rows[ROWS.indexOf('MISS_NOT_INCREASED')].evidence,
        '놓침 25.5% → 18.2% · 같음 (흔들림 폭 ±4.4%)');
    assert.equal(plan.folds[0].rows[ROWS.indexOf('FRICTION_INCREASE_WITHIN_LIMIT')].evidence,
        '마찰 66.7% → 60% · 늘지 않음(상한 30%p)');
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
    assert.deepEqual(folded(plan), [['PASSED', ROWS.length - 2]]);
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
    assert.deepEqual(folded(plan), [['WARNING', 2], ['PASSED', ROWS.length - 4]]);
    assert.equal(plan.folds[0].label, '경고 2줄');
    assert.equal(plan.open[0].evidence, '반드시 잡을 사례 10건 가운데 허용 1건(답 1개)');
    assert.deepEqual(plan.open[0].cases, {names: ['GET /api/documents/HX-310-DWG-00004 (VER-A1T)'], more: null});
    assert.equal(plan.open[1].evidence, '놓침 25.5% → 41.8% · 나빠짐 (흔들림 폭 ±5.5%)');
    assert.equal(plan.folds[0].rows[0].compare.label, '새로 놓친 사례 10건 보기');
    assert.equal(plan.override, true);
    assert.equal(plan.seen, false, 'the reason stands for the reading of the cases');
    assert.equal(plan.subhead, '품질 관문 · 사례 묶음 3ccbfed8 · qwen3:8b · 1회');
    assert.match(plan.modeTip, /^막기 방식: /);
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

test('the warning mode applies a blocked verdict as a warning and says so; as the verdict blocks, the blocking rows'
    + ' alone open and the warnings fold', () => {
    const rows = replaced(passedRows(), {MUST_CATCH_NEVER_ALLOWED: MUST_CATCH_FAILS, MISS_NOT_INCREASED: MISS_WORSE,
        NO_NEWLY_MISSED_OR_STOPPED_CASES: CHANGED_WARNS, ENOUGH_CASES: TOO_FEW});
    const plan = ko.gatePlan(check(quality({mode: 'WARN', verdict: 'BLOCKED', applied: 'WARNING', rows})), 'use');

    assert.equal(plan.state, 'warn');
    assert.equal(plan.chip, 'WARN');
    assert.equal(plan.line, '막는 조건 2건에 걸렸습니다. 관문이 경고 방식이라 막는 조건 2건도 경고로 적용됩니다.');
    assert.deepEqual(conditions(plan.open), ['MUST_CATCH_NEVER_ALLOWED', 'MISS_NOT_INCREASED']);
    assert.deepEqual(plan.open.map(item => item.status), ['BLOCKED', 'BLOCKED']);
    assert.deepEqual(folded(plan), [['WARNING', 2], ['PASSED', ROWS.length - 4]]);
    assert.equal(plan.folds[0].rows[0].compare.label, '새로 놓친 사례 1건 보기');
    assert.equal(plan.override, false);
    assert.equal(plan.seen, false, 'the newly missed cases fold with the warnings');
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
    assert.deepEqual(folded(plan), [['NOT_EVALUATED', ROWS.length - 1]]);
    assert.equal(plan.folds[0].label, `보지 못함 ${ROWS.length - 1}줄`);
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
    assert.deepEqual(folded(plan), [['NOT_EVALUATED', ROWS.length]]);
    assert.equal(plan.folds[0].rows[0].evidence, '잴 수 없음');
    assert.equal(plan.override, false);
    allWordsFound(plan);
});

test('the version in use waits for its first measurement: row 1 warns as the gate applies it, and no override', () => {
    const rows = notEvaluated(replaced(passedRows(), {COMPARABLE_MEASUREMENTS: {status: 'BLOCKED',
        figures: {currentScoredAnswers: 0, candidateScoredAnswers: 70}}, ENOUGH_CASES: TOO_FEW}), COMPARED_ROWS);
    const plan = ko.gatePlan(check(quality({measurement: 'BASELINE_PENDING', measurementSides: ['CURRENT'],
        measurementDetail: 'MEASURING', verdict: 'BLOCKED', applied: 'WARNING', rows,
        details: details({measuring: {version: 'v1.0', answered: 126, planned: 210}})})), 'use');

    assert.equal(plan.state, 'pending');
    assert.equal(plan.label, '기준 판 측정 대기');
    assert.equal(plan.line, '지금 쓰는 판 v1.0 의 측정이 아직 없습니다. 자동으로 한 번 재는 중이며(126 / 210답), 그 전에는'
        + ' 경고만 합니다.');
    assert.deepEqual(conditions(plan.open), ['COMPARABLE_MEASUREMENTS', 'ENOUGH_CASES']);
    assert.deepEqual(plan.open.map(item => item.status), ['WARNING', 'WARNING']);
    assert.equal(plan.open[0].evidence, '기준 판 v1.0 측정 중 126 / 210답 · 후보 판 v2.0 끝남');
    assert.deepEqual(folded(plan), [['NOT_EVALUATED', COMPARED_ROWS.length],
        ['PASSED', ROWS.length - 2 - COMPARED_ROWS.length]]);
    assert.equal(plan.folds[0].rows[0].evidence, '기준 판 측정 뒤에 견줍니다');
    assert.equal(plan.override, false);
    allWordsFound(plan);
});

test('a stale measurement asks for the version to be measured again, unless it is being measured', () => {
    const rows = notEvaluated(replaced(passedRows(), {COMPARABLE_MEASUREMENTS: {status: 'BLOCKED',
        figures: {currentScoredAnswers: 70, candidateScoredAnswers: 70, sameCaseSetVersion: 1, sameModelSetting: 0,
            currentRepeats: 1, candidateRepeats: 1}}, ENOUGH_CASES: TOO_FEW}), COMPARED_ROWS);
    const stale = quality({mode: 'BLOCK', measurement: 'STALE', measurementSides: ['CURRENT'], verdict: 'BLOCKED',
        applied: 'BLOCKED', overridable: true, rows, details: details({modelsBefore: 'qwen3:8b', modelsNow: 'qwen3:14b'})});
    const plan = ko.gatePlan(check(stale), 'use');

    assert.equal(plan.state, 'stale');
    assert.equal(plan.label, '측정이 낡음');
    assert.match(plan.line, /^모델 설정이 바뀌어\(qwen3:8b → qwen3:14b\) 지금 판 v1\.0 의 측정이 낡았습니다\. 다시 재야 견줄 수/);
    assert.deepEqual(conditions(plan.open), ['COMPARABLE_MEASUREMENTS']);
    assert.equal(plan.open[0].evidence, '지금 판 v1.0 의 측정은 이전 모델 설정(qwen3:8b)의 것입니다');
    // Without the details the confirmation says the same without the models.
    const bare = ko.gatePlan(check(Object.assign({}, stale, {details: null})), 'use');
    assert.match(bare.line, /^모델 설정이 바뀌어 지금 판 v1\.0 의 측정이 낡았습니다\./);
    assert.equal(bare.open[0].evidence, '지금 판 v1.0 의 측정은 이전 모델 설정의 것입니다');
    assert.equal(bare.subhead, '품질 관문 · 1회');
    assert.deepEqual(folded(plan), [['WARNING', 1], ['NOT_EVALUATED', COMPARED_ROWS.length],
        ['PASSED', ROWS.length - 2 - COMPARED_ROWS.length]]);
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

test('quality P35: the control cases newly answered outside their allowed actions block, named, in both languages', () => {
    const blocked = quality({mode: 'BLOCK', verdict: 'BLOCKED', applied: 'BLOCKED', overridable: true,
        rows: replaced(passedRows(), {MUST_CATCH_NOT_WEAKENED: CONTROLS_WEAKENED})});
    const plan = ko.gatePlan(check(blocked), 'use');

    assert.equal(plan.state, 'block');
    assert.deepEqual(conditions(plan.open), ['MUST_CATCH_NOT_WEAKENED']);
    const row = plan.open[0];
    assert.equal(row.title, '"반드시 잡을 사례"를 허용 조치 밖(예: 차단이 맞는데 추가 인증이나 미룸)으로 새로 답하지 않았다');
    assert.equal(row.result, '막힘');
    assert.equal(row.evidence, '반드시 잡을 사례 10건 가운데 허용 조치 밖으로 새로 답한 사례 10건(답 10개)');
    assert.deepEqual(row.cases, {names: ['GET /api/documents/HX-310-DWG-00004 (VER-A1T)', 'VER-S01', 'VER-S02', 'VER-K2',
        'VER-A5T'], more: '외 5건'});
    assert.equal(plan.line, '막는 조건 1건에 걸렸습니다. 사유를 적으면 넘길 수 있고, 누가 왜 넘겼는지 감사 기록에 남습니다.');
    allWordsFound(plan);

    const english = load('en').gatePlan(check(blocked), 'canary');
    assert.equal(english.open[0].title, 'No "must catch" case newly answered outside its allowed actions (such as a'
        + ' challenge or a deferral where a block is right)');
    assert.equal(english.open[0].evidence, '10 of the 10 must-catch cases newly answered outside their allowed actions'
        + ' (10 answers)');
    allWordsFound(english);

    // Without a measurement of the version in use to compare, the row says each answer counts against the candidate.
    const uncompared = ko.gatePlan(check(quality({mode: 'BLOCK', verdict: 'BLOCKED', applied: 'BLOCKED',
        rows: replaced(passedRows(), {MUST_CATCH_NOT_WEAKENED: {status: 'BLOCKED', figures: {gradedCases: 10,
            unmeasuredCases: 1, weakenedCases: 2, weakenedAnswers: 3, currentAlsoOutsideCases: 0,
            comparedWithCurrent: 0}, cases: ['VER-A1T', 'VER-S01']}})})), 'use');
    assert.equal(uncompared.open[0].evidence, '반드시 잡을 사례 10건 가운데 허용 조치 밖으로 새로 답한 사례 2건(답 3개)'
        + ' · 지금 판의 측정과 견주지 못해 모두 후보의 답으로 셉니다 · 답이 없는 사례 1건');
    allWordsFound(uncompared);
});

test('quality P35: a control case the version in use answers outside its allowed actions too only warns', () => {
    const plan = ko.gatePlan(check(quality({verdict: 'WARNING', applied: 'WARNING',
        rows: replaced(passedRows(), {MUST_CATCH_NOT_WEAKENED: {status: 'WARNING', figures: {gradedCases: 10,
            unmeasuredCases: 0, weakenedCases: 0, weakenedAnswers: 0, currentAlsoOutsideCases: 1,
            comparedWithCurrent: 1}, cases: ['VER-A1T']}})})), 'use');

    assert.equal(plan.state, 'warn');
    assert.deepEqual(conditions(plan.open), ['MUST_CATCH_NOT_WEAKENED']);
    assert.equal(plan.open[0].result, '경고');
    assert.equal(plan.open[0].evidence, '반드시 잡을 사례 10건 가운데 허용 조치 밖으로 새로 답한 사례 0건(답 0개)'
        + ' · 지금 판도 허용 조치 밖으로 답한 사례 1건은 후보 탓이 아니어서 경고만 합니다');
    assert.deepEqual(plan.open[0].cases, {names: ['GET /api/documents/HX-310-DWG-00004 (VER-A1T)'], more: null});
    allWordsFound(plan);
    const english = load('en').gatePlan(check(quality({verdict: 'WARNING', applied: 'WARNING',
        rows: replaced(passedRows(), {MUST_CATCH_NOT_WEAKENED: {status: 'WARNING', figures: {gradedCases: 10,
            unmeasuredCases: 0, weakenedCases: 0, weakenedAnswers: 0, currentAlsoOutsideCases: 1,
            comparedWithCurrent: 1}, cases: ['VER-A1T']}})})), 'use');
    assert.equal(english.open[0].evidence, '0 of the 10 must-catch cases newly answered outside their allowed actions'
        + ' (0 answers) · 1 cases the version in use also answers outside them only warn: they are not the'
        + " candidate's doing");
    allWordsFound(english);
});

test('quality P8: a friction that rises by the limit or more blocks whatever the significance, in both languages', () => {
    const over = {status: 'BLOCKED', figures: {pairedCases: 15, currentRate: 10 / 15, candidateRate: 1, increase: 5 / 15,
        limit: 0.3, newlyStoppedCases: 4}, comparisons: [rate('FRICTION', 10 / 15, 1, 'UNDECIDABLE', 0)],
    cases: ['A1T', 'K2', 'S03', 'NOR-S01']};
    const blocked = quality({mode: 'BLOCK', verdict: 'BLOCKED', applied: 'BLOCKED', overridable: true,
        rows: replaced(passedRows(), {FRICTION_INCREASE_WITHIN_LIMIT: over})});
    const plan = ko.gatePlan(check(blocked), 'canary');

    assert.equal(plan.state, 'block');
    assert.deepEqual(conditions(plan.open), ['FRICTION_INCREASE_WITHIN_LIMIT']);
    const row = plan.open[0];
    assert.equal(row.title, '마찰이 지금 판보다 상한 이상 늘지 않았다(유의성과 관계없이)');
    assert.equal(row.evidence, '마찰 66.7% → 100% · 33.3%p 늘어남(상한 30%p)'
        + ' · 상한은 설정 contexa.pqa.oss.quality.gate.friction-increase-limit 입니다');
    assert.deepEqual(row.cases, {names: ['A1T', 'K2', 'S03', 'NOR-S01'], more: null});
    allWordsFound(plan);

    const english = load('en').gatePlan(check(blocked), 'canary');
    assert.equal(english.open[0].title, 'Friction did not rise by the limit or more, whatever the significance');
    assert.equal(english.open[0].evidence, 'Friction 66.7% → 100% · up 33.3 pts (limit 30 pts)'
        + ' · The limit is the setting contexa.pqa.oss.quality.gate.friction-increase-limit');
    allWordsFound(english);

    // A rise short of the limit passes and folds with the passed rows; no case that must be allowed, no friction.
    const under = ko.gatePlan(check(quality({rows: replaced(passedRows(), {FRICTION_INCREASE_WITHIN_LIMIT: {
        status: 'PASSED', figures: {pairedCases: 15, currentRate: 10 / 15, candidateRate: 14 / 15, increase: 4 / 15,
            limit: 0.3, newlyStoppedCases: 4}}, MUST_CATCH_NOT_WEAKENED: {status: 'PASSED', figures: {gradedCases: 0}}})})),
    'use');
    const folds = under.folds[0].rows;
    assert.equal(folds[ROWS.indexOf('FRICTION_INCREASE_WITHIN_LIMIT')].evidence, '마찰 66.7% → 93.3% · 26.7%p 늘어남(상한 30%p)');
    assert.equal(folds[ROWS.indexOf('MUST_CATCH_NOT_WEAKENED')].evidence, '이 등급의 사례가 없습니다');
    const none = ko.gatePlan(check(quality({rows: replaced(passedRows(), {FRICTION_INCREASE_WITHIN_LIMIT: {
        status: 'PASSED', figures: {pairedCases: 0, currentRate: null, candidateRate: null, increase: null, limit: 0.3,
            newlyStoppedCases: 0}}})})), 'use');
    assert.equal(none.folds[0].rows[ROWS.indexOf('FRICTION_INCREASE_WITHIN_LIMIT')].evidence,
        '허용해야 할 사례가 없어 견줄 마찰이 없습니다');
    allWordsFound(under);
    allWordsFound(none);
});

test('in English: the words of the same warning', () => {
    const en = load('en');
    const plan = en.gatePlan(check(quality({verdict: 'WARNING', applied: 'WARNING',
        rows: replaced(passedRows(), {NO_NEWLY_MISSED_OR_STOPPED_CASES: CHANGED_WARNS, ENOUGH_CASES: TOO_FEW})})), 'use');

    assert.equal(plan.label, 'Warning');
    assert.equal(plan.line, 'Nothing blocks it. Read the warnings (2) before you go on.');
    assert.equal(plan.folds[0].label, `${ROWS.length - 2} passed`);
    assert.equal(plan.open[0].compare.label, 'Show the 1 newly missed cases');
    assert.equal(plan.subhead, 'Quality gate · case set 3ccbfed8 · qwen3:8b · 1 run(s)');
    allWordsFound(plan);
});
