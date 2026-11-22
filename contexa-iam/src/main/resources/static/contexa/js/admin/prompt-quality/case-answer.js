/*
 * Prompt quality assurance (quality plan 3.6): the fields of the right answer an administrator sets when a decision of
 * the operation is made a labelled case, the same on every screen that does it (the sealed evidence, the result of a
 * trial, the decision detail): what the decision is and who acts, the case's grade, the actions that are right and the
 * one preferred among them, and why. Made of the filter box's form grid and fields; each screen puts them in its own
 * confirmation or card. Load after console-common.js.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    if (!ZT) {
        return;
    }
    const el = ZT.el;
    const w = (key, ...args) => ZT.t('pqa.answer.' + key, ...args);
    const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];
    const CLASSES = ['THREAT', 'NORMAL', 'UNCERTAIN'];
    const KINDS = ['OUTSIDER', 'INSIDER', 'NORMAL_WORK', 'AUTOMATION'];
    const GRADES = ['ORDINARY', 'MUST_CATCH', 'MUST_NOT_BLOCK'];

    function select(name, values, chosen) {
        const node = el('select', {class: 'modern-select', name, 'aria-label': w(name)});
        values.forEach(([value, text]) => node.append(el('option', {value, text, selected: value === chosen ? true
            : null})));
        return node;
    }

    function field(label, control, wide) {
        return el(wide ? 'div' : 'label', {class: 'zt-filter-field' + (wide ? ' pv-span-all' : '')},
            el('span', {class: 'zt-filter-name', text: label}), control);
    }

    /**
     * The fields of an answer, the decision's action checked as a right one to start from.
     *
     * @param options {action}: the action the decision took
     * @returns {{node, read, check}} the form grid, the answer as the server reads it (QualityCaseAnswerForm), and
     *          whether it can be sent (what is missing is marked)
     */
    function fields(options) {
        const given = options || {};
        const classification = select('classification', CLASSES.map(value => [value, w('class.' + value)]),
            'THREAT');
        const kind = select('kind', KINDS.map(value => [value, w('kind.' + value)]), 'OUTSIDER');
        const grade = select('grade', GRADES.map(value => [value, w('grade.' + value)]), 'ORDINARY');
        const preferred = select('preferred', [['', w('noPreferred')]].concat(ACTIONS.map(action => [action,
            ZT.t('zt.console.ui.action.' + action)])), '');
        const boxes = ACTIONS.map(action => el('input', {type: 'checkbox', value: action, name: 'allowedActions',
            checked: action === given.action ? true : null}));
        const allowed = el('div', {class: 'pv-actions', role: 'group', 'aria-label': w('allowed')},
            boxes.map((box, index) => el('label', {class: 'pv-toggle'}, box,
                el('span', {text: ZT.t('zt.console.ui.action.' + ACTIONS[index])}))));
        const rationale = el('textarea', {class: 'modern-input zt-textarea', name: 'rationale', rows: '2',
            maxlength: '1000', placeholder: w('rationaleHint'), 'aria-label': w('rationale')});
        const node = el('div', {class: 'zt-filter-grid pv-form-grid', 'data-form': 'case-answer'},
            field(w('classification'), classification), field(w('kind'), kind), field(w('grade'), grade),
            field(w('preferred'), preferred), field(w('allowed'), allowed, true), field(w('rationale'), rationale, true));
        const chosen = () => boxes.filter(box => box.checked).map(box => box.value);
        const read = () => ({allowedActions: chosen(), preferredAction: preferred.value || null,
            classification: classification.value, kind: kind.value, rationale: rationale.value.trim(),
            grade: grade.value});
        const check = () => {
            const actions = chosen();
            const reason = rationale.value.trim() !== '';
            const preferredFine = !preferred.value || actions.includes(preferred.value);
            allowed.setAttribute('aria-invalid', String(!actions.length));
            rationale.setAttribute('aria-invalid', String(!reason));
            preferred.setAttribute('aria-invalid', String(!preferredFine));
            return actions.length > 0 && reason && preferredFine;
        };
        return {node, read, check};
    }

    /** The words of a refusal of the cases, else the message the server gave, else none. */
    function refusal(body) {
        const code = body && (body.refusal || body.code);
        const key = 'pqa.answer.refusal.' + code;
        if (code && ZT.t(key) !== key) {
            return ZT.t(key);
        }
        return body && body.message ? body.message : null;
    }

    /** What a case made of a decision is now: waiting for confirmation or kept, counted apart from a second analysis. */
    function doneLines(promotion) {
        return [w('key', promotion.caseKey), promotion.status === 'CONFIRMED' ? w('confirmed') : w('pending'),
            promotion.secondAnalysis ? w('secondAnalysis') : null].filter(Boolean);
    }

    global.PQA_CASE_ANSWER = {fields, refusal, doneLines};
})(window);
