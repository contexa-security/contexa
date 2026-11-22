/*
 * Prompt quality assurance (quality plans 3.2 and 3.6): the fields of the right answer of a labelled case, the one way
 * every screen draws them (K200). A decision of the operation made a case (the sealed evidence, the result of a trial,
 * the decision detail) takes what the decision is and who acts, the case's grade, the actions that are right and the
 * one preferred among them, and why. The screen of the labelled cases takes the same, in the order and the words of its
 * own answer card, with why in both languages and the facts that decide the case. Made of the filter box's form grid
 * and fields; each screen puts them in its own confirmation or card. Load after console-common.js.
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
    /** The words of the fields: those of a decision made a case, and those of the screen of the labelled cases. */
    const WORDS = {
        decision: {values: 'pqa.answer.', allowed: 'pqa.answer.allowed', preferred: 'pqa.answer.preferred',
            none: 'pqa.answer.noPreferred', classification: 'pqa.answer.classification', kind: 'pqa.answer.kind',
            grade: 'pqa.answer.grade'},
        cases: {values: 'pqa.cases.', allowed: 'pqa.cases.detail.answerAside', preferred: 'pqa.cases.detail.best',
            none: 'pqa.cases.form.none', classification: 'pqa.cases.column.class', kind: 'pqa.cases.column.kind',
            grade: 'pqa.cases.column.caseGrade'}
    };

    function select(name, label, values, chosen) {
        const node = el('select', {class: 'modern-select', name, 'aria-label': label});
        values.forEach(([value, text]) => node.append(el('option', {value, text, selected: value === chosen ? true
            : null})));
        return node;
    }

    function textarea(name, label, length, text, hint) {
        return el('textarea', {class: 'modern-input zt-textarea', name, rows: '2', maxlength: length,
            placeholder: hint || null, 'aria-label': label, text: text || ''});
    }

    function field(label, control, wide) {
        return el(wide ? 'div' : 'label', {class: 'zt-filter-field' + (wide ? ' pv-span-all' : '')},
            el('span', {class: 'zt-filter-name', text: label}), control);
    }

    /**
     * The fields of an answer.
     *
     * @param options {action}: a decision made a case, its action checked as a right one to start from; or
     *        {cases: true, answer}: the screen of the labelled cases, filled from a case's answer when one is given
     *        ({allowed, preferred, classification, kind, grade, rationaleKo, rationaleEn, decidingFacts})
     * @returns {{node, read, check}} the form grid; the answer as the server reads it (a decision's
     *          QualityCaseAnswerForm, or the AnswerForm of the screen of the labelled cases); and whether it can be
     *          sent, the right actions given, the preferred one among them and why (what is missing is marked)
     */
    function fields(options) {
        const given = options || {};
        const cases = given.cases === true;
        const words = cases ? WORDS.cases : WORDS.decision;
        const answer = given.answer || {};
        const right = new Set(answer.allowed || (given.action ? [given.action] : []));
        const named = (values, prefix) => values.map(value => [value, ZT.t(words.values + prefix + value)]);
        const classification = select('classification', ZT.t(words.classification), named(CLASSES, 'class.'),
            answer.classification || 'THREAT');
        const kind = select('kind', ZT.t(words.kind), named(KINDS, 'kind.'), answer.kind || 'OUTSIDER');
        const grade = select('grade', ZT.t(words.grade), named(GRADES, 'grade.'), answer.grade || 'ORDINARY');
        const preferred = select('preferred', ZT.t(words.preferred), [['', ZT.t(words.none)]].concat(ACTIONS.map(
            action => [action, ZT.t('zt.console.ui.action.' + action)])), answer.preferred || '');
        const boxes = ACTIONS.map(action => el('input', {type: 'checkbox', value: action, name: 'allowedActions',
            checked: right.has(action) ? true : null}));
        const allowed = el('div', {class: 'pv-actions', role: 'group', 'aria-label': ZT.t(words.allowed)},
            boxes.map((box, index) => el('label', {class: 'pv-toggle'}, box,
                el('span', {text: ZT.t('zt.console.ui.action.' + ACTIONS[index])}))));
        const chosen = () => boxes.filter(box => box.checked).map(box => box.value);
        let reasons;
        let node;
        let read;
        if (cases) {
            const m = key => ZT.t('pqa.cases.' + key);
            const ko = textarea('rationaleKo', m('form.whyKo'), '2000', answer.rationaleKo);
            const en = textarea('rationaleEn', m('form.whyEn'), '2000', answer.rationaleEn);
            const facts = textarea('decidingFacts', m('detail.deciding'), '4000',
                (answer.decidingFacts || []).join('\n'), m('form.factsHint'));
            reasons = [ko, en];
            node = el('div', {class: 'zt-filter-grid pv-form-grid', 'data-form': 'case-answer'},
                field(ZT.t(words.allowed), allowed, true), field(ZT.t(words.preferred), preferred),
                field(ZT.t(words.classification), classification), field(ZT.t(words.kind), kind),
                field(ZT.t(words.grade), grade), field(m('form.whyKo'), ko, true), field(m('form.whyEn'), en, true),
                field(m('detail.deciding'), facts, true));
            read = () => ({allowedActions: chosen(), preferred: preferred.value || null,
                classification: classification.value, kind: kind.value, rationaleKo: ko.value.trim() || null,
                rationaleEn: en.value.trim() || null,
                decidingFacts: facts.value.split('\n').map(line => line.trim()).filter(Boolean), grade: grade.value});
        } else {
            const rationale = textarea('rationale', w('rationale'), '1000', null, w('rationaleHint'));
            reasons = [rationale];
            node = el('div', {class: 'zt-filter-grid pv-form-grid', 'data-form': 'case-answer'},
                field(w('classification'), classification), field(w('kind'), kind), field(w('grade'), grade),
                field(w('preferred'), preferred), field(w('allowed'), allowed, true),
                field(w('rationale'), rationale, true));
            read = () => ({allowedActions: chosen(), preferredAction: preferred.value || null,
                classification: classification.value, kind: kind.value, rationale: rationale.value.trim(),
                grade: grade.value});
        }
        const check = () => {
            const actions = chosen();
            const reason = reasons.some(box => box.value.trim() !== '');
            const preferredFine = !preferred.value || actions.includes(preferred.value);
            allowed.setAttribute('aria-invalid', String(!actions.length));
            reasons.forEach(box => box.setAttribute('aria-invalid', String(!reason)));
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
