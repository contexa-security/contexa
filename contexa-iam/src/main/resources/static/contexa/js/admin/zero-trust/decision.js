/*
 * Zero Trust console, one decision (console design 6.4, the detail): the conclusion first, then its grounds, then the
 * raw records. (1) the reasons the model cited with the facts' values and its own sentence, (2) the explanations it
 * weighed, (3) the comparison with the usual, (4) what it did not know, (5) what came of it, (6) where the time went
 * and the records behind it; and the administrator's evaluation (console decision 11.3).
 */
(function (ZT) {
    'use strict';

    const {t, el} = ZT;
    const P = 'zt.console.ui.decision.';
    const D = 'zt.console.ui.decisions.';
    const O = 'zt.console.ui.operations.';
    const PAGES = '/contexa/admin/zero-trust';
    const AUDIT = '/contexa/admin/security-monitor/';
    const EVIDENCE = '/contexa/admin/prompt-inspection/packages/';
    /** The stages of one decision in the order they run; the user's wait is shown apart (it spans them). */
    const STAGES = ['QUEUE', 'PREPARE', 'RAG', 'MODEL', 'PARSE', 'PERSIST'];
    const REASONS = ['OVERREACTION', 'FACTS_WRONG', 'MISSED_SIGNAL', 'OTHER'];
    /** The most characters an evaluation's note keeps (the server's bound). */
    const NOTE_LIMIT = 1024;

    const root = document.getElementById('zt-console');
    const content = document.getElementById('zt-content');
    const band = document.getElementById('zt-band');
    const observationId = root ? root.dataset.observationId || '' : '';
    const path = '/decisions/' + encodeURIComponent(observationId);

    function known(key, fallback) {
        const text = t(key);
        return text === key ? fallback : text;
    }

    function muted(text) {
        return el('div', {class: 'zt-muted', text});
    }

    function grid(...cards) {
        return el('div', {class: 'zt-grid'}, cards);
    }

    function span(card, columns) {
        card.classList.add('zt-span-' + columns);
        return card;
    }

    function actionLabel(action) {
        return action ? t('zt.console.ui.action.' + action) : '—';
    }

    function hypothesisLabel(id) {
        return known(D + 'hypothesis.' + id, id);
    }

    // ----- the band: back to the list, the request, its time, its mode and who acted -----

    function drawBand(detail) {
        band.replaceChildren(
            el('a', {class: 'zt-link', href: PAGES + '/decisions', text: t(P + 'band.back')}),
            el('span', {text: t(P + 'band.request', detail.requestId || '—')}),
            el('span', {text: ZT.time(detail.createdAt)}),
            detail.mode ? el('span', {class: 'status-badge zt-mode', 'data-mode': detail.mode, text: t(P + 'band.mode', detail.mode)})
                : null,
            detail.actor ? el('span', {text: known(D + 'actor.' + detail.actor, detail.actor)}) : null);
        if (detail.mode === 'SHADOW') {
            band.append(el('span', {class: 'zt-band-note', text: t('zt.console.ui.band.shadow')}));
        }
    }

    // ----- the conclusion and its chips -----

    function sourceText(detail) {
        const source = known(D + 'source.' + detail.source, detail.source);
        return detail.cause ? t(P + 'chip.sourceCause', source, ZT.causeName(detail.cause))
            : source;
    }

    function conclusionCard(detail, parts) {
        const subject = [detail.user, detail.resource,
            detail.resourceClass ? known(D + 'resourceClass.' + detail.resourceClass, detail.resourceClass) : null]
            .filter(Boolean).join(' · ');
        parts.conclusion = el('p', {class: 'zt-summary-main', text: detail.conclusion || '—'});
        const facts = [
            [t(P + 'fact.proposed'), detail.proposedAction ? (detail.proposedAction === detail.action
                ? t(P + 'chip.proposedSame') : actionLabel(detail.proposedAction)) : '—'],
            [t(P + 'fact.source'), detail.source ? sourceText(detail) : '—'],
            [t(P + 'fact.timing'), detail.timing ? known(D + 'timing.' + detail.timing, detail.timing) : '—'],
            [t(P + 'fact.total'), ZT.seconds(detail.totalMs)],
            [t(P + 'fact.bundle'), t(P + 'fact.bundleValue', detail.bundle || '—', detail.model || '—')]];
        // Words from the data can be long: each value keeps to its line and shows the whole in its title.
        const grid = el('div', {class: 'zt-facts'}, facts.map(([name, value]) => el('div', {class: 'zt-facts-item'},
            el('span', {class: 'zt-facts-name', text: name}), el('span', {class: 'zt-facts-value', text: value, title: value}))));
        return ZT.card(t(P + 'conclusion.title'), subject || null,
            el('div', {class: 'zt-conclusion'}, ZT.chip(detail.action, t(P + 'chip.final', actionLabel(detail.action))),
                el('div', {class: 'zt-summary'}, parts.conclusion)), grid, breaches(detail));
    }

    /**
     * K17 (decision D11): the decision rules the answer of the model still broke after it was asked again, each in
     * words with the analysis that broke it; the record keeps the rule as the response check named it.
     */
    function breaches(detail) {
        const kept = detail.ruleBreaches || [];
        if (!kept.length) {
            return null;
        }
        const items = kept.map(breach => {
            // the codes the screen has words for; a rule of none of them reads as a decision rule
            const named = (breach.codes || []).map(code => known(P + 'breach.rule.' + code, null)).filter(Boolean);
            const rules = (named.length ? named : [t(P + 'breach.rule.OTHER')]).join(', ');
            const layer = known(P + 'breach.layer.' + String(breach.layer || '').toUpperCase(), breach.layer || '—');
            return el('div', {title: breach.rule || '', text: t(P + 'breach.item', layer, rules)});
        });
        return el('div', {class: 'zt-warning', role: 'note'}, el('div', {text: t(P + 'breach.title')}), items,
            detail.inReview ? el('div', {text: t(P + 'breach.queued')}) : null);
    }

    /** The model's own sentence, marked as its words (design 6.4); the engine's is never shown as the model's (K25). */
    function modelWords(text) {
        if (!text) {
            return null;
        }
        return el('figure', {class: 'zt-quote'}, el('figcaption', {text: t(P + 'modelWords')}),
            el('blockquote', {text: t(P + 'quote', text)}));
    }

    /**
     * K25: the engine's part in the decision, in words made of who set the action and why; the sentence the engine
     * wrote stays its record, in the title.
     */
    function engineWords(detail) {
        if (!detail.engineReason) {
            return null;
        }
        const cause = detail.cause ? ZT.causeName(detail.cause) : '—';
        const source = detail.source === 'MODEL_LESS' || detail.source === 'ENGINE_CHANGED' ? detail.source : 'MODEL';
        return el('figure', {class: 'zt-quote', title: t(P + 'engineWords.record', detail.engineReason)},
            el('figcaption', {text: t(P + 'engineWords')}),
            el('blockquote', {text: t(P + 'engineWords.' + source, cause)}));
    }

    // ----- (1) the reasons with the facts they cite -----

    function reasonsCard(detail) {
        const reasons = detail.reasons || [];
        const anchored = new Set();
        const list = el('div', {class: 'zt-indicators'});
        reasons.forEach(reason => {
            const id = reason.fact && !anchored.has(reason.fact) ? 'zt-fact-' + reason.fact : null;
            if (reason.fact) {
                anchored.add(reason.fact);
            }
            const group = known('zt.console.reasonGroup.' + (reason.group || 'OTHER'), reason.group || '');
            const name = reason.factName ? ZT.factName(reason.factName) : group;
            list.append(el('div', {class: 'zt-indicator zt-fact-row', id, 'data-severity': 'INFO'},
                el('div', {class: 'zt-indicator-text'},
                    el('span', {class: 'zt-indicator-title', text: name, title: name}),
                    el('span', {class: 'zt-fact-value', text: reason.factValue || t(P + 'reasons.noValue')}),
                    el('span', {class: 'zt-indicator-rule', text: t(P + 'reasons.code', group, ZT.reasonName(reason.code)),
                        title: reason.code || ''})),
                el('span', {class: 'zt-fact-id', text: reason.fact || '—'})));
        });
        return ZT.card(t(P + 'reasons.title'), t(P + 'reasons.aside', ZT.count(reasons.length)),
            reasons.length ? list : muted(t(P + 'reasons.none')), modelWords(detail.modelReason), engineWords(detail));
    }

    // ----- (2) the explanations the model weighed -----

    function hypothesesCard(detail) {
        const hypotheses = detail.hypotheses || [];
        const cited = new Set((detail.reasons || []).map(reason => reason.fact).filter(Boolean));
        const body = hypotheses.length ? ZT.hypothesisBoard(hypotheses, {
            label: t(P + 'hypotheses.title'),
            name: hypothesisLabel,
            assessment: code => t(D + 'assessment.' + code),
            cited: (kind, fact) => t(D + 'cited.' + kind, fact),
            href: fact => cited.has(fact) ? '#zt-fact-' + fact : null
        }) : muted(t(P + 'hypotheses.none'));
        return ZT.card(t(P + 'hypotheses.title'), t(P + 'hypotheses.aside'), body);
    }

    /**
     * No reason codes: an older bundle that gives none (design 6.4), or a request that got no decision. (1) and (2) say
     * which and keep the model's sentence.
     */
    function unexplainedCard(detail) {
        const text = detail.action === 'NO_DECISION' ? t(P + 'unexplained.noDecision')
            : detail.source === 'MODEL_LESS' ? t(P + 'unexplained.modelLess')
                : t(P + 'unexplained.text', detail.bundle || '—');
        return ZT.card(t(P + 'unexplained.title'), null, el('div', {text}), modelWords(detail.modelReason),
            engineWords(detail));
    }

    // ----- (3) the comparison with the usual -----

    function judgement(deviation) {
        if (!deviation.compared) {
            return t(P + 'deviation.notCompared');
        }
        if (!deviation.different) {
            return t(P + 'deviation.same');
        }
        switch (deviation.explanation) {
            case 'EXPLAINED':
                return t(P + 'deviation.explained', deviation.explainedBy || '—');
            case 'UNEXPLAINED':
                return t(P + 'deviation.unexplained');
            case 'NOT_ESTABLISHED':
                return t(P + 'deviation.notEstablished');
            default:
                return t(P + 'deviation.differentUnknown');
        }
    }

    function comparisonCard(detail) {
        const deviations = detail.deviations || [];
        const baseline = detail.baselineStatus ? known(P + 'baseline.' + detail.baselineStatus, detail.baselineStatus)
            : t(P + 'baseline.unknown');
        const context = detail.contextLevel ? known(P + 'context.' + detail.contextLevel, detail.contextLevel) : null;
        let body;
        if (deviations.length) {
            const head = el('tr', {}, ['dimension', 'usual', 'current', 'judgement'].map(key => el('th',
                {scope: 'col', text: t(P + 'deviation.column.' + key)})));
            // K26, K27: the usual and the request's values in words, as the server reads the engine's notation.
            const rows = deviations.map(deviation => {
                const values = [known(P + 'dimension.' + deviation.dimension, deviation.dimension || '—'),
                    deviation.usualText || '—', deviation.currentText || deviation.current || '—', judgement(deviation)];
                return el('tr', {}, values.map(value => el('td', {title: value, text: value})));
            });
            body = el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'}, el('thead', {}, head),
                el('tbody', {}, rows)));
        } else {
            body = muted(t(P + 'deviation.none'));
        }
        // K27: a decision stored before the usual values were kept says why its usual column is mostly empty.
        const note = deviations.length && !detail.usualKept ? muted(t(P + 'deviation.usualNotKept')) : null;
        return ZT.card(t(P + 'comparison.title'), [baseline, context].filter(Boolean).join(' · '), body, note);
    }

    // ----- (4) what the model did not know -----

    function unknownCard(detail) {
        const entries = Object.entries(detail.unknown || {});
        const body = entries.length ? ZT.valueRows(entries.map(([fact, why]) => ({label: ZT.factName(fact), title: fact,
            value: known(P + 'unknown.' + why, String(why))}))) : ZT.emptyNote(t(P + 'unknown.none'));
        const card = ZT.card(t(P + 'unknown.title'), entries.length ? t(P + 'unknown.aside', ZT.count(entries.length))
            : null, body);
        return entries.some(([, why]) => why === 'NOT_INTEGRATED') ? ZT.withTip(card, t(P + 'unknown.note')) : card;
    }

    // ----- (5) what came of it -----

    function outcomeItem(text, at, note) {
        return el('li', {class: 'zt-result-row zt-outcome', title: note ? t(P + 'quote', note) : text},
            el('span', {class: 'zt-result-name', text}), el('span', {class: 'zt-muted', text: ZT.time(at)}));
    }

    function fillOutcomes(list, detail) {
        const outcomes = detail.outcomes || [];
        list.replaceChildren(outcomeItem(t(P + 'outcomes.decided', actionLabel(detail.action)), detail.createdAt, null));
        outcomes.forEach(outcome => {
            const text = [known(D + 'outcome.' + outcome.kind, outcome.kind), outcome.actor,
                outcome.reason ? known(P + 'evaluation.reason.' + outcome.reason, outcome.reason) : null]
                .filter(Boolean).join(' · ');
            list.append(outcomeItem(text, outcome.at, outcome.note));
        });
        if (!outcomes.length) {
            list.append(el('li', {class: 'zt-muted zt-outcome-none', text: t(P + 'outcomes.none')}));
        }
    }

    function outcomesCard(detail, parts) {
        parts.outcomes = el('ul', {class: 'zt-result-rows zt-outcomes'});
        fillOutcomes(parts.outcomes, detail);
        return ZT.card(t(P + 'outcomes.title'), null, parts.outcomes);
    }

    // ----- (6) where the time went, and the records behind the decision -----

    function timingsCard(detail) {
        const timings = detail.timings || {};
        const stages = STAGES.map(stage => ({label: t(O + 'stage.' + stage), ms: timings[stage]}));
        const wait = timings.USER_WAIT;
        let waited = null;
        if (wait != null) {
            waited = el('div', {text: t(P + 'timings.userWait', ZT.seconds(wait))});
        } else if (detail.timing === 'NEXT_REQUEST') {
            waited = muted(t(P + 'timings.async'));
        }
        const card = ZT.card(t(P + 'timings.title'), t(P + 'chip.total', ZT.seconds(detail.totalMs)), waited,
            stages.some(stage => stage.ms != null) ? ZT.waterfall(stages) : ZT.empty('NOT_RECORDED'));
        card.append(el('div', {class: 'zt-card-foot'},
            detail.auditId != null
                ? el('a', {class: 'zt-link', href: AUDIT + encodeURIComponent(detail.auditId), text: t(P + 'links.audit')})
                : el('span', {class: 'zt-muted', text: t(P + 'links.noAudit')}),
            detail.packageId
                ? el('a', {class: 'zt-link', href: EVIDENCE + encodeURIComponent(detail.packageId),
                    text: t(P + 'links.evidence')})
                : el('span', {class: 'zt-muted', text: t(P + 'links.noEvidence')})));
        return card;
    }

    // ----- the administrator's evaluation (console decision 11.3) -----

    function choices(legend, name, options) {
        return el('fieldset', {}, el('legend', {text: legend}), options.map(([value, text]) => el('label', {},
            el('input', {type: 'radio', name, value}), el('span', {text}))));
    }

    function evaluationCard(detail, parts) {
        const form = el('form', {class: 'zt-filters', novalidate: true});
        const verdict = choices(t(P + 'evaluation.question'), 'valid',
            [['true', t(P + 'evaluation.valid')], ['false', t(P + 'evaluation.invalid')]]);
        const reasons = choices(t(P + 'evaluation.reasonLegend'), 'reason',
            REASONS.map(reason => [reason, t(P + 'evaluation.reason.' + reason)]));
        reasons.disabled = true;
        const noteId = 'zt-evaluation-note';
        const note = el('textarea', {class: 'modern-input zt-textarea', id: noteId, name: 'note', rows: '3',
            maxlength: String(NOTE_LIMIT)});
        const save = el('button', {type: 'submit', class: 'modern-btn-primary'},
            el('i', {class: 'fas fa-check', 'aria-hidden': 'true'}), t(P + 'evaluation.save'));
        save.disabled = true;
        const status = el('div', {class: 'zt-item', role: 'status', 'aria-live': 'polite'});
        form.append(verdict, reasons, el('label', {for: noteId, text: t(P + 'evaluation.note')}), note,
            el('div', {class: 'zt-toolbar'}, save), status);

        const chosen = name => {
            const input = form.querySelector('input[name="' + name + '"]:checked');
            return input ? input.value : null;
        };
        const ready = () => {
            const valid = chosen('valid');
            reasons.disabled = valid !== 'false';
            save.disabled = valid == null || (valid === 'false' && chosen('reason') == null);
        };
        form.addEventListener('change', ready);
        form.addEventListener('input', () => {
            status.replaceChildren();
        });
        form.addEventListener('submit', async event => {
            event.preventDefault();
            const valid = chosen('valid');
            if (valid == null) {
                return;
            }
            save.disabled = true;
            status.replaceChildren(muted(t(P + 'evaluation.saving')));
            const body = {valid: valid === 'true', reason: valid === 'false' ? chosen('reason') : null,
                note: note.value.trim() || null};
            let result;
            try {
                result = await ZT.post(path + '/evaluation', body);
            } catch (error) {
                result = {ok: false, status: null, body: null};
            }
            if (result.ok) {
                await saved(result.body, parts, status);
            } else {
                status.replaceChildren(el('div', {class: 'zt-warning', role: 'alert', text: problem(result)}));
                ready();
            }
        });
        return ZT.card(t(P + 'evaluation.title'), detail.inReview ? t(P + 'evaluation.inReview') : null, form);
    }

    function problem(result) {
        if (result.status === 400) {
            const detail = result.body && result.body.detail ? result.body.detail : '';
            return t(P + 'evaluation.invalidRequest', detail);
        }
        if (result.status === 404) {
            return t(P + 'evaluation.notFound');
        }
        return t(P + 'evaluation.failed', result.status == null ? '—' : result.status);
    }

    /** Saved: say so, read the outcomes again (the conclusion follows the last outcome) and offer the next review. */
    async function saved(body, parts, status) {
        const kind = body && body.kind ? body.kind : null;
        status.replaceChildren(el('div', {text: t(P + 'evaluation.saved',
            kind ? known('zt.console.outcome.' + kind, kind) : '')}));
        try {
            const fresh = await ZT.load(path);
            fillOutcomes(parts.outcomes, fresh);
            parts.conclusion.textContent = fresh.conclusion || '—';
        } catch (error) {
            status.append(muted(t(P + 'evaluation.reloadFailed')));
        }
        try {
            const queue = await ZT.load('/review-queue');
            const next = queue.find(item => item.observationId !== observationId);
            status.append(next
                ? el('a', {class: 'zt-link', href: PAGES + '/decisions/' + encodeURIComponent(next.observationId),
                    text: t(P + 'evaluation.next', ZT.count(queue.filter(item => item.observationId !== observationId)
                        .length))})
                : muted(t(P + 'evaluation.queueEmpty')));
        } catch (error) {
            // The next review is a convenience; the evaluation is kept either way.
        }
    }

    // ----- the screen -----

    function render(detail) {
        drawBand(detail);
        const parts = {};
        content.replaceChildren(
            grid(span(conclusionCard(detail, parts), 12)),
            detail.explained ? grid(span(reasonsCard(detail), 6), span(hypothesesCard(detail), 6))
                : grid(span(unexplainedCard(detail), 12)),
            grid(span(comparisonCard(detail), 8), span(unknownCard(detail), 4)),
            grid(span(outcomesCard(detail, parts), 4), span(timingsCard(detail), 4), span(evaluationCard(detail, parts), 4)));
        const hash = window.location.hash ? decodeURIComponent(window.location.hash.slice(1)) : '';
        const anchor = hash ? document.getElementById(hash) : null;
        if (anchor) {
            anchor.scrollIntoView();
        }
    }

    function notFound() {
        band.replaceChildren(el('a', {class: 'zt-link', href: PAGES + '/decisions', text: t(P + 'band.back')}));
        content.replaceChildren(grid(span(ZT.card(t(P + 'notFound.title'), null,
            el('div', {text: t(P + 'notFound.text', observationId || '—')})), 12)));
    }

    async function draw() {
        if (!root || !content) {
            return;
        }
        try {
            render(await ZT.load(path));
        } catch (error) {
            if (error && error.message === '404') {
                notFound();
            } else {
                ZT.failed(content, error);
            }
        }
    }

    draw();
})(window.ZT);
