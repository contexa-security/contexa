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
            detail.mode ? el('span', {class: 'zt-mode', 'data-mode': detail.mode, text: t(P + 'band.mode', detail.mode)})
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
        parts.conclusion = el('p', {text: detail.conclusion || '—'});
        const chips = el('div', {class: 'zt-toolbar'});
        chips.append(ZT.chip(detail.action, t(P + 'chip.final', actionLabel(detail.action))));
        if (detail.proposedAction) {
            chips.append(detail.proposedAction === detail.action ? ZT.statusChip('INFO', t(P + 'chip.proposedSame'))
                : ZT.chip(detail.proposedAction, t(P + 'chip.proposed', actionLabel(detail.proposedAction))));
        }
        if (detail.source) {
            chips.append(ZT.statusChip('INFO', sourceText(detail)));
        }
        if (detail.timing) {
            chips.append(ZT.statusChip('INFO', known(D + 'timing.' + detail.timing, detail.timing)));
        }
        chips.append(ZT.statusChip('INFO', t(P + 'chip.total', ZT.seconds(detail.totalMs))));
        chips.append(ZT.statusChip('INFO', t(P + 'chip.bundle', detail.bundle || '—', detail.model || '—')));
        // Words from the data can be long: each chip keeps to its line and shows the whole in its title.
        Array.from(chips.children).forEach(chip => {
            chip.classList.add('zt-fit');
            chip.setAttribute('title', chip.textContent);
        });
        return ZT.card(t(P + 'conclusion.title'), subject || null, el('div', {class: 'zt-verdict'}, parts.conclusion),
            chips);
    }

    /** The model's own sentence, marked as its words (design 6.4). */
    function modelWords(text) {
        if (!text) {
            return null;
        }
        return el('div', {class: 'zt-item'}, el('div', {class: 'zt-toolbar'}, ZT.statusChip('INFO', t(P + 'modelWords'))),
            el('div', {text: t(P + 'quote', text)}));
    }

    // ----- (1) the reasons with the facts they cite -----

    function reasonsCard(detail) {
        const reasons = detail.reasons || [];
        const anchored = new Set();
        const list = el('div', {class: 'zt-rows'});
        reasons.forEach(reason => {
            const id = reason.fact && !anchored.has(reason.fact) ? 'zt-fact-' + reason.fact : null;
            if (reason.fact) {
                anchored.add(reason.fact);
            }
            const group = known('zt.console.reasonGroup.' + (reason.group || 'OTHER'), reason.group || '');
            list.append(el('div', {class: 'zt-fact zt-item', id},
                el('div', {class: 'zt-row'}, el('strong', {text: reason.factName ? ZT.factName(reason.factName) : group,
                    title: reason.factName ? ZT.factName(reason.factName) : group}),
                    el('span', {class: 'zt-muted', text: reason.fact || '—'})),
                el('div', {text: reason.factValue || t(P + 'reasons.noValue')}),
                el('div', {class: 'zt-muted', text: t(P + 'reasons.code', group, ZT.reasonName(reason.code)),
                    title: reason.code || ''})));
        });
        return ZT.card(t(P + 'reasons.title'), t(P + 'reasons.aside', ZT.count(reasons.length)),
            reasons.length ? list : muted(t(P + 'reasons.none')), modelWords(detail.modelReason));
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
            : t(P + 'unexplained.text', detail.bundle || '—');
        return ZT.card(t(P + 'unexplained.title'), null, el('div', {text}), modelWords(detail.modelReason));
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
            const rows = deviations.map(deviation => {
                const values = [known(P + 'dimension.' + deviation.dimension, deviation.dimension || '—'),
                    deviation.usual || '—', deviation.current || '—', judgement(deviation)];
                return el('tr', {}, values.map(value => el('td', {title: value, text: value})));
            });
            body = el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table'}, el('thead', {}, head),
                el('tbody', {}, rows)));
        } else {
            body = muted(t(P + 'deviation.none'));
        }
        return ZT.card(t(P + 'comparison.title'), [baseline, context].filter(Boolean).join(' · '), body);
    }

    // ----- (4) what the model did not know -----

    function unknownCard(detail) {
        const entries = Object.entries(detail.unknown || {});
        const body = entries.length ? ZT.rows(entries, ([fact, why]) => [
            el('span', {text: ZT.factName(fact), title: fact}),
            el('span', {class: 'zt-muted', text: known(P + 'unknown.' + why, String(why))})]) : muted(t(P + 'unknown.none'));
        const integrate = entries.some(([, why]) => why === 'NOT_INTEGRATED') ? muted(t(P + 'unknown.note')) : null;
        return ZT.card(t(P + 'unknown.title'), entries.length ? t(P + 'unknown.aside', ZT.count(entries.length)) : null,
            body, integrate);
    }

    // ----- (5) what came of it -----

    function outcomeItem(text, at, note) {
        return el('li', {class: 'zt-item'}, el('div', {class: 'zt-row'}, el('span', {text, title: text}),
            el('span', {class: 'zt-muted', text: ZT.time(at)})), note ? muted(t(P + 'quote', note)) : null);
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
            list.append(el('li', {class: 'zt-muted', text: t(P + 'outcomes.none')}));
        }
    }

    function outcomesCard(detail, parts) {
        parts.outcomes = el('ul', {class: 'zt-rows'});
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
        const note = el('textarea', {class: 'zt-textarea', id: noteId, name: 'note', rows: '3',
            maxlength: String(NOTE_LIMIT)});
        const save = el('button', {type: 'submit', class: 'zt-button zt-primary', text: t(P + 'evaluation.save')});
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
