import {api, checkName, el, fillTable, formatTime, number, outcomeChip, setStatus, t, verdictChip}
    from './prompt-inspection-common.js';

const page = document.querySelector('[data-pi-page]');
const packageId = page.dataset.packageId;
const status = document.querySelector('[data-pi-status]');
const linePanel = document.querySelector('[data-pi-line-detail]');

function fact(name, value) {
    const node = document.querySelector(`[data-pi-fact="${name}"]`);
    node.replaceChildren(value instanceof Node ? value : document.createTextNode(value || '-'));
}

function findingCard(finding) {
    const rows = [
        [t('promptInspection.detail.expected'), finding.expected],
        [t('promptInspection.detail.actual'), finding.actual],
        [t('promptInspection.detail.source'), finding.sourceRef],
        [t('promptInspection.detail.reason'), finding.reason]
    ].filter(([, value]) => value !== null && value !== undefined && value !== '');
    const place = [finding.block, finding.entry].filter(Boolean).join('.') + (finding.factId ? ` [${finding.factId}]` : '');
    return el('article', {class: 'pi-finding'}, [
        el('header', {class: 'pi-finding-head'}, [outcomeChip(finding.outcome), el('strong', {text: checkName(finding.checkCode)}),
            place ? el('span', {class: 'pi-code', text: place}) : null]),
        el('dl', {class: 'pi-finding-body'}, rows.flatMap(([label, value]) => [el('dt', {text: label}),
            el('dd', {class: 'pi-pre', text: String(value)})]))
    ]);
}

function showLine(line, button) {
    document.querySelectorAll('.pi-line.is-selected').forEach((node) => node.classList.remove('is-selected'));
    button.classList.add('is-selected');
    const parts = [el('p', {class: 'pi-pre pi-line-text', text: `${line.number}  ${line.text}`})];
    if (line.matchedBy.length) {
        parts.push(el('p', {class: 'pi-note'}, [`${t('promptInspection.detail.matchedBy')}: `,
            line.matchedBy.map(checkName).join(', ')]));
    }
    if (line.findings.length) {
        line.findings.forEach((finding) => parts.push(findingCard(finding)));
    } else {
        parts.push(el('p', {class: 'pi-note', text: t('promptInspection.detail.noFinding')}));
    }
    linePanel.replaceChildren(...parts);
}

function lineState(line) {
    if (line.findings.some((finding) => finding.outcome === 'MISMATCH')) {
        return 'mismatch';
    }
    if (line.findings.length) {
        return 'unverifiable';
    }
    return line.matchedBy.length ? 'matched' : 'plain';
}

function render(detail) {
    fact('verdict', verdictChip(detail.verdict));
    fact('capturedAt', formatTime(detail.capturedAt));
    fact('userId', detail.userId);
    fact('request', [detail.httpMethod, detail.requestPath].filter(Boolean).join(' ')
        + (detail.resourceId ? ` (${detail.resourceId})` : ''));
    fact('inspector', t('promptInspection.detail.inspector', detail.inspectorVersion, detail.dictionaryVersion || '-',
        detail.layoutVersion || '-'));
    fact('errorReason', detail.errorReason);
    document.querySelector('[data-pi-error-row]').hidden = !detail.errorReason;

    const stored = detail.stored;
    document.querySelector('[data-pi-stored]').textContent = !stored ? t('promptInspection.detail.stored.none')
        : !stored.sameInspector ? t('promptInspection.detail.stored.other', stored.inspectorVersion)
            : stored.sameFindings ? t('promptInspection.detail.stored.same') : t('promptInspection.detail.stored.differs');

    fillTable(document.querySelector('[data-pi-checks]'), detail.checks.map((check) => el('tr', {}, [
        el('td', {text: checkName(check.checkCode)}),
        el('td', {class: 'pi-number', text: number(check.matched)}),
        el('td', {class: 'pi-number', text: number(check.mismatched)}),
        el('td', {class: 'pi-number', text: number(check.unverifiable)})
    ])), 4);

    const list = document.querySelector('[data-pi-lines]');
    list.replaceChildren(...detail.lines.map((line) => {
        const button = el('button', {type: 'button', class: `pi-line pi-line-${lineState(line)}`}, [
            el('span', {class: 'pi-line-number', text: String(line.number)}),
            el('span', {class: 'pi-line-text', text: line.text})
        ]);
        button.addEventListener('click', () => showLine(line, button));
        return el('li', {}, button);
    }));
    linePanel.replaceChildren(el('p', {class: 'pi-note', text: t('promptInspection.detail.selectLine')}));

    const unplaced = document.querySelector('[data-pi-unplaced]');
    unplaced.replaceChildren(...(detail.unplacedFindings.length ? detail.unplacedFindings.map(findingCard)
        : [el('p', {class: 'pi-note', text: t('promptInspection.common.empty')})]));

    const changes = detail.changes;
    document.querySelector('[data-pi-changes-compared]').textContent = !changes ? t('promptInspection.detail.changes.none')
        : t('promptInspection.detail.changes.compared', changes.comparedVersion, formatTime(changes.comparedAt));
    [['disappeared', changes ? changes.disappeared : []], ['appeared', changes ? changes.appeared : []]]
        .forEach(([kind, findings]) => {
            document.querySelector(`[data-pi-changes-${kind}-title]`).textContent =
                t(`promptInspection.detail.changes.${kind}`, number(findings.length));
            document.querySelector(`[data-pi-changes-${kind}]`).replaceChildren(...findings.map(findingCard));
        });

    fillTable(document.querySelector('[data-pi-history]'), detail.history.map((row) => el('tr', {}, [
        el('td', {class: 'pi-code', text: row.inspectorVersion}),
        el('td', {class: 'pi-code', text: row.dictionaryVersion || '-'}),
        el('td', {}, verdictChip(row.verdict)),
        el('td', {class: 'pi-number', text: number(row.mismatchCount)}),
        el('td', {class: 'pi-number', text: number(row.unverifiableCount)}),
        el('td', {text: t(`promptInspection.trigger.${row.trigger}`)}),
        el('td', {text: formatTime(row.inspectedAt)})
    ])), 7);
}

async function load() {
    setStatus(status, t('promptInspection.common.loading'));
    try {
        render(await api(`/packages/${encodeURIComponent(packageId)}`));
        setStatus(status, '');
    } catch (error) {
        setStatus(status, t(error.status === 404 ? 'promptInspection.common.notFound' : 'promptInspection.common.error'),
            'error');
    }
}

document.querySelector('[data-pi-reinspect]').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
        await api(`/packages/${encodeURIComponent(packageId)}/reinspect`, {method: 'POST'});
        await load();
    } catch (error) {
        setStatus(status, t('promptInspection.common.error'), 'error');
    } finally {
        button.disabled = false;
    }
});

load();
