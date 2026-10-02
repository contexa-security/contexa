import { renderLearningEvidence } from '../common/request-learning.js';
import { renderRequestOutcome } from '../common/request-outcome.js';
import { renderDecisions } from '../common/request-decision.js';
import { renderContextEvidence } from '../common/request-context.js';
import { renderModelEvidence } from '../common/request-model.js';
import { ObservationStream } from '../common/observation-stream.js';
import { dateTime, t } from '../common/i18n.js';
import { localLink, request } from '../common/http.js';
import { appendDefinition, badge, busy, byId, element, notice } from '../common/ui.js';
import { query, showEnvironment, showWorkError } from '../common/work.js';

const id = query.get('id');
const arm = query.get('arm');
let evidencePath;
let observationPath;
let evidence;
let portalUrl;
let evidenceRole;
let businessOrigin;
let receipts;
let receiptUnavailable = false;
let transferChart;
let stream;
let streamState = 'connecting';
let refreshPending = false;
let refreshQueued = false;
let refreshTimer;
let contentKey;

function queueRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => void refresh(true), 150);
}
function streamStatus(state) {
    streamState = state;
    byId('live-status').textContent = t(`work.stream.${state}`);
}

function source(value, key) {
    const details = element('details');
    if (key) details.dataset.sourceKey = key;
    details.append(element('summary', t('work.source')), element('pre', JSON.stringify(value, null, 2)));
    return details;
}
function render() {
    if (!evidence) return;
    byId('request-evidence').hidden = false;
    byId('record-toolbar').hidden = false;
    byId('request-id').textContent = id;
    const opened = new Set([...document.querySelectorAll('details[open][data-source-key]')].map(node => node.dataset.sourceKey));
    const focused = document.activeElement?.closest('details[data-source-key]')?.dataset.sourceKey;
    const health = evidence.collectionHealth;
    const collectionState = health?.state || 'NOT_CAPTURED';
    byId('collection-notice').textContent = t(`work.collection.${collectionState}`);
    byId('collection-notice').className = collectionState === 'NO_GAPS_REPORTED' ? 'notice' : 'notice warning';
    byId('collection-source').textContent = JSON.stringify(health || { state: 'NOT_CAPTURED' }, null, 2);
    const http = evidence.http;
    renderRequestOutcome(evidence, businessOrigin);
    byId('http-badge').replaceChildren(badge(http.httpStatus == null ? t('unknown') : `HTTP ${http.httpStatus}`, http.httpStatus >= 400 ? 'warning' : ''));
    const details = byId('http-details'); details.replaceChildren();
    appendDefinition(details, t('work.http'), `${http.method} ${http.path}`);
    appendDefinition(details, t('work.started'), dateTime(http.startedAt));
    appendDefinition(details, t('work.finished'), dateTime(http.completedAt));
    renderTransfer();
    renderApproval();
    renderContextEvidence(evidence);
    renderModelEvidence(evidence);
    renderLearningEvidence(evidence);
    const baseline = evidence.role === 'baseline';
    byId('analysis-empty').textContent = t(baseline ? 'work.baseline.note' : 'work.no.analysis');
    byId('analysis-empty').hidden = evidence.analysisEvents.length > 0;
    byId('provider-note').hidden = baseline || (evidence.modelBoundary?.observations?.length || 0) > 0;
    const events = byId('analysis-events'); events.replaceChildren();
    evidence.analysisEvents.forEach(event => {
        const item = element('li');
        item.append(element('strong', t(`work.event.${event.kind}`)), element('span', dateTime(event.observedAt), 'event-time'), source(event, event.id));
        if (event.kind === 'GENERATED_PROMPT') item.prepend(element('p', t('work.prompt.note'), 'small muted'));
        if (event.kind === 'MODEL_EXECUTION') item.prepend(element('p', t('work.pipeline.note'), 'small muted')); 
        events.append(item);
    });
    byId('decision-empty').textContent = t(evidence.decisionReadState === 'UNAVAILABLE' ? 'work.decision.unavailable' : baseline ? 'work.baseline.note' : 'work.no.final');
    byId('decision-empty').hidden = evidence.decisions.length > 0;
    renderDecisions(evidence);
    byId('snapshot').textContent = evidence.snapshot ? JSON.stringify(evidence.snapshot, null, 2) : t('none');
    document.querySelectorAll('details[data-source-key]').forEach(node => {
        if (opened.has(node.dataset.sourceKey)) node.open = true;
        if (focused === node.dataset.sourceKey) node.querySelector('summary')?.focus({ preventScroll: true });
    });
    streamStatus(streamState);
}
function renderApproval() {
    const approval = evidence.snapshot?.approval;
    byId('approval-evidence').hidden = !approval;
    if (!approval) return;
    byId('approval-evidence-status').replaceChildren(badge(t(`approval.status.${approval.status}`), approval.status === 'APPROVED' ? 'good' : ''));
    const facts = byId('approval-evidence-facts');
    facts.replaceChildren();
    appendDefinition(facts, t('approval.observed'), dateTime(approval.observedAt));
    if (approval.approvalId) appendDefinition(facts, t('approval.reference'), approval.approvalId);
    if (approval.reviewer) appendDefinition(facts, t('approval.reviewer'), approval.reviewer);
    if (approval.expiresAt) appendDefinition(facts, t('approval.expires'), dateTime(approval.expiresAt));
}

function renderTransfer() {
    const hasDownload = evidence.http.path.endsWith('/download');
    byId('transfer-evidence').hidden = !hasDownload;
    transferChart?.destroy(); transferChart = null;
    if (!hasDownload) return;
    const sourceFile = evidence.download;
    const receipt = receipts?.[0];
    const written = evidence.http.httpStatus === 200 && evidence.http.outputCaptureState === 'SERVLET_OUTPUT_STREAM'
        ? evidence.http.servletOutputBytes : null;
    const received = receipt && ['COMPLETE', 'PARTIAL'].includes(receipt.state) ? receipt.receivedBytes : null;
    const details = byId('transfer-details'); details.replaceChildren();
    appendDefinition(details, t('download.prepared'), sourceFile ? `${sourceFile.preparedBytes} B` : t('unknown'));
    appendDefinition(details, t('download.written'), written == null ? t('unknown') : `${written} B`);
    appendDefinition(details, t('download.reported'), received == null ? t('unknown') : `${received} B`);
    if (sourceFile?.preparedItems != null) appendDefinition(details, t('export.prepared.items'), String(sourceFile.preparedItems));
    if (sourceFile) appendDefinition(details, t('download.file.reuse'), t(sourceFile.reused ? 'download.reused' : 'download.created'));
    notice(byId('receipt-state'), t(receiptUnavailable ? 'download.receipt.unavailable' : receipt ? 'download.receipt.source' : 'download.receipt.missing'), receipt ? '' : 'warning');
    if (sourceFile || written != null || received != null) {
        byId('transfer-chart').hidden = false;
        transferChart = new Chart(byId('transfer-chart'), {
            type: 'bar', data: { labels: [t('download.prepared'), t('download.written'), t('download.reported')],
                datasets: [{ data: [sourceFile?.preparedBytes ?? null, written, received], backgroundColor: ['#52727d', '#006e60', '#87621e'], borderRadius: 4 }] },
            options: { responsive: true, maintainAspectRatio: false, animation: false, indexAxis: 'y',
                plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, title: { display: true, text: 'Bytes' } }, y: { grid: { display: false } } } }
        });
    } else byId('transfer-chart').hidden = true;
    const sources = byId('transfer-sources'); sources.replaceChildren(source({ file: sourceFile, receipt: receipt || null }, 'transfer'));
}

async function refresh(background = false) {
    if (refreshPending) { refreshQueued = true; return; }
    refreshPending = true;
    if (!background) notice(byId('feedback'), t('work.loading'));
    try {
        evidence = await request(evidencePath);
        receiptUnavailable = false; receipts = null;
        if (evidence.http.path.endsWith('/download')) {
            try { receipts = await request(`/api/lab/workspaces/requests/${evidenceRole}/${id}/receipts`, { origin: portalUrl }); }
            catch { receiptUnavailable = true; }
        }
        const nextKey = JSON.stringify([evidence, receipts, receiptUnavailable]);
        notice(byId('feedback'));
        if (nextKey !== contentKey) { contentKey = nextKey; render(); }
        if (!stream) {
            stream = new ObservationStream(observationPath, portalUrl, queueRefresh, streamStatus);
            stream.open();
        }
    } catch (error) {
        const unavailable = [401, 403, 404].includes(error?.status);
        if (unavailable) {
            stream?.stop();
            stream = null;
            clearTimeout(refreshTimer);
            refreshQueued = false;
            evidence = null;
            contentKey = null;
            transferChart?.destroy();
            transferChart = null;
            byId('request-evidence').hidden = true;
            byId('record-toolbar').hidden = true;
            byId('request-id').textContent = '';
            showWorkError(error);
        } else if (background) {
            notice(byId('feedback'), t('work.stream.unavailable'), 'warning');
        } else {
            byId('record-toolbar').hidden = false;
            showWorkError(error);
        }
    } finally {
        refreshPending = false;
        if (refreshQueued) { refreshQueued = false; queueRefresh(); }
    }
}
byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
document.addEventListener('lab:language', render);
try {
    const identity = await request('/api/lab/identity');
    const role = identity.role === 'portal' ? arm : identity.role;
    evidenceRole = role; portalUrl = identity.portalUrl;
    businessOrigin = role === 'baseline' ? identity.baselineUrl : identity.contexaUrl;
    if (!['baseline', 'contexa'].includes(role)) throw new Error('UNKNOWN_ARM');
    showEnvironment(role);
    byId('connect-link').href = localLink('/connect.html', identity.portalUrl);
    byId('breadcrumb').querySelector('a').href = localLink('/projects.html', role === 'baseline' ? identity.baselineUrl : identity.contexaUrl);
    evidencePath = identity.role === 'portal'
        ? `/api/lab/workspaces/requests/${role}/${encodeURIComponent(id)}`
        : `/api/work/requests/${encodeURIComponent(id)}`;
    observationPath = `/api/lab/workspaces/requests/${role}/${encodeURIComponent(id)}/events`;
    await refresh();
}
catch (error) { showWorkError(error); }
