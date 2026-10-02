import '../common/shell.js';
import { dateTime, t } from '../common/i18n.js';
import { ApiError, request } from '../common/http.js';
import { busy, byId, element, errorNotice, notice } from '../common/ui.js';
import { renderReport, renderReviews } from '../common/report-results.js';

const query = new URLSearchParams(location.search);
let runId = query.get('run');
let report;
let versions = [];
let reviews = [];
let pendingReview;
let pendingCapture;
let feedback;

function key() { return `lab.report.pending.${runId}`; }
function rememberCapture() {
    try {
        if (pendingCapture) sessionStorage.setItem(key(), pendingCapture);
        else sessionStorage.removeItem(key());
    } catch { /* The in-page command remains available for a retry. */ }
}

function render() {
    byId('report-empty').hidden = Boolean(report);
    byId('report-empty').textContent = t('report.empty');
    byId('report-content').hidden = !report;
    if (runId) byId('report-run').href = `/run.html?id=${encodeURIComponent(runId)}`;
    if (!report) return;
    renderReport(report);
    renderReviews(reviews);
    byId('report-versions').replaceChildren(...versions.map(value => {
        const item = element('li');
        const link = element('a', dateTime(value.createdAt));
        link.href = `/report.html?id=${value.id}`;
        if (value.id === report.id) link.setAttribute('aria-current', 'page');
        item.append(link); return item;
    }));
    if (feedback) notice(byId('review-feedback'), t(feedback));
}

async function readRelated() {
    versions = await request(`/api/lab/runs/${encodeURIComponent(runId)}/reports`);
    reviews = report ? await request(`/api/lab/reports/${report.id}/assessments`) : [];
}

byId('report-capture').addEventListener('click', () => void busy(byId('report-capture'), async () => {
    pendingCapture ||= crypto.randomUUID(); rememberCapture();
    try {
        report = await request(`/api/lab/runs/${encodeURIComponent(runId)}/reports`, {
            method: 'POST', body: { commandId: pendingCapture }
        });
        pendingCapture = null; rememberCapture(); pendingReview = null; feedback = null;
        byId('review-form').reset();
        history.replaceState(null, '', `/report.html?id=${report.id}`);
        await readRelated(); render(); notice(byId('report-feedback'));
        byId('report-json').focus();
    } catch (error) { errorNotice(byId('report-feedback'), error); }
}));

byId('review-form').addEventListener('submit', event => {
    event.preventDefault();
    void busy(byId('review-submit'), async () => {
        const input = { position: byId('review-position').value, requestId: byId('review-request').value || null,
            comment: byId('review-comment').value.trim() };
        if (!input.comment) { byId('review-comment').focus(); return; }
        if (pendingReview && JSON.stringify(pendingReview.input) !== JSON.stringify(input)) {
            notice(byId('review-feedback'), t('report.changed'), 'warning'); return;
        }
        pendingReview ||= { commandId: crypto.randomUUID(), input };
        try {
            await request(`/api/lab/reports/${report.id}/assessments`, {
                method: 'POST', body: { commandId: pendingReview.commandId, ...pendingReview.input }
            });
            pendingReview = null; feedback = 'report.submitted';
            reviews = await request(`/api/lab/reports/${report.id}/assessments`);
            render();
        } catch (error) {
            if (error instanceof ApiError && error.status < 500) pendingReview = null;
            errorNotice(byId('review-feedback'), error);
        }
    });
});
document.addEventListener('lab:language', render);

try {
    if (query.has('id')) {
        report = await request(`/api/lab/reports/${encodeURIComponent(query.get('id'))}`);
        runId = report.runId;
    }
    if (!runId) throw new Error('Missing run');
    await readRelated();
    if (!report && versions.length) report = await request(`/api/lab/reports/${versions[0].id}`);
    if (report && !reviews.length) reviews = await request(`/api/lab/reports/${report.id}/assessments`);
    try { pendingCapture = sessionStorage.getItem(key()); } catch { /* Optional command persistence. */ }
    byId('report-capture').disabled = false;
    render();
} catch (error) {
    byId('report-empty').hidden = true;
    errorNotice(byId('report-feedback'), error);
}
