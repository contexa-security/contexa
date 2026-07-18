import { $, escapeHtml, ensureArray, rawText } from '../verification-ui-common.js';
import { getJson, publicError } from './prompt-quality-api.js';
import { ensureBundle, t } from './prompt-quality-i18n.js';

export async function bootSummaryPage(endpoint, renderer) {
    const root = document.querySelector('[data-pqa-page]');
    if (!root) {
        return;
    }
    await prepareBundle(root);
    removeSuppressedSummary(root);
    setStatus(root, 'loading',
            t('enterprise.pqa.common.status.loading'),
            t('enterprise.pqa.common.status.loadingDetail.page'));
    if (!endpoint) {
        await renderer(root);
        setStatus(root, 'success',
                t('enterprise.pqa.common.status.success'),
                t('enterprise.pqa.common.status.successDetail'));
        return;
    }
    try {
        const payload = await getJson(endpoint);
        if (shouldRenderSummary(root)) {
            renderSummary(root, payload.summary);
        }
        await renderer(root, payload);
        setStatus(root, 'success',
                t('enterprise.pqa.common.status.success'),
                t('enterprise.pqa.common.status.successDetail'));
    }
    catch (error) {
        logClientFailure(root, 'summary', error, { endpoint });
        setStatus(root, 'error',
                t('enterprise.pqa.common.status.error'),
                publicError(error));
    }
}

export async function bootDetailPage(endpoint, renderer) {
    const root = document.querySelector('[data-pqa-page]');
    if (!root) {
        return;
    }
    await prepareBundle(root);
    removeSuppressedSummary(root);
    setStatus(root, 'loading',
            t('enterprise.pqa.common.status.loading'),
            t('enterprise.pqa.common.status.loadingDetail.detail'));
    try {
        const payload = await getJson(endpoint);
        if (shouldRenderSummary(root)) {
            renderSummary(root, payload.summary);
        }
        await renderer(root, payload);
        setStatus(root, 'success',
                t('enterprise.pqa.common.status.success'),
                t('enterprise.pqa.common.status.successDetail.detail'));
    }
    catch (error) {
        logClientFailure(root, 'detail', error, { endpoint });
        setStatus(root, 'error',
                t('enterprise.pqa.common.status.errorDetail'),
                publicError(error));
    }
}

async function prepareBundle(root) {
    try {
        await ensureBundle();
    }
    catch (error) {
        logClientFailure(root, 'bundle', error);
        const title = t('enterprise.pqa.common.status.bundleError');
        setStatus(root, 'error',
                title,
                publicError(error));
    }
}

export function renderSummary(root, summary) {
    const target = $(root, '[data-pqa-summary]');
    if (!target) {
        return;
    }
    target.innerHTML = `
        <article class="pqa-summary-item">
            <span>${escapeHtml(t('enterprise.pqa.common.summary.total'))}</span>
            <strong>${escapeHtml(summary?.totalCount ?? 0)}</strong>
        </article>
        <article class="pqa-summary-item">
            <span>${escapeHtml(t('enterprise.pqa.common.summary.ready'))}</span>
            <strong>${escapeHtml(summary?.readyCount ?? 0)}</strong>
        </article>
        <article class="pqa-summary-item">
            <span>${escapeHtml(t('enterprise.pqa.common.summary.blocked'))}</span>
            <strong>${escapeHtml(summary?.blockedCount ?? 0)}</strong>
        </article>
    `;
}

function shouldRenderSummary(root) {
    if (root?.dataset?.pqaSuppressSummary === 'true') {
        return false;
    }
    return !['resolution-hub', 'prompt-issues', 'pre-input-issues', 'issue-detail'].includes(root?.dataset?.pqaPage);
}

function removeSuppressedSummary(root) {
    if (shouldRenderSummary(root)) {
        return;
    }
    root?.querySelectorAll('[data-pqa-summary], .pqa-summary-strip').forEach(node => node.remove());
}

export function renderTable(root, headers, rows, emptyMessage) {
    const target = $(root, '[data-pqa-content]');
    if (!target) {
        return;
    }
    const safeRows = ensureArray(rows);
    if (!safeRows.length) {
        target.innerHTML = `<div class="pqa-empty"><p>${escapeHtml(emptyMessage)}</p></div>`;
        return;
    }
    target.innerHTML = `
        <table class="pqa-table">
            <thead><tr>${headers.map(header => `<th>${escapeHtml(header)}</th>`).join('')}</tr></thead>
            <tbody>${safeRows.join('')}</tbody>
        </table>
    `;
}

export function renderKeyValues(items) {
    return `
        <dl class="pqa-key-values">
            ${ensureArray(items).map(item => `
                <div>
                    <dt>${escapeHtml(item.label)}</dt>
                    <dd>${escapeHtml(displayValue(item.value))}</dd>
                </div>
            `).join('')}
        </dl>
    `;
}

export function renderJsonBlock(label, value) {
    return `
        <details class="pqa-disclosure">
            <summary>${escapeHtml(label)}</summary>
            <pre class="pqa-json">${escapeHtml(JSON.stringify(value ?? {}, null, 2))}</pre>
        </details>
    `;
}

// Korean status keywords preserve compatibility with localized server payloads.
const TONE_KEYWORDS = {
    ready: ['ready', 'issued', 'enabled', 'approved', 'pass', 'passed', 'success', 'allow', 'active',
            '통과', '승인', '정상', '허용', '활성', '발급'],
    blocked: ['blocked', 'denied', 'fail', 'failed', 'error', 'critical', 'expired', 'reject',
            '차단', '실패', '위험', '거부', '만료', '오류'],
    reverify: ['reverify', 'expiring', 'review', 'warning',
            '재검증', '만료예정', '검토', '경고'],
    pending: ['pending', 'waiting', 'queued', 'discovered', 'draft',
            '대기', '준비', '검사중', '초안']
};

function resolveTone(raw, explicit) {
    if (explicit) {
        return explicit;
    }
    const lower = raw.toLowerCase();
    for (const tone of ['ready', 'blocked', 'reverify', 'pending']) {
        if (TONE_KEYWORDS[tone].some(keyword => lower.includes(keyword.toLowerCase()) || raw.includes(keyword))) {
            return tone;
        }
    }
    return 'neutral';
}

export function badge(value, options) {
    const raw = displayValue(value);
    const tone = resolveTone(raw, options && options.tone);
    return `<span class="pqa-badge ${tone}">${escapeHtml(raw)}</span>`;
}

function displayValue(value) {
    return rawText(value) ?? t('enterprise.pqa.common.missingLabel');
}

const SPINNER_SVG = `<svg class="pqa-status-icon spin" style="width:18px;height:18px;color:#60a5fa;flex-shrink:0;" fill="none" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><circle style="opacity:0.25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path style="opacity:0.75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`;
const SUCCESS_SVG = `<svg class="pqa-status-icon" style="width:18px;height:18px;color:#34d399;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>`;
const ERROR_SVG = `<svg class="pqa-status-icon" style="width:18px;height:18px;color:#f87171;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;

export function setStatus(root, tone, title, detail) {
    const status = $(root, '[data-pqa-status]');
    if (!status) {
        return;
    }
    status.classList.remove('loading', 'success', 'error');
    status.classList.add(tone);
    
    let icon = '';
    if (tone === 'loading') {
        icon = SPINNER_SVG;
    } else if (tone === 'success') {
        icon = SUCCESS_SVG;
    } else if (tone === 'error') {
        icon = ERROR_SVG;
    }
    
    status.innerHTML = `
        <div class="pqa-status-content" style="display:flex;align-items:center;gap:0.75rem;">
            ${icon}
            <div style="display:flex;flex-direction:column;gap:0.15rem;min-width:0;">
                <strong style="margin:0;line-height:1.2;font-size:0.95rem;font-weight:700;color:var(--pqa-text-strong);">${escapeHtml(title)}</strong>
                <span style="margin:0;line-height:1.3;font-size:0.85rem;color:var(--pqa-text-muted);word-break:break-all;">${escapeHtml(detail)}</span>
            </div>
        </div>
    `;
}

function logClientFailure(root, scope, error, details = {}) {
    const diagnostics = {
        scope,
        page: root?.dataset?.pqaPage || 'unknown',
        endpoint: details.endpoint || null,
        message: error?.message || String(error),
        stack: error?.stack || null,
        location: typeof window !== 'undefined' ? window.location.href : null,
        documentCharset: typeof document !== 'undefined' ? document.characterSet : null,
        contentType: typeof document !== 'undefined' ? document.contentType : null,
        moduleUrl: import.meta.url,
        rootTag: root?.tagName || null,
        loadedAt: new Date().toISOString()
    };
    if (typeof window !== 'undefined') {
        window.__PQA_LAST_CLIENT_ERROR__ = diagnostics;
    }
    if (typeof console !== 'undefined' && typeof console.error === 'function') {
        console.error('[PQA] client page failure', diagnostics);
    }
}
