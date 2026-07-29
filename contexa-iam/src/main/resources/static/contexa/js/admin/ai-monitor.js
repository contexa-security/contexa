(function () {
    'use strict';

    const root = document.getElementById('ai-monitor');
    if (!root) return;

    const section = root.dataset.section || 'overview';
    const period = root.dataset.period || 'day';
    const labels = root.dataset;
    const status = document.getElementById('ai-monitor-status');
    const kpis = document.getElementById('ai-monitor-kpis');
    const details = document.getElementById('ai-monitor-details');
    const range = document.getElementById('ai-monitor-range');
    const exportLink = document.getElementById('ai-monitor-export');
    const endpoint = `/contexa/admin/api/ai-monitor/${section}`;

    if (exportLink) {
        const exportType = section === 'overview' ? 'overview' : section;
        exportLink.href = `/contexa/admin/api/ai-monitor/export.csv?period=${encodeURIComponent(period)}&type=${encodeURIComponent(exportType)}`;
    }

    fetch(`${endpoint}?period=${encodeURIComponent(period)}`, {headers: {'Accept': 'application/json'}})
        .then(response => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(render)
        .catch(error => {
            status.innerHTML = `<div class="ai-monitor-band-title">${escapeHtml(labels.labelUnavailable || 'Unavailable')}</div><div class="ai-monitor-muted">${escapeHtml(error.message)}</div>`;
            kpis.innerHTML = '';
            details.innerHTML = '';
        });

    function render(data) {
        range.textContent = [data.from, data.to].filter(Boolean).join(' – ');
        status.innerHTML = `<span class="ai-monitor-status good">${escapeHtml(modeText(data))}</span>`;
        if (section === 'llm') renderLlm(data);
        else if (section === 'failures') renderFailures(data);
        else if (section === 'readiness') renderReadiness(data);
        else renderOverview(data);
    }

    function renderOverview(data) {
        const llm = data.llm || {};
        const metrics = data.metrics || {};
        kpis.innerHTML = [
            metricCard(labels.labelLlmDecisions, metricValue(metrics.totalAiDecisions, llm.totalDecisionCount, false)),
            metricCard(labels.labelProtectable, number(llm.protectableDecisionCount)),
            metricCard(labels.labelFailureRate, metricValue(metrics.failureRate, null, true)),
            metricCard(labels.labelTimeoutRate, metricValue(metrics.timeoutRate, null, true)),
            metricCard(labels.labelAverageLatency, milliseconds((data.operations || {}).averageLatencyMs))
        ].join('');
        details.innerHTML = [
            breakdownCard(labels.labelAction, llm.finalActionBreakdown || llm.actionBreakdown),
            breakdownCard(labels.labelProvider, llm.providerBreakdown),
            breakdownCard(labels.labelModel, llm.modelBreakdown),
            breakdownCard(labels.labelPromptTemplate, llm.promptTemplateBreakdown)
        ].join('');
    }

    function renderLlm(data) {
        kpis.innerHTML = [
            metricCard(labels.labelLlmDecisions, number(data.totalDecisionCount)),
            metricCard(labels.labelProtectable, number(data.protectableDecisionCount)),
            metricCard(labels.labelParserFailures, number(data.parserFailureCount)),
            metricCard(labels.labelFallbacks, number(data.technicalFallbackCount)),
            metricCard(labels.labelTimeouts, number(data.timeoutCount)),
            metricCard(labels.labelModelUnavailable, number(data.modelUnavailableCount)),
            metricCard(labels.labelAverageLatency, milliseconds(data.averageLatencyMs)),
            metricCard(labels.labelP95Latency, milliseconds(data.p95LatencyMs))
        ].join('');
        details.innerHTML = [
            breakdownCard(labels.labelTriggerSource, data.triggerSourceBreakdown),
            breakdownCard(labels.labelAction, data.actionBreakdown),
            breakdownCard(labels.labelProposedAction, data.proposedActionBreakdown),
            breakdownCard(labels.labelFinalAction, data.finalActionBreakdown),
            breakdownCard(labels.labelProvider, data.providerBreakdown),
            breakdownCard(labels.labelModel, data.modelBreakdown),
            breakdownCard(labels.labelPromptTemplate, data.promptTemplateBreakdown),
            breakdownCard(labels.labelRiskScore, data.riskScoreDistribution),
            breakdownCard(labels.labelConfidence, data.confidenceDistribution)
        ].join('');
    }

    function renderFailures(data) {
        const operations = data.operations || {};
        kpis.innerHTML = [
            metricCard(labels.labelParserFailures, number(operations.parserFailureCount)),
            metricCard(labels.labelFallbacks, number(operations.technicalFallbackCount)),
            metricCard(labels.labelTimeouts, number(operations.timeoutCount)),
            metricCard(labels.labelModelUnavailable, number(operations.modelUnavailableCount)),
            metricCard(labels.labelAverageLatency, milliseconds(operations.averageLatencyMs))
        ].join('');
        details.innerHTML = [
            breakdownCard(labels.labelFailureType, data.explicitFailureBreakdown || data.failureTypeBreakdown),
            breakdownCard(labels.labelFallbackCategory, data.fallbackCategoryBreakdown),
            breakdownCard(labels.labelProvider, data.providerBreakdown),
            breakdownCard(labels.labelModel, data.modelBreakdown),
            requestCard(labels.labelAffectedRequests || labels.labelFailureType, data.affectedRequests),
            failureTable(labels.labelRecentFailures || labels.labelFailureType, data.recentFailures),
            failureTable(labels.labelSlowRequests || labels.labelP95Latency, data.slowRequests)
        ].join('');
    }

    function renderReadiness(data) {
        kpis.innerHTML = [
            metricCard(labels.labelLlmDecisions, number(data.llmDecisionCount)),
            metricCard(labels.labelFailureRate, percent(data.failureRate)),
            metricCard(labels.labelTimeoutRate, percent(data.timeoutRate)),
            metricCard(labels.labelAverageLatency, milliseconds(data.averageLatencyMs)),
            metricCard(labels.labelP95Latency, milliseconds(data.p95LatencyMs))
        ].join('');
        details.innerHTML = [
            readinessCard(data),
            currentSessionCard(data.currentSession),
            previousSessionsCard(data.previousSessions),
            resetCard()
        ].join('');
        const reset = document.getElementById('ai-monitor-reset');
        if (reset) reset.addEventListener('click', resetMonitoring);
    }

    function readinessCard(data) {
        const blockers = Array.isArray(data.blockers) ? data.blockers : [];
        const rows = blockers.length ? blockers.map(item => `
            <div class="ai-monitor-list-row"><span><strong>${escapeHtml(item.title)}</strong><br><small>${escapeHtml(item.action)}</small></span><span>${escapeHtml(item.current)} / ${escapeHtml(item.required)}</span></div>`).join('')
            : `<div class="ai-monitor-muted">${escapeHtml(labels.labelNoData || '')}</div>`;
        return card(labels.labelReadiness, `<span class="ai-monitor-status ${data.recommendation === 'DO_NOT_RECOMMEND' ? 'bad' : 'good'}">${escapeHtml(data.recommendation)}</span><div class="ai-monitor-list">${rows}</div>`);
    }

    function currentSessionCard(item) {
        if (!item) return card(labels.labelCurrentSession, empty());
        return card(labels.labelCurrentSession, `<div class="ai-monitor-list">
            ${pair(labels.labelId, item.sessionId)}${pair(labels.labelFrom, item.from)}${pair(labels.labelTo, item.to)}${pair(labels.labelLlmDecisions, item.llmDecisionCount)}${pair(labels.labelReadiness, item.recommendation)}
        </div>`);
    }

    function previousSessionsCard(items) {
        if (!Array.isArray(items) || !items.length) return card(labels.labelPreviousSessions, `<div class="ai-monitor-muted">${escapeHtml(labels.labelNoPrevious || '')}</div>`);
        const rows = items.map(item => `<tr><td>${escapeHtml(item.endedAt)}</td><td>${number(item.llmDecisionCount)}</td><td>${percent(item.failureRate)}</td><td>${escapeHtml(item.recommendation)}</td></tr>`).join('');
        return card(labels.labelPreviousSessions, `<table class="ai-monitor-table"><thead><tr><th>${escapeHtml(labels.labelEndedAt)}</th><th>${escapeHtml(labels.labelLlmDecisions)}</th><th>${escapeHtml(labels.labelFailureRate)}</th><th>${escapeHtml(labels.labelReadiness)}</th></tr></thead><tbody>${rows}</tbody></table>`);
    }

    function resetCard() {
        return card(labels.labelReset, `<button type="button" class="ai-monitor-button danger" id="ai-monitor-reset">${escapeHtml(labels.labelReset)}</button>`);
    }

    function resetMonitoring() {
        if (!window.confirm(labels.labelResetConfirm || '')) return;
        const confirmationText = window.prompt(labels.labelResetConfirm || '', '');
        if (confirmationText === null) return;
        const reason = window.prompt(labels.labelResetReason || '', '');
        if (reason === null) return;
        const headers = {'Accept': 'application/json', 'Content-Type': 'application/json'};
        if (root.dataset.csrfToken) headers[root.dataset.csrfHeader || 'X-CSRF-TOKEN'] = root.dataset.csrfToken;
        fetch('/contexa/admin/api/ai-monitor/reset', {
            method: 'POST', headers,
            body: JSON.stringify({reason, confirmationText})
        }).then(response => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        }).then(() => window.location.reload()).catch(error => window.alert(`${labels.labelResetFailed || ''}${error.message}`));
    }

    function metricCard(label, value) {
        return `<div class="ai-monitor-kpi"><div class="ai-monitor-kpi-value">${escapeHtml(value)}</div><div class="ai-monitor-kpi-label">${escapeHtml(label || '')}</div></div>`;
    }

    function breakdownCard(title, items) {
        const values = Array.isArray(items) ? items : [];
        if (!values.length) return card(title, empty());
        return card(title, `<div class="ai-monitor-list">${values.map(item => pair(item.key, number(item.count))).join('')}</div>`);
    }

    function requestCard(title, items) {
        const values = Array.isArray(items) ? items : [];
        if (!values.length) return card(title, empty());
        return card(title, `<div class="ai-monitor-list">${values.map(item => pair(`${item.method || ''} ${item.path || ''}`, number(item.count))).join('')}</div>`);
    }

    function failureTable(title, items) {
        const values = Array.isArray(items) ? items : [];
        if (!values.length) return card(title, empty());
        const rows = values.map(item => `<tr><td>${escapeHtml(`${item.method || ''} ${item.path || ''}`)}</td><td>${escapeHtml(item.failureType || '')}</td><td>${escapeHtml(item.finalAction || '')}</td><td>${milliseconds(item.latencyMs)}</td><td>${escapeHtml(item.createdAt || '')}</td></tr>`).join('');
        return card(title, `<table class="ai-monitor-table"><tbody>${rows}</tbody></table>`);
    }

    function card(title, body) {
        return `<section class="ai-monitor-band"><div class="ai-monitor-band-title">${escapeHtml(title || '')}</div>${body}</section>`;
    }

    function pair(key, value) {
        return `<div class="ai-monitor-list-row"><span>${escapeHtml(key || '')}</span><strong>${escapeHtml(value)}</strong></div>`;
    }

    function modeText(data) {
        const modes = (data.snapshot || data).runtimeModes || {};
        return [modes.llmMode, modes.llmEffectKey].filter(Boolean).join(' · ') || labels.labelKeyMetrics || '';
    }

    function metricValue(metric, fallback, asPercent) {
        if (metric && metric.value !== null && metric.value !== undefined) return asPercent ? percent(metric.value) : number(metric.value);
        return fallback === null || fallback === undefined ? emptyText() : number(fallback);
    }

    function empty() { return `<div class="ai-monitor-muted">${escapeHtml(emptyText())}</div>`; }
    function emptyText() { return labels.labelNoData || '-'; }
    function number(value) { return value === null || value === undefined ? emptyText() : new Intl.NumberFormat().format(Number(value)); }
    function percent(value) { return value === null || value === undefined ? emptyText() : `${(Number(value) * 100).toFixed(1)}%`; }
    function milliseconds(value) { return value === null || value === undefined ? emptyText() : `${Number(value).toFixed(1)} ms`; }
    function escapeHtml(value) {
        return String(value === null || value === undefined ? '' : value)
            .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
    }
}());
