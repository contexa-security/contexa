(function () {
    const root = document.getElementById('hcad-monitor');
    if (!root) return;

    const period = root.dataset.period || 'day';
    const formatter = new Intl.NumberFormat('en-US');
    const percentFormatter = new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 1 });
    const decimalFormatter = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 });

    const statusEl = document.getElementById('hcad-status');
    const kpiEl = document.getElementById('hcad-kpis');
    const signalEl = document.getElementById('hcad-signals');
    const resourceEl = document.getElementById('hcad-resources');
    const userSessionEl = document.getElementById('hcad-user-sessions');
    const unknownEl = document.getElementById('hcad-unknown');
    const recentEl = document.getElementById('hcad-recent');
    const rangeEl = document.getElementById('hcad-range');
    const exportEl = document.getElementById('hcad-export');

    if (exportEl) {
        exportEl.href = `/contexa/admin/api/security-monitor/hcad/summary.csv?period=${encodeURIComponent(period)}`;
    }

    fetch(`/contexa/admin/api/security-monitor/hcad/summary?period=${encodeURIComponent(period)}`, {
        headers: { 'Accept': 'application/json' }
    })
        .then((response) => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(render)
        .catch((error) => {
            statusEl.innerHTML = `<div class="hcad-band-title">HCAD metrics unavailable</div><div class="text-sm" style="color:#f87171;">${escapeHtml(error.message)}</div>`;
        });

    function render(summary) {
        if (rangeEl) {
            rangeEl.textContent = `${formatDate(summary.from)} - ${formatDate(summary.to)}`;
        }
        renderStatus(summary);
        renderKpis(summary);
        renderBreakdown(signalEl, summary.signalBreakdown || [], 4, (item) => [
            item.key || '-',
            formatter.format(item.candidateCount || 0),
            percentFormatter.format(item.precision || 0),
            formatter.format(item.falsePositiveCount || 0)
        ]);
        renderBreakdown(resourceEl, summary.resourceBreakdown || [], 4, (item) => [
            `${item.method || ''} ${item.path || '-'}`.trim(),
            formatter.format(item.candidateCount || 0),
            percentFormatter.format(item.precision || 0),
            formatter.format(item.duplicateSuppressedCount || 0)
        ]);
        renderBreakdown(userSessionEl, summary.userSessionBreakdown || [], 5, (item) => [
            item.userId || '-',
            shortHash(item.contextBindingHash || '-'),
            formatter.format(item.candidateCount || 0),
            formatter.format(item.duplicateSuppressedCount || 0),
            percentFormatter.format(item.precision || 0)
        ]);
        renderUnknown(summary.unknownEvaluations || []);
        renderRecent(summary.recentEvaluations || []);
    }

    function renderStatus(summary) {
        const recommendation = summary.recommendation || 'INSUFFICIENT_SAMPLE';
        const tone = recommendationTone(recommendation);
        const sample = summary.candidateCount || 0;
        const minSample = summary.qualification ? summary.qualification.minimumSampleSize : 100;
        statusEl.innerHTML = `
            <div class="flex items-center justify-between gap-3 flex-wrap">
                <div>
                    <div class="hcad-band-title">Promotion Readiness</div>
                    <div class="text-sm" style="color:#94a3b8;">mode ${escapeHtml(summary.currentMode || 'UNKNOWN')}, sample ${formatter.format(sample)} / ${formatter.format(minSample)}, precision ${percentFormatter.format(summary.precision || 0)}</div>
                </div>
                <span class="hcad-status ${tone}">${escapeHtml(recommendation.replaceAll('_', ' '))}</span>
            </div>`;
    }

    function renderKpis(summary) {
        const kpis = [
            ['HCAD windows', summary.candidateCount],
            ['Observed requests', summary.observedRequestCount],
            ['LLM calls', summary.triggeredLlmCount],
            ['Precision', percentFormatter.format(summary.precision || 0)],
            ['False positive', summary.falsePositiveCount],
            ['Observable FN', summary.observableFalseNegativeCount],
            ['True negative', summary.trueNegativeCount],
            ['Unknown', percentFormatter.format(summary.unknownRate || 0)],
            ['Avg latency', `${decimalFormatter.format(summary.averageLlmLatencyMs || 0)} ms`],
            ['Duplicates', summary.duplicateSuppressedCount],
            ['Waste cost', `$${decimalFormatter.format(summary.estimatedWasteCostUsd || 0)}`]
        ];
        kpiEl.innerHTML = kpis.map(([label, value]) => `
            <div class="hcad-kpi">
                <div class="hcad-kpi-value">${escapeHtml(formatValue(value))}</div>
                <div class="hcad-kpi-label">${escapeHtml(label)}</div>
            </div>`).join('');
    }

    function renderBreakdown(tbody, items, colspan, rowFactory) {
        if (!tbody) return;
        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="${colspan || 4}">No data</td></tr>`;
            return;
        }
        tbody.innerHTML = items.map((item) => {
            const cells = rowFactory(item).map((value) => `<td>${escapeHtml(formatValue(value))}</td>`).join('');
            return `<tr>${cells}</tr>`;
        }).join('');
    }

    function renderUnknown(items) {
        if (!unknownEl) return;
        if (!items.length) {
            unknownEl.innerHTML = '<tr><td colspan="5">No unknown evaluations</td></tr>';
            return;
        }
        unknownEl.innerHTML = items.map((item) => `
            <tr>
                <td>${escapeHtml(formatDate(item.createdAt))}</td>
                <td>${escapeHtml(item.userId || '-')}</td>
                <td>${escapeHtml(`${item.method || ''} ${item.path || '-'}`.trim())}</td>
                <td>${escapeHtml(unknownCause(item))}</td>
                <td>${escapeHtml(item.earlyAnalysisScore == null ? '-' : `${item.earlyAnalysisScore} / ${item.band || '-'}`)}</td>
            </tr>`).join('');
    }

    function renderRecent(items) {
        if (!recentEl) return;
        if (!items.length) {
            recentEl.innerHTML = '<tr><td colspan="7">No recent evaluations</td></tr>';
            return;
        }
        recentEl.innerHTML = items.map((item) => `
            <tr>
                <td>${escapeHtml(formatDate(item.createdAt))}</td>
                <td>${escapeHtml(item.userId || '-')}</td>
                <td>${escapeHtml(item.method || '-')}</td>
                <td>${escapeHtml(item.path || '-')}</td>
                <td>${escapeHtml(item.earlyAnalysisScore == null ? '-' : `${item.earlyAnalysisScore} / ${item.band || '-'}`)}</td>
                <td>${escapeHtml(decisionSummary(item))}</td>
                <td><span class="hcad-status ${outcomeTone(item.outcomeClass)}">${escapeHtml(item.outcomeClass || 'UNKNOWN')}</span></td>
            </tr>`).join('');
    }

    function recommendationTone(value) {
        if (value === 'DEFAULT_ENFORCE_CANDIDATE') return 'good';
        if (value === 'LIMITED_ENFORCE_CANDIDATE' || value === 'SHADOW_STABLE') return 'warn';
        if (value === 'KEEP_SHADOW') return 'bad';
        return 'info';
    }

    function decisionSummary(item) {
        if (item.llmParserFailure) return `${item.llmAction || 'UNKNOWN'} / parser`;
        if (item.llmTechnicalFallback) return `${item.llmAction || 'UNKNOWN'} / fallback`;
        return item.llmAction || (item.triggeredLlm ? 'pending' : '-');
    }

    function unknownCause(item) {
        if (item.llmParserFailure) return `parser ${item.llmFallbackCategory || ''}`.trim();
        if (item.llmTechnicalFallback) return `fallback ${item.llmFallbackCategory || ''}`.trim();
        return item.llmAction || (item.triggeredLlm ? 'pending' : '-');
    }

    function outcomeTone(value) {
        if (value === 'TP' || value === 'TN') return 'good';
        if (value === 'FP' || value === 'FN') return 'bad';
        return 'info';
    }

    function formatDate(value) {
        if (!value) return '-';
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) return value;
        return parsed.toLocaleString();
    }

    function formatValue(value) {
        if (typeof value === 'number') return formatter.format(value);
        return value == null ? '-' : String(value);
    }

    function shortHash(value) {
        if (!value || value === '-') return '-';
        const text = String(value);
        return text.length > 12 ? `${text.slice(0, 12)}...` : text;
    }

    function escapeHtml(value) {
        return String(value)
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }
})();
