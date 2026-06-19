(function () {
    const root = document.getElementById('ai-monitor');
    if (!root) return;

    const section = root.dataset.section || 'overview';
    const period = root.dataset.period || 'day';
    const locale = document.documentElement.lang || navigator.language || 'ko-KR';
    const numberFormatter = new Intl.NumberFormat(locale);
    const decimalFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
    const percentFormatter = new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 1 });

    const statusEl = document.getElementById('ai-monitor-status');
    const kpiEl = document.getElementById('ai-monitor-kpis');
    const detailsEl = document.getElementById('ai-monitor-details');
    const rangeEl = document.getElementById('ai-monitor-range');

    fetch(`${endpointForSection(section)}?period=${encodeURIComponent(period)}`, {
        headers: { 'Accept': 'application/json' }
    })
        .then((response) => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(render)
        .catch((error) => {
            statusEl.innerHTML = `<div class="ai-monitor-band-title">${escapeHtml(label('labelUnavailable'))}</div><div class="text-sm" style="color:#f87171;">${escapeHtml(error.message)}</div>`;
        });

    function endpointForSection(value) {
        if (value === 'llm') return '/contexa/admin/api/ai-monitor/llm';
        if (value === 'correlation') return '/contexa/admin/api/ai-monitor/correlation';
        if (value === 'failures' || value === 'operations') return '/contexa/admin/api/ai-monitor/failures';
        if (value === 'readiness') return '/contexa/admin/api/ai-monitor/readiness';
        return '/contexa/admin/api/ai-monitor/overview';
    }

    function render(summary) {
        if (rangeEl && summary.from && summary.to) {
            rangeEl.textContent = `${formatDate(summary.from)} - ${formatDate(summary.to)}`;
        }
        renderStatus(summary);
        if (section === 'llm') {
            renderLlm(summary);
        } else if (section === 'correlation') {
            renderCorrelation(summary);
        } else if (section === 'failures' || section === 'operations') {
            renderFailures(summary);
        } else if (section === 'readiness') {
            renderReadiness(summary);
        } else {
            renderOverview(summary);
        }
    }

    function renderStatus(summary) {
        const profile = sectionProfile();
        const recommendation = summary.readinessRecommendation || summary.recommendation;
        const hasRecommendation = section === 'overview' || section === 'readiness';
        const statusTitle = hasRecommendation ? label('labelCurrentDecision') : label('labelScreenPurpose');
        const statusText = hasRecommendation ? friendlyRecommendation(recommendation) : profile.description;
        const tone = hasRecommendation ? recommendationTone(recommendation) : 'info';
        statusEl.innerHTML = `
            <div class="flex items-center justify-between gap-3 flex-wrap">
                <div>
                    <div class="ai-monitor-band-title">${escapeHtml(profile.title)}</div>
                    <div class="text-sm" style="color:#94a3b8;">${escapeHtml(profile.description)}</div>
                </div>
                <div>
                    <div class="ai-monitor-kpi-label" style="margin:0 0 .35rem;">${escapeHtml(statusTitle)}</div>
                    <span class="ai-monitor-status ${tone}">${escapeHtml(statusText || label('labelNoDecision'))}</span>
                </div>
            </div>`;
    }

    function renderOverview(summary) {
        const hcad = summary.hcad || {};
        const llm = summary.llm || {};
        const operations = summary.operations || {};
        const correlation = summary.correlation || {};
        renderKpis([
            [label('labelObservedRequests'), hcad.observedRequestCount],
            [label('labelHcadWindows'), hcad.candidateCount],
            [label('labelLlmCalls'), llm.totalDecisionCount],
            [label('labelUnknown'), correlation.unknownCount],
            [label('labelTimeouts'), operations.timeoutCount],
            [label('labelAverageLatency'), formatMs(operations.averageLatencyMs)]
        ]);
        detailsEl.innerHTML = [
            tableBand(label('labelDecisionPath'), llm.triggerSourceBreakdown || []),
            tableBand(label('labelTriggerRelation'), correlation.triggerRelationBreakdown || []),
            tableBand(label('labelComparisonResult'), correlation.outcomeBreakdown || [])
        ].join('');
    }

    function renderLlm(summary) {
        renderKpis([
            [label('labelLlmDecisions'), summary.totalDecisionCount],
            [label('labelHcadPretriggerDecisions'), summary.hcadPreTriggerDecisionCount],
            [label('labelProtectableDecisions'), summary.protectableDecisionCount],
            [label('labelHcadAndProtectable'), summary.hcadAndProtectableDecisionCount],
            [label('labelParserFailureRate'), formatPercent(summary.parserFailureRate)],
            [label('labelTimeoutRate'), formatPercent(summary.timeoutRate)],
            [label('labelModelUnavailableRate'), formatPercent(summary.modelUnavailableRate)],
            [label('labelAverageLatency'), formatMs(summary.averageLatencyMs)]
        ]);
        detailsEl.innerHTML = [
            tableBand(label('labelDecisionResult'), summary.finalActionBreakdown || []),
            tableBand(label('labelDecisionPath'), summary.triggerSourceBreakdown || []),
            tableBand(label('labelRiskScoreDistribution'), summary.riskScoreDistribution || []),
            tableBand(label('labelConfidenceDistribution'), summary.confidenceDistribution || [])
        ].join('');
    }

    function renderCorrelation(summary) {
        renderKpis([
            [displayKey('TP'), summary.truePositiveCount],
            [displayKey('FP'), summary.falsePositiveCount],
            [displayKey('FN'), summary.observableFalseNegativeCount],
            [displayKey('TN'), summary.trueNegativeCount],
            [label('labelUnknown'), summary.unknownCount],
            [label('labelUnobserved'), summary.unobservedCount]
        ]);
        detailsEl.innerHTML = [
            matrixBand(summary.matrixRows || []),
            tableBand(label('labelTriggerRelation'), summary.triggerRelationBreakdown || []),
            tableBand(label('labelComparisonResult'), summary.outcomeBreakdown || []),
            recentCorrelationBand(summary.recentCorrelations || [])
        ].join('');
    }

    function renderFailures(summary) {
        const operations = summary.operations || {};
        renderKpis([
            [label('labelTimeouts'), operations.timeoutCount],
            [label('labelParserFailures'), operations.parserFailureCount],
            [label('labelFallbacks'), operations.technicalFallbackCount],
            [label('labelModelUnavailable'), operations.modelUnavailableCount],
            [label('labelAverageLatency'), formatMs(operations.averageLatencyMs)]
        ]);
        detailsEl.innerHTML = [
            tableBand(label('labelMainFailureCause'), summary.explicitFailureBreakdown || []),
            tableBand(label('labelFailureType'), summary.failureTypeBreakdown || []),
            tableBand(label('labelFallbackCategory'), summary.fallbackCategoryBreakdown || [])
        ].join('');
    }

    function renderReadiness(summary) {
        renderKpis([
            [label('labelMinimumSample'), `${formatNumber(summary.hcadCandidateCount || 0)} / ${formatNumber(summary.minimumSampleSize || 0)}`],
            [label('labelHcadPrecision'), formatPercent(summary.hcadPrecision)],
            [label('labelObservableFnRate'), formatPercent(summary.observableFalseNegativeRate)],
            [label('labelUnknownRate'), formatPercent(summary.unknownRate)],
            [label('labelFailureRate'), formatPercent(summary.failureRate)],
            [label('labelTimeoutRate'), formatPercent(summary.timeoutRate)],
            [label('labelAverageLatency'), formatMs(summary.averageLatencyMs)]
        ]);
        detailsEl.innerHTML = tableBand(label('labelReadinessCriteria'), [
            { key: 'MINIMUM_SAMPLE', count: `${formatNumber(summary.hcadCandidateCount || 0)} / ${formatNumber(summary.minimumSampleSize || 0)}` },
            { key: 'HCAD_PRECISION', count: formatPercent(summary.hcadPrecision) },
            { key: 'OBSERVABLE_FN_RATE', count: formatPercent(summary.observableFalseNegativeRate) },
            { key: 'UNKNOWN_RATE', count: formatPercent(summary.unknownRate) },
            { key: 'FAILURE_RATE', count: formatPercent(summary.failureRate) },
            { key: 'TIMEOUT_RATE', count: formatPercent(summary.timeoutRate) }
        ], 6);
    }

    function renderKpis(items) {
        kpiEl.innerHTML = items.map(([labelText, value, help]) => `
            <div class="ai-monitor-kpi">
                <div class="ai-monitor-kpi-value">${escapeHtml(formatValue(value))}</div>
                <div class="ai-monitor-kpi-label">${escapeHtml(labelText)}</div>
                ${help ? `<div class="ai-monitor-kpi-help">${escapeHtml(help)}</div>` : ''}
            </div>`).join('');
    }

    function tableBand(title, rows, limit = 5) {
        const safeRows = Array.isArray(rows) ? rows.slice(0, limit) : [];
        const body = safeRows.length
            ? safeRows.map((row) => `<tr><td>${escapeHtml(displayKey(row.key || '-'))}</td><td>${escapeHtml(formatValue(row.count ?? row.candidateCount ?? 0))}</td></tr>`).join('')
            : `<tr><td colspan="2">${escapeHtml(label('labelNoData'))}</td></tr>`;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(title)}</div>
                <table class="ai-monitor-table">
                    <thead><tr><th>${escapeHtml(label('labelKey'))}</th><th>${escapeHtml(label('labelCount'))}</th></tr></thead>
                    <tbody>${body}</tbody>
                </table>
            </section>`;
    }

    function matrixBand(rows) {
        const body = rows.length
            ? rows.map((row) => `
                <tr>
                    <td>${escapeHtml(displayKey(row.key))}</td>
                    <td>${formatNumber(row.llmRiskCount || 0)}</td>
                    <td>${formatNumber(row.llmAllowCount || 0)}</td>
                    <td>${formatNumber(row.llmUnknownCount || 0)}</td>
                    <td>${formatNumber(row.llmNotCalledCount || 0)}</td>
                </tr>`).join('')
            : `<tr><td colspan="5">${escapeHtml(label('labelNoData'))}</td></tr>`;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelCorrelationMatrix'))}</div>
                <table class="ai-monitor-table">
                    <thead><tr><th>${escapeHtml(label('labelCategory'))}</th><th>${escapeHtml(label('labelLlmRisk'))}</th><th>${escapeHtml(label('labelLlmAllow'))}</th><th>${escapeHtml(label('labelLlmUnknown'))}</th><th>${escapeHtml(label('labelLlmNotCalled'))}</th></tr></thead>
                    <tbody>${body}</tbody>
                </table>
            </section>`;
    }

    function recentCorrelationBand(rows) {
        const visibleRows = rows.slice(0, 10);
        const body = visibleRows.length
            ? visibleRows.map((row) => `
                <tr>
                    <td>${escapeHtml(formatDate(row.createdAt))}</td>
                    <td>${escapeHtml(row.userId || '-')}</td>
                    <td>${escapeHtml(displayKey(row.triggerRelation || '-'))}</td>
                    <td>${escapeHtml(displayKey(row.outcomeClass || '-'))}</td>
                    <td>${escapeHtml(formatValue(row.hcadScore == null ? '-' : row.hcadScore))}</td>
                    <td>${escapeHtml(formatValue(row.llmRiskScore == null ? '-' : row.llmRiskScore))}</td>
                    <td>${escapeHtml(displayKey(row.llmFinalAction || '-'))}</td>
                </tr>`).join('')
            : `<tr><td colspan="7">${escapeHtml(label('labelNoData'))}</td></tr>`;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelRecentCorrelations'))}</div>
                <table class="ai-monitor-table">
                    <thead><tr><th>${escapeHtml(label('labelCreatedAt'))}</th><th>${escapeHtml(label('labelUser'))}</th><th>${escapeHtml(label('labelTriggerRelation'))}</th><th>${escapeHtml(label('labelOutcome'))}</th><th>${escapeHtml(label('labelHcadScore'))}</th><th>${escapeHtml(label('labelLlmRiskScore'))}</th><th>${escapeHtml(label('labelFinalAction'))}</th></tr></thead>
                    <tbody>${body}</tbody>
                </table>
            </section>`;
    }

    function sectionProfile() {
        if (section === 'llm') {
            return { title: label('labelSectionLlmTitle'), description: label('labelSectionLlmDesc') };
        }
        if (section === 'correlation') {
            return { title: label('labelSectionCorrelationTitle'), description: label('labelSectionCorrelationDesc') };
        }
        if (section === 'failures' || section === 'operations') {
            return { title: label('labelSectionFailuresTitle'), description: label('labelSectionFailuresDesc') };
        }
        if (section === 'readiness') {
            return { title: label('labelSectionReadinessTitle'), description: label('labelSectionReadinessDesc') };
        }
        return { title: label('labelSectionOverviewTitle'), description: label('labelSectionOverviewDesc') };
    }

    function friendlyRecommendation(value) {
        return displayKey(value || 'INSUFFICIENT_SAMPLE') || label('labelNoDecision');
    }

    function recommendationTone(value) {
        if (value === 'DEFAULT_ENFORCE_CANDIDATE') return 'good';
        if (value === 'LIMITED_ENFORCE_CANDIDATE' || value === 'SHADOW_STABLE') return 'warn';
        if (value === 'DO_NOT_ENFORCE' || value === 'KEEP_SHADOW') return 'bad';
        return 'info';
    }

    function displayKey(value) {
        const key = String(value || '').trim();
        if (!key) return '-';
        const candidates = [
            key,
            key.toUpperCase().replace(/[^A-Z0-9]+/g, '_'),
            key.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase()
        ];
        for (const candidate of candidates) {
            const mapped = root.dataset[`labelEnum${toDatasetSuffix(candidate)}`];
            if (mapped) return mapped;
        }
        if (/^\d+\.\d+-\d+\.\d+$/.test(key)) return key;
        return key.replaceAll('_', ' ');
    }

    function toDatasetSuffix(value) {
        return value.toLowerCase()
            .replace(/[^a-z0-9]+(.)/g, (_, chr) => chr.toUpperCase())
            .replace(/^[a-z]/, (chr) => chr.toUpperCase());
    }

    function formatDate(value) {
        if (!value) return '-';
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) return value;
        return parsed.toLocaleString();
    }

    function formatValue(value) {
        if (typeof value === 'number') return formatNumber(value);
        return value == null ? '-' : String(value);
    }

    function formatNumber(value) {
        return numberFormatter.format(value || 0);
    }

    function formatMs(value) {
        return `${decimalFormatter.format(value || 0)} ms`;
    }

    function formatPercent(value) {
        if (typeof value !== 'number' || Number.isNaN(value)) return '0%';
        return percentFormatter.format(value);
    }

    function label(key) {
        return root.dataset[key] || key;
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
