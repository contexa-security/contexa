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
        const classifiedCount = (correlation.truePositiveCount || 0)
            + (correlation.falsePositiveCount || 0)
            + (correlation.observableFalseNegativeCount || 0)
            + (correlation.trueNegativeCount || 0);
        const failureCount = (operations.parserFailureCount || 0)
            + (operations.technicalFallbackCount || 0)
            + (operations.timeoutCount || 0)
            + (operations.modelUnavailableCount || 0);
        const failureRate = ratioValue(failureCount, llm.totalDecisionCount || 0);
        const minSample = hcad.qualification && hcad.qualification.minimumSampleSize
            ? hcad.qualification.minimumSampleSize
            : 100;
        const sampleCoverage = ratioValue(hcad.candidateCount || 0, minSample);
        detailsEl.className = 'ai-monitor-dashboard';
        renderKpis([
            [label('labelObservedRequests'), hcad.observedRequestCount],
            [label('labelHcadWindows'), hcad.candidateCount],
            [label('labelLlmCalls'), llm.totalDecisionCount],
            [label('labelHcadPrecision'), formatPercent(hcad.precision)],
            [label('labelUnknown'), correlation.unknownCount],
            [label('labelTimeouts'), operations.timeoutCount],
            [label('labelAverageLatency'), formatMs(operations.averageLatencyMs)]
        ]);
        detailsEl.innerHTML = [
            `<div class="ai-monitor-overview-top">
                ${readinessPanel(summary.readinessRecommendation, sampleCoverage, hcad.precision || 0, hcad.unknownRate || 0, failureRate)}
                ${flowPanel([
                    {
                        label: label('labelObservedRequests'),
                        value: hcad.observedRequestCount || 0,
                        rateLabel: label('labelFlowBase'),
                        rate: 1,
                        color: '#22d3ee'
                    },
                    {
                        label: label('labelHcadWindows'),
                        value: hcad.candidateCount || 0,
                        rateLabel: label('labelFlowObservedToHcad'),
                        rate: ratioValue(hcad.candidateCount || 0, hcad.observedRequestCount || 0),
                        color: '#38bdf8'
                    },
                    {
                        label: label('labelLlmCalls'),
                        value: llm.totalDecisionCount || 0,
                        rateLabel: label('labelFlowHcadToLlm'),
                        rate: ratioValue(llm.totalDecisionCount || 0, hcad.candidateCount || 0),
                        color: '#a78bfa'
                    },
                    {
                        label: label('labelClearOutcome'),
                        value: classifiedCount,
                        rateLabel: label('labelFlowLlmToClear'),
                        rate: ratioValue(classifiedCount, llm.totalDecisionCount || 0),
                        color: '#22c55e'
                    }
                ])}
            </div>`,
            `<div class="ai-monitor-overview-grid">
                ${outcomePanel(correlation)}
                ${reliabilityPanel([
                    {
                        label: label('labelHcadPrecision'),
                        value: hcad.precision || 0,
                        tone: (hcad.precision || 0) >= 0.95 ? 'good' : ((hcad.precision || 0) >= 0.80 ? 'warn' : 'bad')
                    },
                    {
                        label: label('labelUnknownPressure'),
                        value: hcad.unknownRate || 0,
                        tone: (hcad.unknownRate || 0) >= 0.40 ? 'bad' : ((hcad.unknownRate || 0) > 0 ? 'warn' : 'good')
                    },
                    {
                        label: label('labelFailurePressure'),
                        value: failureRate,
                        tone: failureRate >= 0.10 ? 'bad' : (failureRate > 0 ? 'warn' : 'good')
                    },
                    {
                        label: label('labelTimeoutPressure'),
                        value: llm.timeoutRate || 0,
                        tone: (llm.timeoutRate || 0) >= 0.10 ? 'bad' : ((llm.timeoutRate || 0) > 0 ? 'warn' : 'good')
                    }
                ], operations, llm)}
            </div>`
        ].join('');
    }

    function renderLlm(summary) {
        detailsEl.className = 'ai-monitor-grid';
        renderKpis([
            [label('labelLlmDecisions'), summary.totalDecisionCount],
            [label('labelHcadPretriggerDecisions'), summary.hcadPreTriggerDecisionCount],
            [label('labelProtectableDecisions'), summary.protectableDecisionCount],
            [label('labelHcadAndProtectable'), summary.hcadAndProtectableDecisionCount],
            [label('labelParserFailureRate'), formatPercent(summary.parserFailureRate)],
            [label('labelFallbackRate'), formatPercent(summary.technicalFallbackRate)],
            [label('labelTimeoutRate'), formatPercent(summary.timeoutRate)],
            [label('labelModelUnavailableRate'), formatPercent(summary.modelUnavailableRate)],
            [label('labelAverageLatency'), formatMs(summary.averageLatencyMs)],
            [label('labelP95Latency'), formatMs(summary.p95LatencyMs)]
        ]);
        detailsEl.innerHTML = [
            tableBand(label('labelDecisionResult'), summary.finalActionBreakdown || []),
            tableBand(label('labelActionBreakdown'), summary.actionBreakdown || []),
            tableBand(label('labelProposedActionBreakdown'), summary.proposedActionBreakdown || []),
            tableBand(label('labelDecisionPath'), summary.triggerSourceBreakdown || []),
            tableBand(label('labelProvider'), summary.providerBreakdown || []),
            tableBand(label('labelModel'), summary.modelBreakdown || []),
            tableBand(label('labelPromptTemplate'), summary.promptTemplateBreakdown || []),
            tableBand(label('labelRiskScoreDistribution'), summary.riskScoreDistribution || []),
            tableBand(label('labelConfidenceDistribution'), summary.confidenceDistribution || [])
        ].join('');
    }

    function renderCorrelation(summary) {
        detailsEl.className = 'ai-monitor-grid';
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
        detailsEl.className = 'ai-monitor-grid';
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
            tableBand(label('labelFallbackCategory'), summary.fallbackCategoryBreakdown || []),
            tableBand(label('labelProvider'), summary.providerBreakdown || []),
            tableBand(label('labelModel'), summary.modelBreakdown || []),
            tableBand(label('labelPromptTemplate'), summary.promptTemplateBreakdown || [])
        ].join('');
    }

    function renderReadiness(summary) {
        detailsEl.className = 'ai-monitor-grid';
        renderKpis([
            [label('labelMinimumSample'), `${formatNumber(summary.hcadCandidateCount || 0)} / ${formatNumber(summary.minimumSampleSize || 0)}`],
            [label('labelHcadPrecision'), formatPercent(summary.hcadPrecision)],
            [label('labelObservableFnRate'), formatPercent(summary.observableFalseNegativeRate)],
            [label('labelUnknownRate'), formatPercent(summary.unknownRate)],
            [label('labelFailureRate'), formatPercent(summary.failureRate)],
            [label('labelParserFailureRate'), formatPercent(summary.parserFailureRate)],
            [label('labelFallbackRate'), formatPercent(summary.technicalFallbackRate)],
            [label('labelTimeoutRate'), formatPercent(summary.timeoutRate)],
            [label('labelModelUnavailableRate'), formatPercent(summary.modelUnavailableRate)],
            [label('labelAverageLatency'), formatMs(summary.averageLatencyMs)],
            [label('labelP95Latency'), formatMs(summary.p95LatencyMs)]
        ]);
        detailsEl.innerHTML = tableBand(label('labelReadinessCriteria'), [
            { key: 'MINIMUM_SAMPLE', count: `${formatNumber(summary.hcadCandidateCount || 0)} / ${formatNumber(summary.minimumSampleSize || 0)}` },
            { key: 'HCAD_PRECISION', count: formatPercent(summary.hcadPrecision) },
            { key: 'OBSERVABLE_FN_RATE', count: formatPercent(summary.observableFalseNegativeRate) },
            { key: 'UNKNOWN_RATE', count: formatPercent(summary.unknownRate) },
            { key: 'FAILURE_RATE', count: formatPercent(summary.failureRate) },
            { key: 'PARSER_FAILURE_RATE', count: formatPercent(summary.parserFailureRate) },
            { key: 'TECHNICAL_FALLBACK_RATE', count: formatPercent(summary.technicalFallbackRate) },
            { key: 'TIMEOUT_RATE', count: formatPercent(summary.timeoutRate) },
            { key: 'MODEL_UNAVAILABLE_RATE', count: formatPercent(summary.modelUnavailableRate) },
            { key: 'P95_LATENCY', count: formatMs(summary.p95LatencyMs) }
        ], 10);
    }

    function readinessPanel(recommendation, sampleCoverage, precision, unknownRate, failureRate) {
        const tone = recommendationTone(recommendation);
        return `
            <section class="ai-monitor-band ai-monitor-judgement">
                <div>
                    <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewReadiness'))}</div>
                    <div class="ai-monitor-judgement-value">${escapeHtml(friendlyRecommendation(recommendation))}</div>
                    <div class="ai-monitor-judgement-sub">${escapeHtml(label('labelOverviewReadinessDesc'))}</div>
                </div>
                <div class="ai-monitor-bars">
                    ${metricBar(label('labelSampleCoverage'), sampleCoverage, sampleCoverage >= 1 ? 'good' : 'warn')}
                    ${metricBar(label('labelHcadPrecision'), precision, precision >= 0.95 ? 'good' : (precision >= 0.80 ? 'warn' : 'bad'))}
                    ${metricBar(label('labelUnknownPressure'), unknownRate, unknownRate >= 0.40 ? 'bad' : (unknownRate > 0 ? 'warn' : 'good'))}
                    ${metricBar(label('labelFailurePressure'), failureRate, failureRate >= 0.10 ? 'bad' : (failureRate > 0 ? 'warn' : 'good'))}
                </div>
                <div class="ai-monitor-dashboard-note">
                    <span class="ai-monitor-status ${tone}">${escapeHtml(friendlyRecommendation(recommendation))}</span>
                </div>
            </section>`;
    }

    function flowPanel(items) {
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewFlow'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelOverviewFlowDesc'))}</div>
                <div class="ai-monitor-flow">
                    ${items.map((item) => `
                        <div class="ai-monitor-flow-step" style="--flow-color:${item.color};">
                            <div class="ai-monitor-flow-label">${escapeHtml(item.label)}</div>
                            <div class="ai-monitor-flow-value">${escapeHtml(formatNumber(item.value))}</div>
                            <div class="ai-monitor-flow-rate">${escapeHtml(item.rateLabel)} ${escapeHtml(formatPercent(item.rate))}</div>
                            <div class="ai-monitor-flow-bar"><span style="width:${percentWidth(item.rate)}%;"></span></div>
                        </div>`).join('')}
                </div>
            </section>`;
    }

    function outcomePanel(correlation) {
        const rows = [
            { label: displayKey('TP'), value: correlation.truePositiveCount || 0, color: '#22c55e' },
            { label: displayKey('FP'), value: correlation.falsePositiveCount || 0, color: '#f59e0b' },
            { label: displayKey('FN'), value: correlation.observableFalseNegativeCount || 0, color: '#ef4444' },
            { label: displayKey('TN'), value: correlation.trueNegativeCount || 0, color: '#38bdf8' },
            { label: label('labelUnknown'), value: correlation.unknownCount || 0, color: '#94a3b8' }
        ];
        const total = rows.reduce((sum, row) => sum + row.value, 0);
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewOutcome'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelOverviewOutcomeDesc'))}</div>
                <div class="ai-monitor-chart-shell">
                    <div class="ai-monitor-donut" style="background:${escapeHtml(donutGradient(rows))};">
                        <div class="ai-monitor-donut-center">${escapeHtml(formatNumber(total))}</div>
                    </div>
                    <div class="ai-monitor-legend">
                        ${rows.map((row) => `
                            <div class="ai-monitor-legend-row" style="--legend-color:${row.color};">
                                <span class="ai-monitor-legend-dot"></span>
                                <span>${escapeHtml(row.label)}</span>
                                <strong>${escapeHtml(formatNumber(row.value))}</strong>
                            </div>`).join('')}
                    </div>
                </div>
            </section>`;
    }

    function reliabilityPanel(items, operations, llm) {
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewReliability'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelOverviewReliabilityDesc'))}</div>
                <div class="ai-monitor-bars">
                    ${items.map((item) => metricBar(item.label, item.value, item.tone)).join('')}
                    ${valueRow(label('labelAverageLatency'), formatMs(operations.averageLatencyMs || 0), (operations.averageLatencyMs || 0) > 0 ? 'warn' : 'good')}
                    ${valueRow(label('labelP95Latency'), formatMs(llm.p95LatencyMs || 0), (llm.p95LatencyMs || 0) > 0 ? 'warn' : 'good')}
                </div>
            </section>`;
    }

    function metricBar(labelText, value, tone) {
        return `
            <div class="ai-monitor-bar-row">
                <div class="ai-monitor-bar-head">
                    <span>${escapeHtml(labelText)}</span>
                    <strong>${escapeHtml(formatPercent(value))}</strong>
                </div>
                <div class="ai-monitor-bar-track">
                    <span class="ai-monitor-bar-fill ${tone === 'bad' ? 'bad' : tone === 'warn' ? 'warn' : ''}" style="width:${percentWidth(value)}%;"></span>
                </div>
            </div>`;
    }

    function valueRow(labelText, value, tone) {
        return `
            <div class="ai-monitor-bar-row">
                <div class="ai-monitor-bar-head">
                    <span>${escapeHtml(labelText)}</span>
                    <strong>${escapeHtml(value)}</strong>
                </div>
                <div class="ai-monitor-meter">
                    <span class="ai-monitor-meter-fill ${tone === 'bad' ? 'bad' : tone === 'warn' ? 'warn' : ''}" style="width:${tone === 'good' ? 8 : 36}%;"></span>
                </div>
            </div>`;
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
        if (key.startsWith('WINDOW ')) {
            return `${label('labelScreenOrApi')} ${key.substring('WINDOW '.length)}`;
        }
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

    function ratioValue(numerator, denominator) {
        if (!denominator || denominator <= 0) return 0;
        return numerator / denominator;
    }

    function percentWidth(value) {
        const normalized = typeof value === 'number' && Number.isFinite(value) ? value : 0;
        return Math.max(0, Math.min(100, Math.round(normalized * 100)));
    }

    function donutGradient(rows) {
        const total = rows.reduce((sum, row) => sum + (row.value || 0), 0);
        if (total <= 0) {
            return 'conic-gradient(#334155 0deg 360deg)';
        }
        let cursor = 0;
        const stops = rows
            .filter((row) => row.value > 0)
            .map((row) => {
                const start = cursor;
                const end = cursor + (row.value / total) * 360;
                cursor = end;
                return `${row.color} ${start.toFixed(1)}deg ${end.toFixed(1)}deg`;
            });
        return `conic-gradient(${stops.join(', ')})`;
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
