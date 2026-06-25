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
        const modeHtml = runtimeModePanel(summary);
        if (section === 'readiness') {
            statusEl.innerHTML = `
                <div>
                    <div class="ai-monitor-band-title">${escapeHtml(profile.title)}</div>
                    <div class="text-sm" style="color:#94a3b8;">${escapeHtml(profile.description)}</div>
                </div>
                ${modeHtml}`;
            return;
        }
        statusEl.innerHTML = `
            <div>
                <div class="ai-monitor-band-title">${escapeHtml(profile.title)}</div>
                <div class="text-sm" style="color:#94a3b8;">${escapeHtml(profile.description)}</div>
            </div>
            ${modeHtml}`;
    }

    function runtimeModePanel(summary) {
        const modes = summary && summary.snapshot ? summary.snapshot.runtimeModes : null;
        if (!modes) return '';
        return `
            <div class="ai-monitor-mode-grid" aria-label="${escapeHtml(label('labelModeTitle'))}">
                ${runtimeModeCard(label('labelModeHcad'), modes.hcadMode, modes.hcadEffectKey)}
                ${runtimeModeCard(label('labelModeLlm'), modes.llmMode, modes.llmEffectKey)}
            </div>`;
    }

    function runtimeModeCard(title, mode, effectKey) {
        const normalized = String(mode || '').toUpperCase();
        return `
            <div class="ai-monitor-mode-card ${escapeHtml(modeTone(normalized))}">
                <div class="ai-monitor-mode-head">
                    <span class="ai-monitor-mode-title">${escapeHtml(title)}</span>
                    <span class="ai-monitor-mode-badge">${escapeHtml(displayKey(normalized || '-'))}</span>
                </div>
                <div class="ai-monitor-mode-effect">${escapeHtml(effectText(effectKey))}</div>
            </div>`;
    }

    function effectText(effectKey) {
        if (!effectKey) return '-';
        const mapped = root.dataset[`labelModeEffect${toDatasetSuffix(effectKey)}`];
        return mapped || displayKey(effectKey);
    }

    function modeTone(mode) {
        if (mode === 'ENFORCE') return 'enforce';
        if (mode === 'SHADOW' || mode === 'OBSERVE') return 'shadow';
        if (mode === 'DISABLED') return 'disabled';
        return '';
    }

    function renderOverview(summary) {
        const hcad = summary.hcad || {};
        const llm = summary.llm || {};
        const operations = summary.operations || {};
        const correlation = summary.correlation || {};
        const metrics = correlationMetrics(correlation, hcad, llm, operations);
        const standard = summary.metrics || {};
        detailsEl.className = 'ai-monitor-dashboard';
        renderKpis([
            [label('labelRecommendation'), friendlyRecommendation(summary.readinessRecommendation), label('labelCurrentDecision')],
            [label('labelHcadPrecision'), formatMetricPercent(standard.hcadPrecision, metrics.hcadPrecision, (metrics.tp + metrics.fp) > 0), label('labelHcadPrecisionHelp')],
            [label('labelObservableFnRate'), formatMetricPercent(standard.observableFalseNegativeRate, metrics.fnRiskRate, (metrics.tp + metrics.fn) > 0), label('labelObservableFnRateHelp')],
            [label('labelUnknownRate'), formatMetricPercent(standard.unknownRate, metrics.unknownRate, metrics.comparisonAvailable), label('labelUnknownRateHelp')],
            [label('labelFailureRate'), formatMetricPercent(standard.failureRate, metrics.failureRate, (llm.totalDecisionCount || 0) > 0), label('labelFailureRateHelp')]
        ]);
        detailsEl.innerHTML = [
            flowPanel([
                flowItem(label('labelObservedRequests'), hcad.observedRequestCount || 0, label('labelFlowBase'), 1, '#22d3ee'),
                flowItem(label('labelHcadWindows'), hcad.candidateCount || 0, label('labelFlowObservedToHcad'), ratioValue(hcad.candidateCount || 0, hcad.observedRequestCount || 0), '#38bdf8'),
                flowItem(label('labelHcadAiConnected'), hcad.triggeredLlmCount || 0, label('labelFlowHcadToLlm'), ratioValue(hcad.triggeredLlmCount || 0, hcad.candidateCount || 0), '#a78bfa'),
                flowItem(label('labelLlmDecisions'), llm.totalDecisionCount || 0, label('labelFlowObservedToAi'), ratioValue(llm.totalDecisionCount || 0, Math.max(1, hcad.observedRequestCount || 0)), '#818cf8'),
                flowItem(label('labelClearOutcome'), metrics.classified, label('labelFlowLlmToClear'), ratioValue(metrics.classified, llm.totalDecisionCount || 0), '#22c55e')
            ]),
            `<div class="ai-monitor-overview-grid">
                ${agreementPanel(metrics)}
                ${qualitySignalPanel(hcad, llm, operations, metrics, standard)}
            </div>`,
            feedbackLearningPanel(summary.feedbackLearning || {})
        ].join('');
    }

    function renderLlm(summary) {
        detailsEl.className = 'ai-monitor-dashboard';
        const confirmedDecisions = confirmedDecisionCount(summary.finalActionBreakdown || []);
        renderKpis([
            [label('labelLlmDecisions'), summary.totalDecisionCount, label('labelLlmDecisionsHelp')],
            [label('labelConfirmedDecisions'), confirmedDecisions, label('labelConfirmedDecisionsHelp')],
            [label('labelHcadPretriggerDecisions'), summary.hcadPreTriggerDecisionCount, label('labelHcadPretriggerHelp')],
            [label('labelProtectableDecisions'), summary.protectableDecisionCount, label('labelProtectableDecisionsHelp')],
            [label('labelHcadAndProtectable'), summary.hcadAndProtectableDecisionCount, label('labelHcadAndProtectableHelp')],
            [label('labelAverageLatency'), formatMsOrNoData(summary.averageLatencyMs, (summary.totalDecisionCount || 0) > 0), label('labelAverageLatencyHelp')]
        ]);
        detailsEl.innerHTML = [
            `<div class="ai-monitor-overview-grid">
                ${distributionPanel(label('labelDecisionResult'), normalizeActionRows(summary.finalActionBreakdown || []), 'action')}
                ${distributionPanel(label('labelDecisionPath'), normalizeRows(summary.triggerSourceBreakdown || []), 'path')}
            </div>`,
            `<div class="ai-monitor-overview-grid">
                ${bucketChart(label('labelRiskScoreDistribution'), summary.riskScoreDistribution || [])}
                ${bucketChart(label('labelConfidenceDistribution'), summary.confidenceDistribution || [])}
            </div>`,
            `<div class="ai-monitor-overview-grid">
                ${providerPanel(summary)}
                ${llmQualityPanel(summary)}
            </div>`
        ].join('');
    }

    function renderCorrelation(summary) {
        const metrics = correlationMetrics(summary || {}, {}, {}, {});
        const standard = summary.metrics || {};
        detailsEl.className = 'ai-monitor-dashboard';
        renderKpis([
            [label('labelMatchRate'), formatMetricPercent(standard.matchRate, metrics.matchRate, metrics.classified > 0), label('labelMatchRateHelp')],
            [label('labelMismatchRate'), formatMetricPercent(standard.mismatchRate, metrics.mismatchRate, metrics.classified > 0), label('labelMismatchRateHelp')],
            [label('labelFalsePositiveRate'), formatMetricPercent(standard.falsePositiveRate, metrics.fpTriggerRate, (metrics.tp + metrics.fp) > 0), label('labelFalsePositiveRateHelp')],
            [label('labelObservableFnRate'), formatMetricPercent(standard.observableFalseNegativeRate, metrics.fnRiskRate, (metrics.tp + metrics.fn) > 0), label('labelObservableFnRateHelp')],
            [label('labelUnknownRate'), formatMetricPercent(standard.unknownRate, metrics.unknownRate, metrics.comparisonAvailable), label('labelUnknownRateHelp')]
        ]);
        detailsEl.innerHTML = [
            confusionMatrixPanel(summary || {}),
            attentionListPanel(summary.recentCorrelations || [])
        ].join('');
    }

    function renderFailures(summary) {
        const operations = summary.operations || {};
        const failureTotal = failureCount(operations);
        detailsEl.className = 'ai-monitor-dashboard';
        renderKpis([
            [label('labelTimeouts'), operations.timeoutCount, label('labelTimeoutsHelp')],
            [label('labelParserFailures'), operations.parserFailureCount, label('labelParserFailuresHelp')],
            [label('labelModelUnavailable'), operations.modelUnavailableCount, label('labelModelUnavailableHelp')],
            [label('labelAverageLatency'), formatMs(operations.averageLatencyMs), label('labelAverageLatencyHelp')]
        ]);
        detailsEl.innerHTML = [
            `<div class="ai-monitor-overview-grid">
                ${failureCausePanel(summary.explicitFailureBreakdown || [], failureTotal)}
                ${trendPanel(label('labelFailureTrend'), summary.failureTrend || [])}
            </div>`,
            `<div class="ai-monitor-overview-grid">
                ${recentFailurePanel(summary.recentFailures || [])}
                ${slowRequestPanel(summary.slowRequests || [])}
            </div>`,
            `<div class="ai-monitor-overview-grid">
                ${affectedRequestPanel(summary.affectedRequests || [])}
                ${optionalBreakdownPanel(label('labelProvider'), summary.providerBreakdown || [], label('labelProviderUnknownHelp'))}
            </div>`,
            `<div class="ai-monitor-overview-grid">
                ${optionalBreakdownPanel(label('labelModel'), summary.modelBreakdown || [], label('labelProviderUnknownHelp'))}
                ${optionalBreakdownPanel(label('labelPromptTemplate'), summary.promptTemplateBreakdown || [], label('labelNoData'))}
            </div>`
        ].join('');
    }

    function renderReadiness(summary) {
        const blockers = readinessBlockers({
            observableFalseNegativeRate: summary.observableFalseNegativeRate,
            failureRate: summary.failureRate,
            recommendation: summary.recommendation,
            hcad: {
                candidateCount: summary.hcadCandidateCount,
                precision: summary.hcadPrecision,
                unknownRate: summary.unknownRate,
                qualification: { minimumSampleSize: summary.minimumSampleSize }
            },
            llm: { totalDecisionCount: summary.llmDecisionCount, timeoutRate: summary.timeoutRate },
            operations: {
                parserFailureCount: Math.round((summary.parserFailureRate || 0) * (summary.llmDecisionCount || 0)),
                technicalFallbackCount: Math.round((summary.technicalFallbackRate || 0) * (summary.llmDecisionCount || 0)),
                timeoutCount: Math.round((summary.timeoutRate || 0) * (summary.llmDecisionCount || 0)),
                modelUnavailableCount: Math.round((summary.modelUnavailableRate || 0) * (summary.llmDecisionCount || 0)),
                averageLatencyMs: summary.averageLatencyMs
            },
            correlation: { observableFalseNegativeCount: Math.round((summary.observableFalseNegativeRate || 0) * (summary.llmDecisionCount || 0)) }
        });
        const criteria = readinessCriteria(summary);

        detailsEl.className = 'ai-monitor-dashboard';
        renderKpis([]);
        detailsEl.innerHTML = [
            executiveDecisionPanel(summary.recommendation, blockers),
            readinessVisualizationPanel(summary, criteria)
        ].join('');
    }

    function executiveDecisionPanel(recommendation, blockers) {
        const tone = recommendationTone(recommendation);
        const top = blockers.slice(0, 3);
        return `
            <section class="ai-monitor-band ai-monitor-decision-card ${tone}">
                <div class="ai-monitor-decision-head">
                    <div>
                        <div class="ai-monitor-band-title">${escapeHtml(label('labelCurrentDecision'))}</div>
                        <div class="ai-monitor-decision-value">${escapeHtml(friendlyRecommendation(recommendation))}</div>
                    </div>
                    <div class="ai-monitor-decision-caption">${escapeHtml(label('labelDecisionReasonIntro'))}</div>
                </div>
                <div class="ai-monitor-blocker-list">
                    ${(top.length ? top : [{ title: label('labelNoMajorBlocker'), detail: label('labelNoMajorBlockerDesc'), tone: 'good' }]).map(blocker => {
                        const measurement = blockerMeasurement(blocker.detail);
                        return `
                        <div class="ai-monitor-blocker ${blocker.tone || 'warn'}">
                            <div class="ai-monitor-blocker-main">
                                <strong>${escapeHtml(blocker.title)}</strong>
                                <span class="ai-monitor-blocker-value">${escapeHtml(measurement.value)}</span>
                            </div>
                            <span class="ai-monitor-blocker-criteria">${escapeHtml(measurement.criteria)}</span>
                        </div>`;
                    }).join('')}
                </div>
            </section>`;
    }

    function blockerMeasurement(detail) {
        const text = String(detail || '-').trim();
        let parts = text.match(/^(.+?)\s*<\s*(.+)$/);
        if (parts) return { value: parts[1], criteria: `${parts[2]} ${label('labelOrMore')}` };
        parts = text.match(/^(.+?)\s*>=\s*(.+)$/);
        if (parts) return { value: parts[1], criteria: `${parts[2]} ${label('labelOrLess')}` };
        parts = text.match(/^(.+?)\s*\/\s*(.+)$/);
        if (parts) return { value: parts[1], criteria: `${parts[2]} ${label('labelOrMore')}` };
        return { value: text, criteria: '-' };
    }

    function flowItem(labelText, value, rateLabel, rate, color) {
        return { label: labelText, value, rateLabel, rate, color };
    }

    function flowPanel(items) {
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewFlow'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelOverviewFlowDesc'))}</div>
                <div class="ai-monitor-funnel">
                    ${items.map((item, index) => `
                        <div class="ai-monitor-funnel-step" style="--flow-color:${item.color};">
                            <div class="ai-monitor-flow-index">${index + 1}</div>
                            <div class="ai-monitor-flow-label">${escapeHtml(item.label)}</div>
                            <div class="ai-monitor-flow-value">${escapeHtml(formatNumber(item.value))}</div>
                            <div class="ai-monitor-flow-rate">${escapeHtml(item.rateLabel)} ${escapeHtml(formatPercent(item.rate))}</div>
                            <div class="ai-monitor-flow-bar"><span style="width:${percentWidth(item.rate)}%;"></span></div>
                        </div>`).join('')}
                </div>
            </section>`;
    }

    function agreementPanel(metrics) {
        const rows = [
            { label: label('labelMatched'), value: metrics.match, color: '#22c55e' },
            { label: label('labelMismatched'), value: metrics.mismatch, color: '#ef4444' },
            { label: label('labelUnknown'), value: metrics.unknown, color: '#94a3b8' }
        ];
        const centerText = metrics.classified > 0 ? formatPercent(metrics.matchRate) : label('labelNoComparisonData');
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewOutcome'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelOverviewOutcomeDesc'))}</div>
                <div class="ai-monitor-chart-shell">
                    <div class="ai-monitor-donut" style="background:${escapeHtml(donutGradient(rows))};">
                        <div class="ai-monitor-donut-center">${escapeHtml(centerText)}</div>
                    </div>
                    <div class="ai-monitor-legend">
                        ${rows.map(row => `
                            <div class="ai-monitor-legend-row" style="--legend-color:${row.color};">
                                <span class="ai-monitor-legend-dot"></span>
                                <span>${escapeHtml(row.label)}</span>
                                <strong>${escapeHtml(formatNumber(row.value))}</strong>
                            </div>`).join('')}
                    </div>
                </div>
            </section>`;
    }

    function qualitySignalPanel(hcad, llm, operations, metrics, standard) {
        const hcadComparisonAvailable = (metrics.tp + metrics.fp) > 0;
        const llmAvailable = (llm.totalDecisionCount || 0) > 0;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelOverviewReliability'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelOverviewReliabilityDesc'))}</div>
                <div class="ai-monitor-bars">
                    ${metricBarFromMetric(label('labelHcadPrecision'), standard.hcadPrecision, metrics.hcadPrecision, hcadComparisonAvailable, metrics.hcadPrecision >= 0.80 ? 'warn' : 'bad')}
                    ${metricBarFromMetric(label('labelMismatchRate'), standard.mismatchRate, metrics.mismatchRate, metrics.classified > 0, metrics.mismatchRate >= 0.20 ? 'bad' : (metrics.mismatchRate > 0 ? 'warn' : 'good'))}
                    ${metricBarFromMetric(label('labelUnknownPressure'), standard.unknownRate, metrics.unknownRate, metrics.comparisonAvailable, metrics.unknownRate >= 0.40 ? 'bad' : (metrics.unknownRate > 0 ? 'warn' : 'good'))}
                    ${metricBarFromMetric(label('labelTimeoutPressure'), standard.timeoutRate, llm.timeoutRate || 0, llmAvailable, (llm.timeoutRate || 0) >= 0.10 ? 'bad' : ((llm.timeoutRate || 0) > 0 ? 'warn' : 'good'))}
                    ${valueRow(label('labelAverageLatency'), formatMetricMs(standard.averageLatencyMs, operations.averageLatencyMs || 0, llmAvailable), (operations.averageLatencyMs || 0) > 0 ? 'warn' : 'good')}
                </div>
            </section>`;
    }


    function feedbackLearningPanel(summary) {
        const normalCount = summary.normalPatternLearningCount || 0;
        const riskCount = summary.riskPatternLearningCount || 0;
        const excludedCount = summary.learningExcludedCount || 0;
        const cacheHit = summary.cacheHitCount || 0;
        const cacheMiss = summary.cacheMissCount || 0;
        const cacheStale = summary.cacheStaleCount || 0;
        const hasNormal = normalCount > 0;
        const hasRisk = riskCount > 0;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelFeedbackLearning'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelFeedbackLearningHelp'))}</div>
                <div class="ai-monitor-cause-grid">
                    ${feedbackCause(label('labelNormalLearning'), normalCount, label('labelNormalLearningHelp'))}
                    ${feedbackCause(label('labelRiskLearning'), riskCount, label('labelRiskLearningHelp'))}
                    ${feedbackCause(label('labelLearningExcluded'), excludedCount, label('labelLearningExcludedHelp'))}
                    ${feedbackCause(label('labelCacheHit'), cacheHit, label('labelCacheHitHelp'))}
                    ${feedbackCause(label('labelCacheMiss'), cacheMiss, label('labelCacheMissHelp'))}
                    ${feedbackCause(label('labelCacheStale'), cacheStale, label('labelCacheStaleHelp'))}
                </div>
                <div class="ai-monitor-bars" style="margin-top:1rem;">
                    ${metricBar(label('labelNormalSuppression'), hasNormal ? summary.normalSuppressionRate || 0 : 0, 'good', hasNormal ? formatPercent(summary.normalSuppressionRate || 0) : label('labelNoData'))}
                    ${metricBar(label('labelRiskHitLlm'), hasRisk ? summary.riskHitLlmConnectionRate || 0 : 0, 'warn', hasRisk ? formatPercent(summary.riskHitLlmConnectionRate || 0) : label('labelNoData'))}
                    ${metricBar(label('labelRiskHitEligible'), hasRisk ? summary.riskHitEligibleRate || 0 : 0, 'warn', hasRisk ? formatPercent(summary.riskHitEligibleRate || 0) : label('labelNoData'))}
                </div>
            </section>`;
    }

    function feedbackCause(title, value, help) {
        return `
            <div class="ai-monitor-cause">
                <strong>${escapeHtml(title)}</strong>
                <span>${escapeHtml(formatNumber(value || 0))}</span>
                <i>${escapeHtml(help)}</i>
            </div>`;
    }
    function distributionPanel(title, rows, variant) {
        const safeRows = rows.filter(row => row.count > 0).slice(0, 6);
        const total = safeRows.reduce((sum, row) => sum + row.count, 0);
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(title)}</div>
                <div class="ai-monitor-bars">
                    ${(safeRows.length ? safeRows : [{ key: label('labelNoData'), count: 0 }]).map((row, index) => {
                        const ratio = ratioValue(row.count, total);
                        return metricBar(displayKey(row.key), ratio, toneForRow(row.key, variant, index), formatNumber(row.count));
                    }).join('')}
                </div>
            </section>`;
    }

    function bucketChart(title, rows) {
        const safeRows = (rows || []).filter(row => row.key !== 'UNKNOWN').slice(0, 8);
        const total = safeRows.reduce((sum, row) => sum + (row.count || 0), 0);
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(title)}</div>
                <div class="ai-monitor-mini-bars">
                    ${(safeRows.length ? safeRows : [{ key: label('labelNoData'), count: 0 }]).map(row => `
                        <div class="ai-monitor-mini-bar">
                            <span>${escapeHtml(displayKey(row.key))}</span>
                            <div><i style="width:${percentWidth(ratioValue(row.count || 0, total))}%;"></i></div>
                            <strong>${escapeHtml(formatNumber(row.count || 0))}</strong>
                        </div>`).join('')}
                </div>
            </section>`;
    }

    function providerPanel(summary) {
        const providerRows = meaningfulRows(summary.providerBreakdown || []);
        const modelRows = meaningfulRows(summary.modelBreakdown || []);
        if (!providerRows.length && !modelRows.length) {
            return `
                <section class="ai-monitor-band">
                    <div class="ai-monitor-band-title">${escapeHtml(label('labelProvider'))}</div>
                    <div class="ai-monitor-empty-note">${escapeHtml(label('labelProviderUnknownHelp'))}</div>
                </section>`;
        }
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelProvider'))}</div>
                <div class="ai-monitor-two-stack">
                    ${simpleNamedRows(providerRows, 5)}
                    ${simpleNamedRows(modelRows, 5)}
                </div>
            </section>`;
    }

    function llmQualityPanel(summary) {
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelResponseQuality'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelQualityFailureLink'))}</div>
                <a class="ai-monitor-inline-link" href="/contexa/admin/ai-monitor/failures?period=${encodeURIComponent(period)}">${escapeHtml(label('labelOpenFailurePage'))}</a>
            </section>`;
    }

    function confusionMatrixPanel(summary) {
        const tp = summary.truePositiveCount || 0;
        const fp = summary.falsePositiveCount || 0;
        const fn = summary.observableFalseNegativeCount || 0;
        const tn = summary.trueNegativeCount || 0;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelCorrelationMatrix'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelConfusionMatrixHelp'))}</div>
                <div class="ai-monitor-confusion">
                    ${confusionCell(label('labelHcadFoundAiRisk'), label('labelTruePositiveMeaning'), tp, 'good')}
                    ${confusionCell(label('labelHcadFoundAiAllow'), label('labelFalsePositiveMeaning'), fp, 'bad')}
                    ${confusionCell(label('labelHcadMissedAiRisk'), label('labelFalseNegativeMeaning'), fn, 'bad')}
                    ${confusionCell(label('labelHcadMissedAiAllow'), label('labelTrueNegativeMeaning'), tn, 'good')}
                </div>
            </section>`;
    }

    function confusionCell(title, detail, value, tone) {
        return `
            <div class="ai-monitor-confusion-cell ${tone}">
                <strong>${escapeHtml(title)}</strong>
                <span>${escapeHtml(detail)}</span>
                <b>${escapeHtml(formatNumber(value))}</b>
            </div>`;
    }

    function notCalledPanel(rows) {
        const notCalled = (rows || [])
            .filter(row => (row.count || 0) > 0)
            .map(row => ({ key: row.key, count: row.count }));
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelNotCalledReason'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelNotCalledReasonHelp'))}</div>
                ${simpleNamedRows(notCalled, 5)}
            </section>`;
    }

    function attentionListPanel(rows) {
        const attention = (rows || [])
            .filter(row => ['FP', 'FN', 'UNKNOWN'].includes(row.outcomeClass))
            .slice(0, 10);
        const body = attention.length
            ? attention.map(row => `
                <tr>
                    <td>${escapeHtml(formatDate(row.createdAt))}</td>
                    <td>${escapeHtml(row.userId || '-')}</td>
                    <td>${escapeHtml(displayKey(row.outcomeClass || '-'))}<div class="ai-monitor-row-meta">${escapeHtml(`requestId ${row.requestId || '-'}`)}</div></td>
                    <td>${escapeHtml(formatNumber(row.hcadScore || 0))}<div class="ai-monitor-row-meta">${escapeHtml(`hcad ${row.hcadEvaluationId || '-'}`)}</div></td>
                    <td>${escapeHtml(displayKey(row.llmFinalAction || '-'))}<div class="ai-monitor-row-meta">${escapeHtml(`llm ${row.llmObservationId || '-'}`)}</div></td>
                </tr>`).join('')
            : `<tr><td colspan="5">${escapeHtml(label('labelNoData'))}</td></tr>`;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelInvestigationQueue'))}</div>
                <table class="ai-monitor-table">
                    <thead><tr><th>${escapeHtml(label('labelCreatedAt'))}</th><th>${escapeHtml(label('labelUser'))}</th><th>${escapeHtml(label('labelOutcome'))}</th><th>${escapeHtml(label('labelHcadScore'))}</th><th>${escapeHtml(label('labelFinalAction'))}</th></tr></thead>
                    <tbody>${body}</tbody>
                </table>
            </section>`;
    }

    function failureCausePanel(rows, failureTotal) {
        const safeRows = meaningfulRows(rows).slice(0, 4);
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelMainFailureCause'))}</div>
                <div class="ai-monitor-cause-grid">
                    ${(safeRows.length ? safeRows : [{ key: label('labelNoData'), count: 0 }]).map(row => `
                        <div class="ai-monitor-cause">
                            <strong>${escapeHtml(displayKey(row.key))}</strong>
                            <span>${escapeHtml(formatNumber(row.count))}</span>
                            <i>${escapeHtml(formatPercent(ratioValue(row.count, failureTotal)))}</i>
                        </div>`).join('')}
                </div>
            </section>`;
    }

    function trendPanel(title, rows) {
        const safeRows = (rows || []).slice(-12);
        const max = Math.max(1, ...safeRows.map(row => row.count || 0));
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(title)}</div>
                <div class="ai-monitor-trend">
                    ${(safeRows.length ? safeRows : [{ key: label('labelNoData'), count: 0 }]).map(row => `
                        <div class="ai-monitor-trend-bar">
                            <i style="height:${Math.max(4, Math.round(((row.count || 0) / max) * 100))}%;"></i>
                            <span>${escapeHtml(row.key)}</span>
                        </div>`).join('')}
                </div>
            </section>`;
    }

    function recentFailurePanel(rows) {
        const body = (rows || []).length
            ? rows.slice(0, 10).map(row => `
                <tr>
                    <td>${escapeHtml(formatDate(row.createdAt))}</td>
                    <td>${escapeHtml(displayKey(row.failureType || '-'))}</td>
                    <td>${escapeHtml(`${row.method || ''} ${row.path || '-'}`.trim())}</td>
                    <td>${escapeHtml(formatMs(row.latencyMs || 0))}</td>
                </tr>`).join('')
            : `<tr><td colspan="4">${escapeHtml(label('labelNoData'))}</td></tr>`;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelRecentFailures'))}</div>
                <table class="ai-monitor-table">
                    <thead><tr><th>${escapeHtml(label('labelCreatedAt'))}</th><th>${escapeHtml(label('labelFailureType'))}</th><th>${escapeHtml(label('labelRequest'))}</th><th>${escapeHtml(label('labelAverageLatency'))}</th></tr></thead>
                    <tbody>${body}</tbody>
                </table>
            </section>`;
    }

    function slowRequestPanel(rows) {
        const body = (rows || []).length
            ? rows.slice(0, 10).map(row => `
                <tr>
                    <td>${escapeHtml(formatDate(row.createdAt))}</td>
                    <td>${escapeHtml(`${row.method || ''} ${row.path || '-'}`.trim())}</td>
                    <td>${escapeHtml(formatMs(row.latencyMs || 0))}</td>
                </tr>`).join('')
            : `<tr><td colspan="3">${escapeHtml(label('labelNoData'))}</td></tr>`;
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelSlowRequests'))}</div>
                <div class="ai-monitor-band-help">${escapeHtml(label('labelSlowRequestsHelp'))}</div>
                <table class="ai-monitor-table">
                    <thead><tr><th>${escapeHtml(label('labelCreatedAt'))}</th><th>${escapeHtml(label('labelRequest'))}</th><th>${escapeHtml(label('labelAverageLatency'))}</th></tr></thead>
                    <tbody>${body}</tbody>
                </table>
            </section>`;
    }

    function affectedRequestPanel(rows) {
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelAffectedRequests'))}</div>
                ${simpleNamedRows((rows || []).map(row => ({ key: `${row.method || ''} ${row.path || '-'}`.trim(), count: row.count })), 10)}
            </section>`;
    }

    function optionalBreakdownPanel(title, rows, emptyMessage) {
        const safeRows = meaningfulRows(rows);
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(title)}</div>
                ${safeRows.length ? simpleNamedRows(safeRows, 5) : `<div class="ai-monitor-empty-note">${escapeHtml(emptyMessage)}</div>`}
            </section>`;
    }

    function criteriaChecklistPanel(criteria) {
        return `
            <section class="ai-monitor-band">
                <div class="ai-monitor-band-title">${escapeHtml(label('labelReadinessCriteria'))}</div>
                <div class="ai-monitor-criteria-grid">
                    ${criteria.map(item => `
                        <div class="ai-monitor-criterion ${item.pass ? 'good' : 'bad'}">
                            <strong>${escapeHtml(item.label)}</strong>
                            <span>${escapeHtml(item.current)} / ${escapeHtml(item.required)}</span>
                            <em>${escapeHtml(item.pass ? label('labelPassed') : item.gap)}</em>
                        </div>`).join('')}
                </div>
            </section>`;
    }

    function readinessVisualizationPanel(summary, criteria) {
        const score = readinessScore(criteria);
        const angle = Math.round(score * 3.6);
        return `
            <div class="ai-monitor-readiness-visual-grid">
                <section class="ai-monitor-band ai-monitor-readiness-gauge-card">
                    <div class="ai-monitor-band-title">${escapeHtml(label('labelReadinessScore'))}</div>
                    <div class="ai-monitor-readiness-gauge" style="--readiness-angle:${angle}deg;">
                        <div class="ai-monitor-readiness-gauge-core">
                            <strong>${escapeHtml(formatNumber(score))}%</strong>
                        </div>
                    </div>
                </section>
                <section class="ai-monitor-band">
                    <div class="ai-monitor-band-title">${escapeHtml(label('labelReadinessCriteria'))}</div>
                    <div class="ai-monitor-readiness-bars">
                        ${criteria.map(item => `
                            <div class="ai-monitor-readiness-bar-row ${item.pass ? 'good' : 'bad'}">
                                <div class="ai-monitor-readiness-bar-head">
                                    <strong>${escapeHtml(item.label)}</strong>
                                    <span>${escapeHtml(item.current)} / ${escapeHtml(item.required)}</span>
                                </div>
                                <div class="ai-monitor-readiness-track">
                                    <span style="width:${percentWidth(item.score || 0)}%;"></span>
                                </div>
                            </div>`).join('')}
                    </div>
                </section>
            </div>`;
    }

    function readinessScore(criteria) {
        if (!criteria || !criteria.length) return 0;
        const total = criteria.reduce((sum, item) => sum + Math.max(0, Math.min(1, item.score || 0)), 0);
        return Math.round((total / criteria.length) * 100);
    }

    function readinessCriteria(summary) {
        const minSample = summary.minimumSampleSize || 100;
        const sample = summary.hcadCandidateCount || 0;
        const precisionTarget = 0.80;
        const fnTarget = 0.10;
        const unknownTarget = 0.40;
        const failureTarget = 0.10;
        const decisionAvailable = (summary.llmDecisionCount || 0) > 0;
        return [
            {
                label: label('labelMinimumSample'),
                current: formatNumber(sample),
                required: formatNumber(minSample),
                pass: sample >= minSample,
                score: Math.min(1, ratioValue(sample, minSample)),
                gap: label('labelNeedMoreSamples').replace('{0}', formatNumber(Math.max(0, minSample - sample)))
            },
            percentCriterion(label('labelHcadPrecision'), summary.hcadPrecision || 0, precisionTarget, true, decisionAvailable),
            percentCriterion(label('labelObservableFnRate'), summary.observableFalseNegativeRate || 0, fnTarget, false, decisionAvailable),
            percentCriterion(label('labelUnknownRate'), summary.unknownRate || 0, unknownTarget, false, decisionAvailable),
            percentCriterion(label('labelFailureRate'), summary.failureRate || 0, failureTarget, false, decisionAvailable)
        ];
    }

    function percentCriterion(labelText, current, required, higherIsBetter, available = true) {
        if (!available) {
            return {
                label: labelText,
                current: label('labelNoDecisionData'),
                required: higherIsBetter ? `${formatPercent(required)} ${label('labelOrMore')}` : `${formatPercent(required)} ${label('labelOrLess')}`,
                pass: false,
                score: 0,
                gap: label('labelNoDecisionData')
            };
        }
        const pass = higherIsBetter ? current >= required : current <= required;
        const gapValue = higherIsBetter ? Math.max(0, required - current) : Math.max(0, current - required);
        return {
            label: labelText,
            current: formatPercent(current),
            required: higherIsBetter ? `${formatPercent(required)} ${label('labelOrMore')}` : `${formatPercent(required)} ${label('labelOrLess')}`,
            pass,
            score: higherIsBetter ? Math.min(1, ratioValue(current, required)) : (current <= required ? 1 : Math.min(1, ratioValue(required, current))),
            gap: label('labelGap').replace('{0}', formatPercent(gapValue))
        };
    }

    function readinessBlockers(context) {
        const hcad = context.hcad || {};
        const llm = context.llm || {};
        const operations = context.operations || {};
        const correlation = context.correlation || {};
        const minSample = hcad.qualification && hcad.qualification.minimumSampleSize ? hcad.qualification.minimumSampleSize : 100;
        const classified = (correlation.truePositiveCount || 0)
            + (correlation.falsePositiveCount || 0)
            + (correlation.observableFalseNegativeCount || 0)
            + (correlation.trueNegativeCount || 0);
        const fnRate = Number.isFinite(context.observableFalseNegativeRate)
            ? context.observableFalseNegativeRate
            : ratioValue(correlation.observableFalseNegativeCount || 0,
                (correlation.truePositiveCount || 0) + (correlation.observableFalseNegativeCount || 0));
        const failureRate = Number.isFinite(context.failureRate)
            ? context.failureRate
            : ratioValue(failureCount(operations), llm.totalDecisionCount || context.llmDecisionCount || 0);
        const blockers = [];
        if ((hcad.candidateCount || 0) < minSample) {
            blockers.push({
                title: label('labelBlockerSample'),
                detail: `${formatNumber(hcad.candidateCount || 0)} / ${formatNumber(minSample)}`,
                action: label('labelActionCollectMore'),
                tone: 'warn'
            });
        }
        if ((hcad.precision || 0) < 0.80) {
            blockers.push({
                title: label('labelBlockerPrecision'),
                detail: `${formatPercent(hcad.precision || 0)} < ${formatPercent(0.80)}`,
                action: label('labelActionReviewMismatch'),
                tone: 'bad'
            });
        }
        if (fnRate >= 0.10) {
            blockers.push({
                title: label('labelBlockerFn'),
                detail: `${formatPercent(fnRate)} >= ${formatPercent(0.10)}`,
                action: label('labelActionReviewMissed'),
                tone: 'bad'
            });
        }
        if ((hcad.unknownRate || 0) >= 0.40) {
            blockers.push({
                title: label('labelBlockerUnknown'),
                detail: `${formatPercent(hcad.unknownRate || 0)} >= ${formatPercent(0.40)}`,
                action: label('labelActionFixUnknown'),
                tone: 'bad'
            });
        }
        if (failureRate >= 0.10) {
            blockers.push({
                title: label('labelBlockerFailure'),
                detail: `${formatPercent(failureRate)} >= ${formatPercent(0.10)}`,
                action: label('labelActionFixFailures'),
                tone: 'bad'
            });
        }
        return blockers;
    }

    function correlationMetrics(correlation, hcad, llm, operations) {
        const tp = correlation.truePositiveCount || 0;
        const fp = correlation.falsePositiveCount || 0;
        const fn = correlation.observableFalseNegativeCount || 0;
        const tn = correlation.trueNegativeCount || 0;
        const unknown = correlation.unknownCount || 0;
        const classified = tp + fp + fn + tn;
        const comparisonTotal = classified + unknown;
        const match = tp + tn;
        const mismatch = fp + fn;
        return {
            tp,
            fp,
            fn,
            tn,
            unknown,
            classified,
            comparisonTotal,
            comparisonAvailable: comparisonTotal > 0,
            match,
            mismatch,
            hcadPrecision: ratioValue(tp, tp + fp),
            matchRate: ratioValue(match, classified),
            mismatchRate: ratioValue(mismatch, classified),
            fpTriggerRate: ratioValue(fp, tp + fp),
            fnRiskRate: ratioValue(fn, tp + fn),
            unknownRate: ratioValue(unknown, classified + unknown),
            failureRate: ratioValue(failureCount(operations || {}), (llm || {}).totalDecisionCount || 0)
        };
    }

    function normalizeRows(rows) {
        return (rows || []).map(row => ({ key: row.key, count: row.count || 0 }));
    }

    function normalizeActionRows(rows) {
        return normalizeRows(rows).map(row => ({
            key: row.key === 'BLOCK' ? 'DENY' : row.key,
            count: row.count
        }));
    }

    function confirmedDecisionCount(rows) {
        return normalizeRows(rows)
            .filter(row => {
                const key = String(row.key || '').toUpperCase();
                return key !== 'PENDING_ANALYSIS' && key !== 'UNKNOWN' && key !== 'NONE' && key !== '-';
            })
            .reduce((sum, row) => sum + (row.count || 0), 0);
    }

    function meaningfulRows(rows) {
        return (rows || []).filter(row => {
            const key = String(row.key || '').toUpperCase();
            return row.count > 0 && key !== 'NONE' && key !== 'UNKNOWN' && key !== '-';
        });
    }

    function simpleNamedRows(rows, limit) {
        const visible = (rows || []).slice(0, limit);
        if (!visible.length) {
            return `<div class="ai-monitor-empty-note">${escapeHtml(label('labelNoData'))}</div>`;
        }
        return `
            <div class="ai-monitor-simple-list">
                ${visible.map(row => `
                    <div class="ai-monitor-simple-row">
                        <span>${escapeHtml(displayKey(row.key || '-'))}</span>
                        <strong>${escapeHtml(formatNumber(row.count || 0))}</strong>
                    </div>`).join('')}
            </div>`;
    }

    function metricBar(labelText, value, tone, valueText) {
        return `
            <div class="ai-monitor-bar-row">
                <div class="ai-monitor-bar-head">
                    <span>${escapeHtml(labelText)}</span>
                    <strong>${escapeHtml(valueText || formatPercent(value))}</strong>
                </div>
                <div class="ai-monitor-bar-track">
                    <span class="ai-monitor-bar-fill ${tone === 'bad' ? 'bad' : tone === 'warn' ? 'warn' : ''}" style="width:${percentWidth(value)}%;"></span>
                </div>
            </div>`;
    }

    function metricBarOptional(labelText, value, available, tone) {
        return metricBar(labelText, available ? value : 0, available ? tone : 'warn',
                available ? formatPercent(value) : label('labelNoDecisionData'));
    }

    function metricBarFromMetric(labelText, metric, fallbackValue, fallbackAvailable, tone) {
        const available = metricAvailable(metric, fallbackAvailable);
        const value = metricValue(metric, fallbackValue);
        return metricBar(labelText, available ? value : 0, available ? tone : 'warn',
                available ? formatPercent(value) : noDataText(metric));
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

    function failureCount(operations) {
        return (operations.parserFailureCount || 0)
            + (operations.technicalFallbackCount || 0)
            + (operations.timeoutCount || 0)
            + (operations.modelUnavailableCount || 0);
    }

    function toneForRow(key, variant, index) {
        const normalized = String(key || '').toUpperCase();
        if (['DENY', 'BLOCK', 'CHALLENGE', 'PENDING_ANALYSIS'].includes(normalized)) return 'warn';
        if (['ALLOW'].includes(normalized)) return 'good';
        if (['UNKNOWN'].includes(normalized)) return 'bad';
        if (variant === 'path' && index === 0) return 'warn';
        return 'good';
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

    function formatMsOrNoData(value, available) {
        return available ? formatMs(value) : label('labelNoDecisionData');
    }

    function formatMetricMs(metric, fallbackValue, fallbackAvailable) {
        if (metric && metric.noDataReason) return noDataText(metric);
        if (metric && typeof metric.value === 'number') return formatMs(metric.value);
        return formatMsOrNoData(fallbackValue, fallbackAvailable);
    }

    function formatPercent(value) {
        if (typeof value !== 'number' || Number.isNaN(value)) return '0%';
        return percentFormatter.format(value);
    }

    function formatPercentOrNoData(value, available) {
        return available ? formatPercent(value) : label('labelNoDecisionData');
    }

    function formatMetricPercent(metric, fallbackValue, fallbackAvailable) {
        if (metric && metric.noDataReason) return noDataText(metric);
        if (metric && typeof metric.value === 'number') return formatPercent(metric.value);
        return formatPercentOrNoData(fallbackValue, fallbackAvailable);
    }

    function metricAvailable(metric, fallbackAvailable) {
        if (metric) return !metric.noDataReason && typeof metric.value === 'number';
        return fallbackAvailable;
    }

    function metricValue(metric, fallbackValue) {
        if (metric && typeof metric.value === 'number') return metric.value;
        return fallbackValue || 0;
    }

    function noDataText(metric) {
        const reason = metric && metric.noDataReason ? metric.noDataReason : 'NO_DECISION_DATA';
        const mapped = root.dataset[`labelNoData${toDatasetSuffix(reason)}`];
        return mapped || label('labelNoDecisionData');
    }

    function hasHcadComparison(hcad) {
        return ((hcad || {}).truePositiveCount || 0)
            + ((hcad || {}).falsePositiveCount || 0)
            + ((hcad || {}).observableFalseNegativeCount || 0)
            + ((hcad || {}).trueNegativeCount || 0)
            + ((hcad || {}).unknownCount || 0) > 0;
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
