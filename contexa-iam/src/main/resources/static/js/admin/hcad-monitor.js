(function () {
    const root = document.getElementById('hcad-monitor');
    if (!root) return;

    const period = root.dataset.period || 'day';
    const locale = document.documentElement.lang || navigator.language || 'ko-KR';
    const formatter = new Intl.NumberFormat(locale);
    const percentFormatter = new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 1 });
    const decimalFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
    const labels = root.dataset;
    const pageSize = 10;

    let recentEvaluations = [];
    let currentPage = 0;
    let expandedEvaluationId = null;

    const statusEl = document.getElementById('hcad-status');
    const kpiEl = document.getElementById('hcad-kpis');
    const signalEl = document.getElementById('hcad-signals');
    const resourceEl = document.getElementById('hcad-resources');
    const scoreBandEl = document.getElementById('hcad-score-band-distribution');
    const recentEl = document.getElementById('hcad-recent');
    const rangeEl = document.getElementById('hcad-range');
    const exportEl = document.getElementById('hcad-export');
    const prevEl = document.getElementById('hcad-prev');
    const nextEl = document.getElementById('hcad-next');
    const pageStatusEl = document.getElementById('hcad-page-status');

    if (exportEl) {
        exportEl.href = `/contexa/admin/api/security-monitor/hcad/summary.csv?period=${encodeURIComponent(period)}`;
    }
    if (prevEl) {
        prevEl.textContent = label('labelPrev');
        prevEl.addEventListener('click', () => {
            if (currentPage > 0) {
                currentPage -= 1;
                expandedEvaluationId = null;
                renderRecent();
            }
        });
    }
    if (nextEl) {
        nextEl.textContent = label('labelNext');
        nextEl.addEventListener('click', () => {
            if ((currentPage + 1) * pageSize < recentEvaluations.length) {
                currentPage += 1;
                expandedEvaluationId = null;
                renderRecent();
            }
        });
    }
    if (recentEl) {
        recentEl.addEventListener('click', (event) => {
            const button = event.target.closest('[data-hcad-detail]');
            if (!button) return;
            const id = button.getAttribute('data-hcad-detail');
            expandedEvaluationId = expandedEvaluationId === id ? null : id;
            renderRecent();
        });
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
            statusEl.innerHTML = `<div class="hcad-band-title">${escapeHtml(label('labelUnavailable'))}</div><div class="text-sm" style="color:#f87171;">${escapeHtml(error.message)}</div>`;
        });

    function render(summary) {
        if (rangeEl) {
            rangeEl.textContent = `${formatDate(summary.from)} - ${formatDate(summary.to)}`;
        }
        recentEvaluations = Array.isArray(summary.recentEvaluations) ? summary.recentEvaluations : [];
        currentPage = 0;
        expandedEvaluationId = null;

        renderStatus(summary);
        renderKpis(summary);
        renderScoreBandDistribution(scoreBandEl, summary.scoreBandDistribution || []);
        renderSignals(summary);
        renderResources(summary.resourceBreakdown || []);
        renderRecent();
    }

    function renderStatus(summary) {
        const recommendation = summary.recommendation || 'INSUFFICIENT_SAMPLE';
        const sample = summary.candidateCount || 0;
        const minSample = summary.qualification ? summary.qualification.minimumSampleSize : 100;
        const comparisonAvailable = hasComparison(summary);
        statusEl.innerHTML = `
            <div class="flex items-center justify-between gap-3 flex-wrap">
                <div>
                    <div class="hcad-band-title">${escapeHtml(label('labelPromotionReadiness'))}</div>
                    <div class="text-sm" style="color:#94a3b8;">
                        ${escapeHtml(label('labelMode'))} ${escapeHtml(friendlyMode(summary.currentMode || 'UNKNOWN'))},
                        ${escapeHtml(label('labelSample'))} ${formatter.format(sample)} / ${formatter.format(minSample)},
                        ${escapeHtml(label('labelPrecision'))} ${escapeHtml(formatPercentOrNoData(summary.precision || 0, comparisonAvailable))}
                    </div>
                </div>
                <span class="hcad-status ${recommendationTone(recommendation)}">${escapeHtml(recommendationLabel(recommendation))}</span>
            </div>`;
    }

    function renderKpis(summary) {
        const comparisonAvailable = hasComparison(summary);
        const kpis = [
            [label('labelHcadWindows'), summary.candidateCount, label('labelEvaluatedHelp')],
            [label('labelLlmCalls'), summary.triggeredLlmCount, label('labelLlmHelp')],
            [label('labelFalsePositive'), summary.falsePositiveCount, label('labelFalsePositiveHelp')],
            [label('labelObservableFn'), summary.observableFalseNegativeCount, label('labelObservableFnHelp')],
            [label('labelUnknown'), formatPercentOrNoData(summary.unknownRate || 0, comparisonAvailable), label('labelUnknownHelp')]
        ];
        kpiEl.innerHTML = kpis.map(([text, value, help]) => `
            <div class="hcad-kpi">
                <div class="hcad-kpi-value">${escapeHtml(formatValue(value))}</div>
                <div class="hcad-kpi-label">${escapeHtml(text)}</div>
                <div class="hcad-kpi-help">${escapeHtml(help)}</div>
            </div>`).join('');
    }

    function renderDistribution(container, items, band) {
        if (!container) return;
        const rows = (items || []).filter(item => (item.count || 0) > 0);
        const total = rows.reduce((sum, item) => sum + (item.count || 0), 0);
        if (!rows.length) {
            container.innerHTML = `<div class="hcad-simple-meta">${escapeHtml(label('labelNoData'))}</div>`;
            return;
        }
        container.innerHTML = rows.map((item) => {
            const ratio = total <= 0 ? 0 : (item.count || 0) / total;
            return `
                <div class="hcad-bar-row">
                    <div class="hcad-bar-head">
                        <span>${escapeHtml(band ? friendlyBand(item.key) : item.key)}</span>
                        <strong>${escapeHtml(formatter.format(item.count || 0))}</strong>
                    </div>
                    <div class="hcad-bar-track"><span class="hcad-bar-fill" style="width:${percentWidth(ratio)}%;"></span></div>
                </div>`;
        }).join('');
    }

    function renderScoreBandDistribution(container, items) {
        if (!container) return;
        const rows = (items || []).filter(item => (item.totalCount || 0) > 0);
        if (!rows.length) {
            container.innerHTML = `<div class="hcad-simple-meta">${escapeHtml(label('labelNoData'))}</div>`;
            return;
        }
        const bands = [
            ['lowCount', 'low', label('labelBandLow')],
            ['mediumCount', 'medium', label('labelBandMedium')],
            ['highCount', 'high', label('labelBandHigh')],
            ['redlineCount', 'redline', label('labelBandRedline')],
            ['unknownCount', 'unknown', label('labelBandUnknown')]
        ];
        const legend = `<div class="hcad-score-band-legend">${bands.map(([, cssClass, text]) => `<span><i class="${cssClass}"></i>${escapeHtml(text)}</span>`).join('')}</div>`;
        const body = rows.map((item) => {
            const total = item.totalCount || 0;
            const segments = bands
                .map(([key, cssClass, text]) => {
                    const count = item[key] || 0;
                    if (count <= 0 || total <= 0) return '';
                    const width = Math.max(1, Math.min(100, (count / total) * 100));
                    return `<span class="hcad-score-band-segment ${cssClass}" style="width:${width}%;" title="${escapeHtml(text)} ${escapeHtml(formatter.format(count))}"></span>`;
                })
                .join('');
            return `
                <div class="hcad-score-band-row">
                    <div class="hcad-score-band-bucket">${escapeHtml(scoreBucketLabel(item.scoreBucket))}</div>
                    <div class="hcad-score-band-track">${segments}</div>
                    <div class="hcad-score-band-total">${escapeHtml(formatter.format(total))}</div>
                </div>`;
        }).join('');
        container.innerHTML = body + legend;
    }

    function renderSignals(summary) {
        if (!signalEl) return;
        const signalRows = renderBreakdownRows(summary.signalBreakdown || [], (item) => ({
            title: friendlySignal(item.key || '-'),
            meta: `${label('labelCandidateRequests')} ${formatter.format(item.candidateCount || 0)} / ${label('labelAiConfirmedRisk')} ${formatter.format(item.truePositiveCount || 0)} / ${label('labelFalsePositive')} ${formatter.format(item.falsePositiveCount || 0)}`,
            value: formatter.format(item.candidateCount || 0)
        }));
        const nonTriggerRows = renderCountRows(summary.nonTriggerReasonBreakdown || [], (item) => ({
            title: friendlyNonTriggerReason(item.key),
            meta: nonTriggerHelp(item.key),
            value: formatter.format(item.count || 0)
        }));
        const evidenceRows = renderCountRows(summary.evidenceCoverageBreakdown || [], (item) => ({
            title: friendlyEvidenceGap(item.key),
            meta: evidenceHelp(item.key),
            value: formatter.format(item.count || 0)
        }));
        signalEl.innerHTML = `
            ${miniSection(label('labelSignalEvidence'), signalRows)}
            ${miniSection(label('labelNonTriggerReason'), nonTriggerRows)}
            ${miniSection(label('labelEvidenceCoverage'), evidenceRows)}
        `;
    }

    function renderResources(items) {
        renderSimpleBreakdown(resourceEl, items, (item) => {
            return {
                title: formatResource(item.method, item.path),
                meta: `${label('labelCandidateRequests')} ${formatter.format(item.candidateCount || 0)} / ${label('labelAiConfirmedRisk')} ${formatter.format(item.truePositiveCount || 0)} / ${label('labelFalsePositive')} ${formatter.format(item.falsePositiveCount || 0)}`,
                value: formatter.format(item.candidateCount || 0)
            };
        });
    }

    function renderSimpleBreakdown(container, items, rowFactory) {
        if (!container) return;
        const visible = (items || []).filter(item => (item.candidateCount || 0) > 0).slice(0, 5);
        if (!visible.length) {
            container.innerHTML = `<div class="hcad-simple-meta">${escapeHtml(label('labelNoData'))}</div>`;
            return;
        }
        container.innerHTML = renderBreakdownRows(visible, rowFactory);
    }

    function renderBreakdownRows(items, rowFactory) {
        const visible = (items || []).filter(item => (item.candidateCount || 0) > 0).slice(0, 5);
        if (!visible.length) {
            return `<div class="hcad-simple-meta">${escapeHtml(label('labelNoData'))}</div>`;
        }
        return visible.map((item) => {
            const row = rowFactory(item);
            const title = row.htmlTitle ? row.title : escapeHtml(row.title);
            return `
                <div class="hcad-simple-row">
                    <div>
                        <div class="hcad-simple-title">${title}</div>
                        <div class="hcad-simple-meta">${escapeHtml(row.meta)}</div>
                    </div>
                    <div class="hcad-simple-value">${escapeHtml(row.value)}</div>
                </div>`;
        }).join('');
    }

    function renderCountRows(items, rowFactory) {
        const visible = (items || []).filter(item => (item.count || 0) > 0).slice(0, 5);
        if (!visible.length) {
            return `<div class="hcad-simple-meta">${escapeHtml(label('labelNoData'))}</div>`;
        }
        return visible.map((item) => {
            const row = rowFactory(item);
            return `
                <div class="hcad-simple-row">
                    <div>
                        <div class="hcad-simple-title">${escapeHtml(row.title)}</div>
                        <div class="hcad-simple-meta">${escapeHtml(row.meta)}</div>
                    </div>
                    <div class="hcad-simple-value">${escapeHtml(row.value)}</div>
                </div>`;
        }).join('');
    }

    function miniSection(title, body) {
        return `
            <div class="hcad-mini-section">
                <div class="hcad-mini-title">${escapeHtml(title)}</div>
                ${body}
            </div>`;
    }

    function renderRecent() {
        if (!recentEl) return;
        if (!recentEvaluations.length) {
            recentEl.innerHTML = `<tr><td colspan="8">${escapeHtml(label('labelNoRecent'))}</td></tr>`;
            updatePagination();
            return;
        }
        const pageRows = recentEvaluations.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
        recentEl.innerHTML = pageRows.map((item, index) => {
            const rowId = item.evaluationId || `${currentPage}-${index}`;
            const request = `${item.method || ''} ${item.path || '-'}`.trim();
            return `
                <tr>
                    <td>${escapeHtml(formatDate(item.createdAt))}</td>
                    <td>${escapeHtml(item.userId || '-')}</td>
                    <td><div class="hcad-request-line">${escapeHtml(request)}</div></td>
                    <td>${escapeHtml(scoreText(item))}</td>
                    <td>${renderReason(item)}</td>
                    <td>${escapeHtml(item.promptContextContractVersion || '-')}</td>
                    <td><span class="hcad-status ${outcomeTone(item.outcomeClass)}">${escapeHtml(outcomeLabel(item.outcomeClass, item.triggeredLlm))}</span></td>
                    <td><button type="button" class="hcad-detail-button" data-hcad-detail="${escapeHtml(rowId)}">${escapeHtml(expandedEvaluationId === rowId ? label('labelCloseDetail') : label('labelViewDetail'))}</button></td>
                </tr>
                ${expandedEvaluationId === rowId ? detailRow(item) : ''}`;
        }).join('');
        updatePagination();
    }

    function detailRow(item) {
        return `
            <tr class="hcad-detail-row">
                <td colspan="8">
                    <div class="hcad-detail-panel">
                        ${detailItem(label('labelEvaluationId'), item.evaluationId)}
                        ${detailItem(label('labelRequestId'), item.requestId)}
                        ${detailItem(label('labelMode'), friendlyMode(item.mode || '-'))}
                        ${detailItem(label('labelTriggered'), item.triggeredLlm === true ? label('labelTriggered') : label('labelNotTriggered'))}
                        ${detailItem(label('labelDuplicateSuppressed'), item.duplicateSuppressed === true ? label('labelYes') : label('labelNo'))}
                        ${detailItem(label('labelNonTriggerReason'), friendlyNonTriggerReason(item.nonTriggerReason))}
                        ${detailItem(label('labelEvidenceGap'), formatList(item.evidenceGaps, friendlyEvidenceGap))}
                        ${detailItem(label('labelAnchorSignals'), formatList(item.anchorSignals, friendlySignal))}
                        ${detailItem(label('labelCorroboratingSignals'), formatList(item.corroboratingSignals, friendlySignal))}
                        ${detailItem(label('labelFinalAction'), displayOutcomeAction(item.llmAction))}
                        ${detailItem(label('labelRiskScore'), item.llmRiskScore == null ? '-' : decimalFormatter.format(item.llmRiskScore))}
                        ${detailItem(label('labelConfidence'), item.llmConfidence == null ? '-' : percentFormatter.format(item.llmConfidence))}
                        ${detailItem(label('labelFallback'), fallbackSummary(item))}
                        ${detailItem(label('labelDecidedAt'), formatDate(item.decidedAt))}
                    </div>
                </td>
            </tr>`;
    }

    function detailItem(title, value) {
        return `
            <div class="hcad-detail-item">
                <span>${escapeHtml(title)}</span>
                <strong>${escapeHtml(value == null || value === '' ? '-' : value)}</strong>
            </div>`;
    }

    function updatePagination() {
        const totalPages = Math.max(1, Math.ceil(recentEvaluations.length / pageSize));
        if (prevEl) prevEl.disabled = currentPage <= 0;
        if (nextEl) nextEl.disabled = currentPage >= totalPages - 1;
        if (pageStatusEl) {
            pageStatusEl.textContent = label('labelPageStatus')
                .replace('{0}', formatter.format(Math.min(currentPage + 1, totalPages)))
                .replace('{1}', formatter.format(totalPages));
        }
    }

    function renderReason(item) {
        const codes = Array.isArray(item.reasonCodes) ? item.reasonCodes : [];
        const readable = codes.map(friendlySignal).filter(Boolean);
        const reason = readable.length
            ? readable.join(', ')
            : friendlyNonTriggerReason(item.nonTriggerReason);
        const baseline = item.baselineComparisonSummary ? `<div class="hcad-simple-meta">${escapeHtml(item.baselineComparisonSummary)}</div>` : '';
        return `<div class="hcad-simple-title">${escapeHtml(reason)}</div>${baseline}`;
    }

    function formatList(values, mapper) {
        if (!Array.isArray(values) || !values.length) {
            return '-';
        }
        return values.map(mapper).filter(Boolean).join(', ');
    }

    function scoreText(item) {
        const score = item.earlyAnalysisScore == null ? '-' : formatter.format(item.earlyAnalysisScore);
        const band = item.band ? friendlyBand(item.band) : '-';
        return `${label('labelScore')} ${score} / ${label('labelBand')} ${band}`;
    }

    function displayOutcomeAction(value) {
        const normalized = String(value || '').trim().toUpperCase();
        if (normalized === 'ALLOW') return label('labelActionAllow');
        if (normalized === 'CHALLENGE') return label('labelActionChallenge');
        if (normalized === 'BLOCK' || normalized === 'DENY') return label('labelActionDeny');
        if (normalized === 'PENDING_ANALYSIS') return label('labelActionPending');
        return value || '-';
    }

    function fallbackSummary(item) {
        const parts = [];
        if (item.llmParserFailure === true) parts.push(label('labelParserFailure'));
        if (item.llmTechnicalFallback === true) parts.push(label('labelTechnicalFallback'));
        if (item.llmFallbackCategory) parts.push(item.llmFallbackCategory);
        return parts.length ? parts.join(' / ') : label('labelNo');
    }

    function friendlySignal(value) {
        const normalized = String(value || '').trim().toUpperCase();
        const known = {
            PREVIOUS_PATH_JUMP: label('labelSignalPreviousPathJump'),
            REQUEST_BURST: label('labelSignalRequestBurst'),
            RAPID_SEQUENCE: label('labelSignalRapidSequence'),
            IMPOSSIBLE_TRAVEL: label('labelSignalImpossibleTravel'),
            RECENT_PERMISSION_CHANGE: label('labelSignalRecentPermissionChange'),
            FAILED_LOGIN_BURST: label('labelSignalFailedLoginBurst'),
            AUTH_CONTEXT_INCONSISTENT: label('labelSignalAuthContextInconsistent'),
            PRIVILEGED_AUTHORIZATION: label('labelSignalPrivilegedAuthorization'),
            FRESH_MFA_REQUIRED: label('labelSignalFreshMfaRequired'),
            LOW_AUTH_ASSURANCE: label('labelSignalLowAuthAssurance'),
            BASELINE_MATERIAL_MISMATCH: label('labelSignalBaselineMismatch'),
            SEMANTIC_EVIDENCE_MISMATCH: label('labelSignalSemanticMismatch'),
            SEMANTIC_RISK_SIMILARITY: label('labelSignalSemanticRiskSimilarity')
        };
        return known[normalized] || value || '-';
    }

    function friendlyNonTriggerReason(value) {
        const normalized = String(value || '').trim().toUpperCase();
        const known = {
            TRIGGERED_LLM: label('labelReasonTriggeredLlm'),
            DUPLICATE_SUPPRESSED: label('labelReasonDuplicateSuppressed'),
            NEGATIVE_CACHE_HIT: label('labelReasonNegativeCacheHit'),
            SUPPORTING_SIGNAL_ONLY: label('labelReasonSupportingOnly'),
            NO_TRUSTED_RISK_SIGNAL: label('labelReasonNoTrustedSignal'),
            BASELINE_INSUFFICIENT: label('labelReasonBaselineInsufficient'),
            BASELINE_UNAVAILABLE: label('labelReasonBaselineUnavailable'),
            BELOW_TRIGGER_THRESHOLD: label('labelReasonBelowThreshold'),
            ELIGIBLE_BUT_NOT_PUBLISHED: label('labelReasonEligibleNotPublished'),
            POLICY_OBSERVE_ONLY: label('labelReasonObserveOnly'),
            RATE_LIMITED: label('labelReasonRateLimited'),
            NOT_TRIGGERED: label('labelReasonNotTriggered')
        };
        return known[normalized] || value || '-';
    }

    function nonTriggerHelp(value) {
        const normalized = String(value || '').trim().toUpperCase();
        const known = {
            DUPLICATE_SUPPRESSED: label('labelReasonDuplicateSuppressedHelp'),
            NEGATIVE_CACHE_HIT: label('labelReasonNegativeCacheHitHelp'),
            SUPPORTING_SIGNAL_ONLY: label('labelReasonSupportingOnlyHelp'),
            NO_TRUSTED_RISK_SIGNAL: label('labelReasonNoTrustedSignalHelp'),
            BASELINE_INSUFFICIENT: label('labelReasonBaselineInsufficientHelp'),
            BASELINE_UNAVAILABLE: label('labelReasonBaselineUnavailableHelp'),
            BELOW_TRIGGER_THRESHOLD: label('labelReasonBelowThresholdHelp'),
            ELIGIBLE_BUT_NOT_PUBLISHED: label('labelReasonEligibleNotPublishedHelp')
        };
        return known[normalized] || label('labelReasonDefaultHelp');
    }

    function friendlyEvidenceGap(value) {
        const normalized = String(value || '').trim().toUpperCase();
        const known = {
            PERSONAL_BASELINE_AVAILABLE: label('labelEvidenceBaselineAvailable'),
            PERSONAL_BASELINE_UNAVAILABLE: label('labelEvidenceBaselineUnavailable'),
            PERSONAL_BASELINE_INSUFFICIENT: label('labelEvidenceBaselineInsufficient'),
            TRUSTED_ANCHOR_PRESENT: label('labelEvidenceAnchorPresent'),
            TRUSTED_ANCHOR_ABSENT: label('labelEvidenceAnchorAbsent'),
            SUPPORTING_SIGNAL_PRESENT: label('labelEvidenceSupportingPresent'),
            SUPPORTING_SIGNAL_ABSENT: label('labelEvidenceSupportingAbsent'),
            AUTHORIZATION_CONTEXT_PRESENT: label('labelEvidenceAuthorizationPresent'),
            AUTHORIZATION_CONTEXT_ABSENT: label('labelEvidenceAuthorizationAbsent'),
            LOCATION_RISK_OBSERVED: label('labelEvidenceLocationObserved'),
            LOCATION_RISK_NOT_OBSERVED: label('labelEvidenceLocationNotObserved'),
            FAILED_LOGIN_HISTORY_PRESENT: label('labelEvidenceFailedLoginPresent'),
            FAILED_LOGIN_HISTORY_ABSENT: label('labelEvidenceFailedLoginAbsent'),
            SEMANTIC_EVIDENCE_AVAILABLE: label('labelEvidenceSemanticAvailable'),
            SEMANTIC_EVIDENCE_STALE: label('labelEvidenceSemanticStale'),
            SEMANTIC_EVIDENCE_MISSING: label('labelEvidenceSemanticMissing'),
            SEMANTIC_EVIDENCE_SOURCE_AVAILABLE: label('labelEvidenceSemanticSourceAvailable'),
            SEMANTIC_EVIDENCE_SOURCE_ABSENT: label('labelEvidenceSemanticSourceAbsent'),
            SEMANTIC_EVIDENCE_VERSION_MISMATCH: label('labelEvidenceSemanticVersionMismatch'),
            SEMANTIC_EVIDENCE_DIMENSION_MISMATCH: label('labelEvidenceSemanticDimensionMismatch'),
            SEMANTIC_EVIDENCE_LOOKUP_TIMEOUT: label('labelEvidenceSemanticLookupTimeout'),
            SEMANTIC_EVIDENCE_LOOKUP_FAILED: label('labelEvidenceSemanticLookupFailed'),
            SEMANTIC_EVIDENCE_CACHE_MISS: label('labelEvidenceSemanticCacheMiss'),
            SEMANTIC_EVIDENCE_WARMUP_QUEUED: label('labelEvidenceSemanticWarmupQueued'),
            SEMANTIC_EVIDENCE_WARMUP_COMPLETED: label('labelEvidenceSemanticWarmupCompleted'),
            SEMANTIC_EVIDENCE_WARMUP_FAILED: label('labelEvidenceSemanticWarmupFailed'),
            DIMENSION_MISMATCH: label('labelEvidenceSemanticDimensionMismatch'),
            VERSION_MISMATCH: label('labelEvidenceSemanticVersionMismatch'),
            CACHE_MISS_SOURCE_AVAILABLE: label('labelEvidenceSemanticSourceAvailable'),
            CACHE_MISS_SOURCE_ABSENT: label('labelEvidenceSemanticSourceAbsent'),
            CACHE_MISS_SOURCE_UNKNOWN: label('labelEvidenceSemanticCacheMiss'),
            SEMANTIC_EVIDENCE_CACHE_UNAVAILABLE: label('labelEvidenceSemanticLookupFailed'),
            SEMANTIC_EVIDENCE_NOT_AVAILABLE: label('labelEvidenceSemanticMissing'),
            WARMUP_QUEUED: label('labelEvidenceSemanticWarmupQueued'),
            WARMUP_COMPLETED: label('labelEvidenceSemanticWarmupCompleted'),
            WARMUP_FAILED: label('labelEvidenceSemanticWarmupFailed'),
            SEMANTIC_EVIDENCE_NOT_REQUESTED: label('labelEvidenceSemanticNotRequested')
        };
        return known[normalized] || value || '-';
    }

    function evidenceHelp(value) {
        const normalized = String(value || '').trim().toUpperCase();
        if (normalized.includes('SEMANTIC_EVIDENCE_MISSING')
                || normalized.includes('SEMANTIC_EVIDENCE_SOURCE_ABSENT')
                || normalized.includes('SEMANTIC_EVIDENCE_VERSION_MISMATCH')
                || normalized.includes('SEMANTIC_EVIDENCE_DIMENSION_MISMATCH')
                || normalized.includes('SEMANTIC_EVIDENCE_LOOKUP_TIMEOUT')
                || normalized.includes('SEMANTIC_EVIDENCE_LOOKUP_FAILED')
                || normalized.includes('SEMANTIC_EVIDENCE_CACHE_MISS')
                || normalized.includes('WARMUP_FAILED')
                || normalized.includes('SEMANTIC_EVIDENCE_NOT_REQUESTED')) {
            return label('labelEvidenceSemanticMissingHelp');
        }
        if (normalized.includes('SEMANTIC_EVIDENCE_STALE')) {
            return label('labelEvidenceSemanticStaleHelp');
        }
        if (normalized.includes('SEMANTIC_EVIDENCE_AVAILABLE')) {
            return label('labelEvidenceSemanticPresentHelp');
        }
        if (normalized.endsWith('_ABSENT') || normalized.includes('UNAVAILABLE') || normalized.includes('INSUFFICIENT')) {
            return label('labelEvidenceMissingHelp');
        }
        return label('labelEvidencePresentHelp');
    }

    function friendlyBand(value) {
        const normalized = String(value || '').trim().toUpperCase();
        if (normalized === 'LOW') return label('labelBandLow');
        if (normalized === 'MEDIUM') return label('labelBandMedium');
        if (normalized === 'HIGH') return label('labelBandHigh');
        if (normalized === 'REDLINE') return label('labelBandRedline');
        return value || '-';
    }

    function scoreBucketLabel(value) {
        const normalized = String(value || '').trim().toUpperCase();
        if (normalized === 'UNKNOWN' || normalized === '') {
            return label('labelScoreUnknown');
        }
        return value;
    }

    function formatResource(method, path) {
        const normalizedMethod = String(method || '').trim().toUpperCase();
        const safePath = path || '-';
        if (normalizedMethod === 'WINDOW') {
            return `${label('labelScreenOrApi')} ${safePath}`;
        }
        return `${method || ''} ${safePath}`.trim();
    }

    function friendlyMode(value) {
        const normalized = String(value || '').toUpperCase();
        if (normalized === 'SHADOW') return label('labelModeShadow');
        if (normalized === 'OBSERVE') return label('labelModeObserve');
        if (normalized === 'ENFORCE') return label('labelModeEnforce');
        if (normalized === 'DISABLED') return label('labelModeDisabled');
        return value;
    }

    function recommendationTone(value) {
        if (value === 'DEFAULT_ENFORCE_CANDIDATE') return 'good';
        if (value === 'LIMITED_ENFORCE_CANDIDATE' || value === 'SHADOW_STABLE') return 'warn';
        if (value === 'KEEP_SHADOW') return 'bad';
        return 'info';
    }

    function outcomeTone(value) {
        if (value === 'TP' || value === 'TN') return 'good';
        if (value === 'FP' || value === 'FN') return 'bad';
        return 'info';
    }

    function outcomeLabel(value, triggered) {
        if (value === 'TP') return label('labelOutcomeTp');
        if (value === 'FP') return label('labelOutcomeFp');
        if (value === 'FN') return label('labelOutcomeFn');
        if (value === 'TN') return label('labelOutcomeTn');
        if (triggered === true) return label('labelTriggered');
        if (triggered === false) return label('labelNotTriggered');
        return label('labelOutcomeUnknown');
    }

    function recommendationLabel(value) {
        if (value === 'INSUFFICIENT_SAMPLE') return label('labelInsufficientSample');
        if (value === 'KEEP_SHADOW') return label('labelKeepShadow');
        if (value === 'SHADOW_STABLE') return label('labelShadowStable');
        if (value === 'LIMITED_ENFORCE_CANDIDATE') return label('labelLimitedEnforce');
        if (value === 'DEFAULT_ENFORCE_CANDIDATE') return label('labelDefaultEnforce');
        return value || label('labelUnknownRecommendation');
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

    function formatPercentOrNoData(value, available) {
        return available ? percentFormatter.format(value || 0) : label('labelNoDecisionData');
    }

    function hasComparison(summary) {
        return (summary.truePositiveCount || 0)
            + (summary.falsePositiveCount || 0)
            + (summary.observableFalseNegativeCount || 0)
            + (summary.trueNegativeCount || 0)
            + (summary.unknownCount || 0) > 0;
    }

    function percentWidth(value) {
        const normalized = typeof value === 'number' && Number.isFinite(value) ? value : 0;
        return Math.max(2, Math.min(100, Math.round(normalized * 100)));
    }

    function label(key) {
        return labels[key] || key;
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
