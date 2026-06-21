(function () {
    const root = document.getElementById('hcad-monitor');
    if (!root) return;

    const period = root.dataset.period || 'day';
    const locale = document.documentElement.lang || navigator.language || 'ko-KR';
    const formatter = new Intl.NumberFormat(locale);
    const percentFormatter = new Intl.NumberFormat(locale, { style: 'percent', maximumFractionDigits: 1 });
    const decimalFormatter = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
    const labels = root.dataset;

    const statusEl = document.getElementById('hcad-status');
    const kpiEl = document.getElementById('hcad-kpis');
    const signalEl = document.getElementById('hcad-signals');
    const resourceEl = document.getElementById('hcad-resources');
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
            statusEl.innerHTML = `<div class="hcad-band-title">${escapeHtml(label('labelUnavailable'))}</div><div class="text-sm" style="color:#f87171;">${escapeHtml(error.message)}</div>`;
        });

    function render(summary) {
        if (rangeEl) {
            rangeEl.textContent = `${formatDate(summary.from)} - ${formatDate(summary.to)}`;
        }
        renderStatus(summary);
        renderKpis(summary);
        renderSimpleBreakdown(signalEl, summary.signalBreakdown || [], (item) => ({
            title: friendlySignal(item.key || '-'),
            meta: `${label('labelPrecision')} ${percentFormatter.format(item.precision || 0)} / ${label('labelFalsePositive')} ${formatter.format(item.falsePositiveCount || 0)}`,
            value: formatter.format(item.candidateCount || 0)
        }));
        renderSimpleBreakdown(resourceEl, summary.resourceBreakdown || [], (item) => ({
            title: formatResource(item.method, item.path),
            meta: `${label('labelPrecision')} ${percentFormatter.format(item.precision || 0)}`,
            value: formatter.format(item.candidateCount || 0)
        }));
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
                    <div class="hcad-band-title">${escapeHtml(label('labelPromotionReadiness'))}</div>
                    <div class="text-sm" style="color:#94a3b8;">
                        ${escapeHtml(label('labelMode'))} ${escapeHtml(friendlyMode(summary.currentMode || 'UNKNOWN'))},
                        ${escapeHtml(label('labelSample'))} ${formatter.format(sample)} / ${formatter.format(minSample)},
                        ${escapeHtml(label('labelPrecision'))} ${percentFormatter.format(summary.precision || 0)}
                    </div>
                </div>
                <span class="hcad-status ${tone}">${escapeHtml(recommendationLabel(recommendation))}</span>
            </div>`;
    }

    function renderKpis(summary) {
        const kpis = [
            [label('labelHcadWindows'), summary.candidateCount, label('labelEvaluatedHelp')],
            [label('labelLlmCalls'), summary.triggeredLlmCount, label('labelLlmHelp')],
            [label('labelUnknown'), percentFormatter.format(summary.unknownRate || 0), label('labelUnknownHelp')],
            [label('labelFalsePositive'), summary.falsePositiveCount, label('labelFalsePositiveHelp')],
            [label('labelObservableFn'), summary.observableFalseNegativeCount, label('labelObservableFnHelp')],
            [label('labelAvgLatency'), `${decimalFormatter.format(summary.averageLlmLatencyMs || 0)} ms`, label('labelAvgLatencyHelp')]
        ];
        kpiEl.innerHTML = kpis.map(([text, value, help]) => `
            <div class="hcad-kpi">
                <div class="hcad-kpi-value">${escapeHtml(formatValue(value))}</div>
                <div class="hcad-kpi-label">${escapeHtml(text)}</div>
                <div class="hcad-kpi-help">${escapeHtml(help)}</div>
            </div>`).join('');
    }

    function renderSimpleBreakdown(container, items, rowFactory) {
        if (!container) return;
        const visible = items.slice(0, 5);
        if (!visible.length) {
            container.innerHTML = `<div class="hcad-simple-meta">${escapeHtml(label('labelNoData'))}</div>`;
            return;
        }
        container.innerHTML = visible.map((item) => {
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

    function renderRecent(items) {
        if (!recentEl) return;
        const visible = items.slice(0, 10);
        if (!visible.length) {
            recentEl.innerHTML = `<tr><td colspan="6">${escapeHtml(label('labelNoRecent'))}</td></tr>`;
            return;
        }
        recentEl.innerHTML = visible.map((item) => `
            <tr>
                <td>${escapeHtml(formatDate(item.createdAt))}</td>
                <td>${escapeHtml(item.userId || '-')}</td>
                <td>${escapeHtml(`${item.method || ''} ${item.path || '-'}`.trim())}</td>
                <td>${renderReason(item)}</td>
                <td>${escapeHtml(item.promptContextContractVersion || '-')}</td>
                <td><span class="hcad-status ${outcomeTone(item.outcomeClass)}">${escapeHtml(outcomeLabel(item.outcomeClass))}</span></td>
            </tr>`).join('');
    }

    function renderReason(item) {
        const codes = Array.isArray(item.reasonCodes) ? item.reasonCodes : [];
        const labels = codes.map(friendlySignal).filter(Boolean);
        const reason = labels.length ? labels.join(', ') : '-';
        const baseline = item.baselineComparisonSummary ? `<div class="hcad-simple-meta">${escapeHtml(item.baselineComparisonSummary)}</div>` : '';
        return `<div class="hcad-simple-title">${escapeHtml(reason)}</div>${baseline}`;
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
            BASELINE_MATERIAL_MISMATCH: label('labelSignalBaselineMismatch')
        };
        return known[normalized] || value || '-';
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

    function outcomeLabel(value) {
        switch (value) {
            case 'TP':
                return label('labelOutcomeTp');
            case 'FP':
                return label('labelOutcomeFp');
            case 'FN':
                return label('labelOutcomeFn');
            case 'TN':
                return label('labelOutcomeTn');
            default:
                return label('labelOutcomeUnknown');
        }
    }

    function recommendationLabel(value) {
        switch (value) {
            case 'INSUFFICIENT_SAMPLE':
                return label('labelInsufficientSample');
            case 'KEEP_SHADOW':
                return label('labelKeepShadow');
            case 'SHADOW_STABLE':
                return label('labelShadowStable');
            case 'LIMITED_ENFORCE_CANDIDATE':
                return label('labelLimitedEnforce');
            case 'DEFAULT_ENFORCE_CANDIDATE':
                return label('labelDefaultEnforce');
            default:
                return value || label('labelUnknownRecommendation');
        }
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
