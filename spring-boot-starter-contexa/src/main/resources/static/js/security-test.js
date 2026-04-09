'use strict';
(function () {
const CONFIG = window.SECURITY_TEST_CONFIG || {};
const MSG = window.ZT_MSG || {};
const API = {
    sse: (CONFIG.api && CONFIG.api.sseUserUrl) || '/admin/api/sse/llm-analysis/user',
    status: (CONFIG.api && CONFIG.api.statusUrl) || '/admin/api/test-action/status',
    evidenceBase: (CONFIG.api && CONFIG.api.evidenceBaseUrl) || '/admin/api/security-test/evidence',
    endpointBases: {
        normal: (CONFIG.api && CONFIG.api.endpointBases && CONFIG.api.endpointBases.normal) || '/admin/api/security-test/normal/',
        sensitive: (CONFIG.api && CONFIG.api.endpointBases && CONFIG.api.endpointBases.sensitive) || '/admin/api/security-test/sensitive/',
        critical: (CONFIG.api && CONFIG.api.endpointBases && CONFIG.api.endpointBases.critical) || '/admin/api/security-test/critical/'
    }
};
const DEFAULT_RESOURCE_ID_BY_ENDPOINT = {
    normal: 'resource-001',
    sensitive: 'resource-001',
    critical: 'resource-001'
};
const STORE = {
    access: 'contexa_access_token',
    refresh: 'contexa_refresh_token',
    mode: 'authMode'
};
const SCENARIOS = {
    NORMAL_USER: {
        title: MSG.scenarioNormalTitle || 'Normal User',
        ip: '192.168.1.100',
        uaLabel: 'Chrome 120 / Windows 11',
        uaHeader: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        expect: 'ALLOW or LOW_RISK',
        deviceId: 'd7e3f1a2-4b8c-4e9d-a1f5-6c3b2d8e9f01'
    },
    ACCOUNT_TAKEOVER: {
        title: MSG.scenarioTakeoverTitle || 'Account Takeover',
        ip: '203.0.113.50',
        uaLabel: 'Chrome 120 Mobile / Android 10',
        uaHeader: 'Mozilla/5.0 (Linux; Android 10; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        expect: 'CHALLENGE or BLOCK',
        deviceId: 'a9c4e7b1-2f6d-48a3-b5e8-1d7f3c9a2e04'
    }
};
const ENDPOINTS = {
    normal: {
        title: MSG.endpointNormal || 'Standard Resource',
        desc: MSG.endpointNormalDesc || 'Low-sensitivity business access path'
    },
    sensitive: {
        title: MSG.endpointSensitive || 'Sensitive Resource',
        desc: MSG.endpointSensitiveDesc || 'Sensitive information access path'
    },
    critical: {
        title: MSG.endpointCritical || 'Critical Resource',
        desc: MSG.endpointCriticalDesc || 'Critical information access path'
    }
};
const SSE_TYPES = [
    'connected',
    'CONTEXT_COLLECTED',
    'HCAD_ANALYSIS',
    'SESSION_CONTEXT_LOADED',
    'RAG_SEARCH_COMPLETE',
    'BEHAVIOR_ANALYSIS_COMPLETE',
    'LAYER1_START',
    'LAYER1_COMPLETE',
    'LAYER2_START',
    'LAYER2_COMPLETE',
    'LLM_EXECUTION_START',
    'LLM_EXECUTION_COMPLETE',
    'DECISION_APPLIED',
    'RESPONSE_BLOCKED',
    'ERROR'
];
const el = {};
const st = {
    user: document.body.dataset.username || 'anonymous',
    scenario: 'NORMAL_USER',
    endpoint: 'normal',
    runId: null,
    requestId: null,
    history: [],
    events: new Map(),
    responses: new Map(),
    evidence: new Map(),
    truth: null,
    eventSource: null,
    pendingRequest: false,
    activeLinks: null,
    auth: {
        mode: 'cookie',
        source: 'none',
        carrier: 'SESSION_COOKIE_ONLY',
        subject: document.body.dataset.username || 'anonymous',
        attached: false,
        accessToken: null,
        refreshToken: null
    }
};

document.addEventListener('DOMContentLoaded', init);

async function init() {
    bindElements();
    bindEvents();
    refreshAuth();
    renderScenario();
    renderRequestHistory();
    renderTimeline();
    renderImmediateResponse(null);
    renderServerTruth(null);
    renderEvidence(null);
    renderEvidenceLinks(null, null);
    setText(el.evidenceStreamOutput, MSG.ndjsonHint || 'Check NDJSON stream with the "View Evidence Live" button.');
    await initializeSse();
}

function bindElements() {
    [
        'sse-indicator', 'sse-text', 'current-run-id', 'selected-request-id',
        'auth-transport', 'auth-token-source', 'auth-token-state', 'auth-subject',
        'selected-scenario-name', 'selected-scenario-ip', 'selected-scenario-ua', 'selected-expected-action',
        'selected-endpoint-name', 'request-header-preview', 'btn-run-initial', 'btn-run-follow-up',
        'btn-refresh-server', 'btn-export-evidence', 'btn-stream-evidence', 'btn-reset-console',
        'immediate-response-facts', 'immediate-response-json', 'verdict-badge', 'metric-risk',
        'metric-confidence', 'metric-depth', 'metric-context-hash', 'reasoning-summary', 'proposed-action',
        'consistency-list', 'timeline', 'request-history', 'server-truth-facts', 'server-truth-json',
        'context-summary', 'saas-summary', 'evidence-links', 'evidence-json', 'evidence-stream-output'
    ].forEach(function (id) {
        el[toCamel(id)] = document.getElementById(id);
    });
}

function bindEvents() {
    document.querySelectorAll('[data-scenario]').forEach(function (button) {
        button.addEventListener('click', function () {
            st.scenario = button.dataset.scenario;
            document.querySelectorAll('[data-scenario]').forEach(function (item) {
                item.classList.remove('selected');
            });
            button.classList.add('selected');
            renderScenario();
        });
    });

    document.querySelectorAll('[data-endpoint]').forEach(function (button) {
        button.addEventListener('click', function () {
            st.endpoint = button.dataset.endpoint;
            document.querySelectorAll('[data-endpoint]').forEach(function (item) {
                item.classList.remove('active');
            });
            button.classList.add('active');
            renderScenario();
        });
    });

    el.btnRunInitial.addEventListener('click', function () { executeRequest('INITIAL'); });
    el.btnRunFollowUp.addEventListener('click', function () { executeRequest('FOLLOW_UP'); });
    el.btnRefreshServer.addEventListener('click', function () { refreshEvidence(true); });
    el.btnExportEvidence.addEventListener('click', exportEvidence);
    el.btnStreamEvidence.addEventListener('click', streamEvidence);
    el.btnResetConsole.addEventListener('click', resetConsole);
}

async function initializeSse() {
    refreshAuth();
    if (!canStartSse()) {
        stopSse(MSG.sseAuthRequired || 'Please verify authentication before connecting SSE.');
        return;
    }
    const probe = await probeSseAccess();
    if (!probe.allowed) {
        stopSse(probe.message);
        return;
    }
    connectSse();
}

function canStartSse() {
    const subject = (st.auth && st.auth.subject) || st.user;
    const normalized = String(subject || '').trim().toLowerCase();
    return normalized !== '' && normalized !== 'anonymous' && normalized !== 'anonymoususer' && normalized !== 'unknown';
}

async function probeSseAccess() {
    try {
        const response = await fetch(buildStatusUrl(), {
            headers: buildHeaders({ 'Accept': 'application/json' }),
            credentials: 'same-origin'
        });
        if (response.status === 401 || response.status === 403) {
            return { allowed: false, message: MSG.sseAuthOrAuthz || 'Please verify authentication or authorization before connecting SSE.' };
        }
        const payload = await parseBody(response);
        const userId = String(payload.userId || '').trim().toLowerCase();
        if (userId === 'anonymous' || userId === 'anonymoususer') {
            return { allowed: false, message: MSG.sseAnonymous || 'SSE is not connected in anonymous state.' };
        }
        return { allowed: true };
    } catch (error) {
        return { allowed: false, message: 'SSE server probe failed.' };
    }
}

function connectSse() {
    if (st.eventSource) {
        st.eventSource.close();
    }
    setSseState('connecting', MSG.sseConnecting || 'Connecting to user SSE');
    st.eventSource = new EventSource(API.sse);
    SSE_TYPES.forEach(function (type) {
        st.eventSource.addEventListener(type, function (event) {
            handleSse(type, event);
        });
    });
    st.eventSource.onopen = function () {
        setSseState('connected', MSG.sseConnected || 'User SSE connected');
    };
    st.eventSource.onerror = async function () {
        const probe = await probeSseAccess();
        if (!probe.allowed) {
            stopSse(probe.message);
            return;
        }
        setSseState('disconnected', MSG.sseReconnecting || 'User SSE auto-reconnecting.');
    };
}

function stopSse(message) {
    if (st.eventSource) {
        st.eventSource.close();
        st.eventSource = null;
    }
    setSseState('disconnected', message);
}

function handleSse(type, event) {
    const payload = asJson(event.data) || { type: type, timestamp: Date.now() };
    const requestId = resolveEventRequestId(payload);
    const list = st.events.get(requestId) || [];
    list.push(payload);
    st.events.set(requestId, list);
    if (requestId === st.requestId) {
        renderTimeline();
        renderVerdict();
    }
    if (payload.type === 'DECISION_APPLIED' || payload.type === 'LAYER2_COMPLETE' || payload.type === 'ERROR') {
        refreshEvidence(false);
    }
}

function resolveEventRequestId(payload) {
    return payload.requestId || payload.correlationId || 'unlinked';
}
async function executeRequest(phase) {
    refreshAuth();
    if (st.pendingRequest) {
        addTimelineEntry('ERROR', 'Another request is already in progress.', st.requestId);
        return;
    }
    if (phase === 'FOLLOW_UP' && !st.runId) {
        window.alert(MSG.alertRunFirst || 'Please execute the 1st request first.');
        return;
    }

    const scenario = SCENARIOS[st.scenario];
    const resourceId = DEFAULT_RESOURCE_ID_BY_ENDPOINT[st.endpoint] || 'resource-001';
    const tentativeRequestId = createId('req');
    const deviceId = resolveDeviceId(scenario);

    if (phase === 'INITIAL') {
        st.runId = createId('run');
        setText(el.currentRunId, st.runId);
    }

    st.pendingRequest = true;
    setRunButtonsBusy(true);
    renderHeaderPreview({
        requestId: tentativeRequestId,
        phase: phase,
        scenarioKey: st.scenario,
        ip: scenario.ip,
        uaLabel: resolveScenarioUaLabel(scenario),
        expectedAction: scenario.expect,
        deviceId: deviceId
    });

    try {
        const response = await fetch(buildEndpointUrl(st.endpoint, resourceId), {
            method: 'GET',
            headers: buildHeaders({
                'Accept': 'application/json',
                'X-Request-ID': tentativeRequestId,
                'X-Forwarded-For': scenario.ip,
                'X-Simulated-User-Agent': resolveScenarioUaHeader(scenario),
                'X-Device-Id': deviceId,
                'X-Contexa-Scenario': st.scenario,
                'X-Contexa-Expected-Action': scenario.expect,
                'X-Contexa-Demo-Run-Id': st.runId,
                'X-Contexa-Demo-Phase': phase
            }),
            credentials: 'same-origin'
        });

        const body = await parseBody(response);
        const effectiveRequestId = body.requestId || tentativeRequestId;
        body.requestId = effectiveRequestId;
        body.httpStatus = response.status;

        st.requestId = effectiveRequestId;
        setText(el.selectedRequestId, effectiveRequestId);
        st.responses.set(effectiveRequestId, body);
        st.history.unshift({
            requestId: effectiveRequestId,
            phase: phase,
            scenario: st.scenario,
            status: response.status,
            body: body,
            authCarrier: st.auth.carrier,
            executedAt: Date.now()
        });

        addTimelineEntry('LOCAL_REQUEST', phaseLabel(phase) + ' completed with HTTP ' + response.status, effectiveRequestId);
        renderRequestHistory();
        renderHeaderPreview({
            requestId: body.requestId,
            phase: body.demoPhase || phase,
            scenarioKey: body.scenario || st.scenario,
            ip: body.clientIp || scenario.ip,
            uaLabel: resolveScenarioUaLabel(SCENARIOS[body.scenario]) || body.userAgent || resolveScenarioUaLabel(scenario),
            expectedAction: body.expectedAction || scenario.expect,
            deviceId: body.deviceId || deviceId
        });
        renderImmediateResponse(body);
        renderEvidenceLinks(body, null);

        await refreshEvidence(true);
        [800, 1800, 3200].forEach(function (delay) {
            window.setTimeout(function () {
                if (st.requestId === effectiveRequestId) {
                    refreshEvidence(false);
                }
            }, delay);
        });
    } catch (error) {
        addTimelineEntry('ERROR', 'Request execution failed: ' + error.message, st.requestId || tentativeRequestId);
    } finally {
        st.pendingRequest = false;
        setRunButtonsBusy(false);
    }
}

async function refreshEvidence(includeStream) {
    if (!st.requestId) {
        return;
    }

    refreshAuth();
    const evidenceUrl = API.evidenceBase + '/' + encodeURIComponent(st.requestId);
    const [truthResult, evidenceResult] = await Promise.allSettled([
        fetchJson(buildStatusUrl(st.requestId), {
            headers: buildHeaders({ 'Accept': 'application/json' }),
            credentials: 'same-origin'
        }),
        fetchJson(evidenceUrl, {
            headers: buildHeaders({ 'Accept': 'application/json' }),
            credentials: 'same-origin'
        })
    ]);

    if (truthResult.status === 'fulfilled') {
        st.truth = truthResult.value;
    } else {
        addTimelineEntry('ERROR', 'Server truth refresh failed: ' + truthResult.reason.message, st.requestId);
    }

    if (evidenceResult.status === 'fulfilled') {
        st.evidence.set(st.requestId, evidenceResult.value);
    } else {
        addTimelineEntry('ERROR', 'Evidence refresh failed: ' + evidenceResult.reason.message, st.requestId);
    }

    const evidence = st.evidence.get(st.requestId) || null;
    renderServerTruth(st.truth);
    renderEvidence(evidence);
    renderEvidenceLinks(st.responses.get(st.requestId) || null, evidence);
    renderConsistency(evidence, st.truth);
    renderVerdict();
    renderTimeline();

    if (includeStream) {
        setText(el.evidenceStreamOutput, MSG.ndjsonHint || 'Check NDJSON stream with the "View Evidence Live" button.');
    }
}

function exportEvidence() {
    const links = resolveEvidenceLinks(st.responses.get(st.requestId) || null, st.evidence.get(st.requestId) || null);
    if (!links || !links.evidenceExportUrl) {
        window.alert(MSG.alertNoExport || 'No evidence to export.');
        return;
    }
    window.open(links.evidenceExportUrl, '_blank', 'noopener');
}

async function streamEvidence() {
    const links = resolveEvidenceLinks(st.responses.get(st.requestId) || null, st.evidence.get(st.requestId) || null);
    if (!links || !links.evidenceStreamUrl) {
        window.alert(MSG.alertNoStream || 'No evidence to stream.');
        return;
    }
    try {
        const payload = await fetchText(links.evidenceStreamUrl);
        setText(el.evidenceStreamOutput, payload || (MSG.emptyStream || 'Empty.'));
    } catch (error) {
        setText(el.evidenceStreamOutput, 'Stream load failed: ' + error.message);
    }
}

async function resetConsole() {
    await resetServerTruth();
    st.runId = null;
    st.requestId = null;
    st.history = [];
    st.events.clear();
    st.responses.clear();
    st.evidence.clear();
    st.truth = null;
    st.activeLinks = null;

    setText(el.currentRunId, MSG.unset || '-');
    setText(el.selectedRequestId, MSG.none || '-');
    refreshAuth();
    renderScenario();
    renderRequestHistory();
    renderTimeline();
    renderImmediateResponse(null);
    renderServerTruth(null);
    renderEvidence(null);
    renderEvidenceLinks(null, null);
    setText(el.evidenceStreamOutput, MSG.ndjsonHint || 'Check NDJSON stream with the "View Evidence Live" button.');
    await initializeSse();
}

async function resetServerTruth() {
    const resetUrl = API.status.replace(/\/status$/, '/reset');
    try {
        await fetch(resetUrl, {
            method: 'DELETE',
            headers: buildHeaders({ 'Accept': 'application/json' }),
            credentials: 'same-origin'
        });
    } catch (error) {
        addTimelineEntry('ERROR', 'Server reset failed: ' + error.message, st.requestId);
    }
}
function renderScenario() {
    const scenario = SCENARIOS[st.scenario];
    const endpoint = ENDPOINTS[st.endpoint];
    setText(el.selectedScenarioName, scenario.title);
    setText(el.selectedScenarioIp, scenario.ip);
    setText(el.selectedScenarioUa, resolveScenarioUaLabel(scenario));
    setText(el.selectedExpectedAction, scenario.expect);
    setText(el.selectedEndpointName, endpoint.title + ' / ' + endpoint.desc);
    renderHeaderPreview({
        requestId: st.requestId || '-',
        phase: st.runId ? 'FOLLOW_UP' : 'INITIAL',
        scenarioKey: st.scenario,
        ip: scenario.ip,
        uaLabel: resolveScenarioUaLabel(scenario),
        expectedAction: scenario.expect,
        deviceId: resolveDeviceId(scenario)
    });
}

function renderHeaderPreview(preview) {
    const ua = scenarioUaParts(preview.uaLabel);
    const sessionId = resolveSessionCookie();
    const items = [
        [MSG.scenario || 'Scenario', preview.scenarioKey],
        [MSG.expectedAction || 'Expected Action', preview.expectedAction],
        [MSG.requestId || 'Request ID', preview.requestId],
        [MSG.phase || 'Phase', phaseLabel(preview.phase)],
        [MSG.clientIp || 'Client IP', preview.ip],
        [MSG.headerBrowser || 'Browser', ua.browser],
        [MSG.headerOs || 'OS', ua.os],
        [MSG.headerDevice || 'Device ID', preview.deviceId],
        [MSG.headerSession || 'Session Cookie', sessionId]
    ];
    setHtml(el.requestHeaderPreview, items.map(function (entry) {
        return '<div class="header-item"><span>' + esc(entry[0]) + '</span><code>' + esc(str(entry[1])) + '</code></div>';
    }).join(''));
}

function renderImmediateResponse(payload) {
    if (!payload) {
        setHtml(el.immediateResponseFacts, empty(MSG.noEvidence || 'No evidence selected'));
        setText(el.immediateResponseJson, '{}');
        return;
    }

    setHtml(el.immediateResponseFacts, facts([
        [MSG.httpStatus || 'HTTP Status', payload.httpStatus],
        [MSG.resultType || 'Result Type', payload.resultType],
        [MSG.requestId || 'Request ID', payload.requestId],
        [MSG.correlationId || 'Correlation ID', payload.correlationId],
        [MSG.phase || 'Phase', payload.demoPhase],
        ['Endpoint', payload.endpointKey],
        ['Resource ID', payload.resourceId],
        ['Request Path', payload.requestPath],
        ['Device ID', payload.deviceId],
        [MSG.clientIp || 'Client IP', payload.clientIp],
        [MSG.sessionId || 'Session ID', payload.sessionId],
        [MSG.authCarrier || 'Auth Carrier', payload.authCarrier],
        [MSG.authMode || 'Auth Mode', payload.authMode],
        [MSG.authSubject || 'Auth Subject', payload.authSubjectHint],
        [MSG.authHeader || 'Authorization Header', payload.authorizationHeaderPresent]
    ]));
    setText(el.immediateResponseJson, pretty(payload));
}

function renderServerTruth(payload) {
    if (!payload) {
        setHtml(el.serverTruthFacts, empty(MSG.noEvidence || 'No evidence selected'));
        setText(el.serverTruthJson, '{}');
        return;
    }

    setHtml(el.serverTruthFacts, facts([
        [MSG.currentAction || 'Current Action', payload.action],
        [MSG.analysisStatus || 'Analysis Status', payload.analysisStatus],
        ['Analysis Source', payload.analysisSource],
        ['Selected Request', payload.selectedRequestId || st.requestId],
        ['Linked To Request', payload.requestLinked],
        [MSG.requestId || 'Request ID', payload.requestId],
        [MSG.userId || 'User ID', payload.userId],
        [MSG.risk || 'Risk', payload.riskScore],
        [MSG.confidence || 'Confidence', payload.confidence],
        [MSG.contextHash || 'Context Binding Hash', payload.contextBindingHash],
        [MSG.threatEvidence || 'Threat Evidence', payload.threatEvidence],
        ['Linked Events', payload.linkedEventCount]
    ]));
    setText(el.serverTruthJson, pretty(payload));
}

function renderEvidence(evidence) {
    if (!evidence) {
        setHtml(el.contextSummary, empty(MSG.noEvidence || 'No evidence selected'));
        setHtml(el.saasSummary, empty(MSG.noEvidence || 'No evidence selected'));
        setText(el.evidenceJson, '{}');
        return;
    }

    const request = evidence.request || {};
    const context = evidence.context || {};
    const prompt = evidence.prompt || {};
    const saas = evidence.saas || {};

    setText(el.evidenceJson, pretty(evidence));
    setHtml(el.contextSummary, [
        row('Scenario', context.scenario || request.scenario),
        row('Expected Action', context.expectedAction || request.expectedAction),
        row('Endpoint', request.endpointKey || context.endpointKey),
        row('Resource ID', request.resourceId || context.resourceId),
        row('Request Path', request.requestPath || context.requestPath),
        row('Client IP', context.clientIp || request.clientIp),
        row('User-Agent', context.userAgent || request.userAgent),
        row('Device ID', context.deviceId || request.deviceId),
        row('Session ID', context.sessionId || request.sessionId),
        row('Context Binding Hash', context.contextBindingHash),
        row('Auth Carrier', request.authCarrier),
        row('Auth Mode', request.authMode),
        row('Auth Subject', request.authSubjectHint),
        row('Authorization Header', request.authorizationHeaderPresent),
        row('Recent Session Actions', sizeOf(context.recentSessionActions)),
        row('Recent Narrative Families', sizeOf(context.recentNarrativeActionFamilies)),
        row('Recent Protectable Accesses', sizeOf(context.recentProtectableAccesses)),
        row('Work Profile Observations', sizeOf(context.workProfileObservations)),
        row('Permission Change Observations', sizeOf(context.permissionChangeObservations)),
        row('HCAD Session Metadata', sizeOf(context.hcadSessionMetadata)),
        row('HCAD Analysis', sizeOf(context.hcadAnalysis))
    ].join(''));

    setHtml(el.saasSummary, [
        card('Prompt Runtime / Audit', [
            ['present', prompt.present],
            ['telemetryKeys', sizeOf(prompt.telemetry)],
            ['auditFields', sizeOf(prompt.audit)]
        ]),
        card('Security Decision Outbox', [
            ['enabled', saas.securityDecisionOutbox && saas.securityDecisionOutbox.enabled],
            ['present', saas.securityDecisionOutbox && saas.securityDecisionOutbox.present],
            ['status', saas.securityDecisionOutbox && saas.securityDecisionOutbox.status],
            ['attemptCount', saas.securityDecisionOutbox && saas.securityDecisionOutbox.attemptCount],
            ['deliveredAt', saas.securityDecisionOutbox && saas.securityDecisionOutbox.deliveredAt],
            ['correlationId', saas.securityDecisionOutbox && saas.securityDecisionOutbox.correlationId]
        ]),
        card('Prompt Context Audit Outbox', [
            ['enabled', saas.promptContextAuditOutbox && saas.promptContextAuditOutbox.enabled],
            ['present', saas.promptContextAuditOutbox && saas.promptContextAuditOutbox.present],
            ['status', saas.promptContextAuditOutbox && saas.promptContextAuditOutbox.status],
            ['attemptCount', saas.promptContextAuditOutbox && saas.promptContextAuditOutbox.attemptCount],
            ['deliveredAt', saas.promptContextAuditOutbox && saas.promptContextAuditOutbox.deliveredAt],
            ['correlationId', saas.promptContextAuditOutbox && saas.promptContextAuditOutbox.correlationId]
        ]),
        card('SaaS Pull Snapshots', [
            ['baselineSeed', snapshotSummary(saas.pullSnapshots && saas.pullSnapshots.baselineSeed)],
            ['threatIntelligence', snapshotSummary(saas.pullSnapshots && saas.pullSnapshots.threatIntelligence)],
            ['knowledgePack', snapshotSummary(saas.pullSnapshots && saas.pullSnapshots.knowledgePack)],
            ['runtimePolicy', snapshotSummary(saas.pullSnapshots && saas.pullSnapshots.runtimePolicy)]
        ])
    ].join(''));
}

function renderConsistency(evidence, truth) {
    if (!evidence) {
        setHtml(el.consistencyList, consistencyItem(MSG.waiting || 'Waiting', MSG.noEvidence || 'No evidence selected', 'pending'));
        return;
    }

    refreshAuth();
    const response = st.responses.get(st.requestId) || {};
    const request = evidence.request || {};
    const analysis = evidence.analysis || {};
    const consistency = evidence.consistency || {};
    const currentSubject = st.auth.subject && st.auth.subject !== 'unknown' ? st.auth.subject : st.user;

    setHtml(el.consistencyList, [
        boolItem(MSG.consistencyRequestId || 'Immediate response requestId matches evidence requestId', response.requestId === evidence.requestId),
        boolItem(MSG.consistencySessionId || 'Immediate response sessionId matches evidence sessionId', response.sessionId === request.sessionId),
        boolItem(MSG.consistencyClientIp || 'Immediate response clientIp matches evidence clientIp', response.clientIp === request.clientIp),
        boolItem(MSG.consistencyAuthCarrier || 'UI auth carrier matches evidence auth carrier', !request.authCarrier || request.authCarrier === st.auth.carrier),
        boolItem(MSG.consistencyAuthMode || 'UI auth mode matches evidence auth mode', !request.authMode || request.authMode === st.auth.mode),
        boolItem(MSG.consistencyTokenSource || 'UI token source matches evidence token source', !request.tokenSource || request.tokenSource === st.auth.source),
        boolItem(MSG.consistencyAuthSubject || 'UI auth subject matches evidence auth subject', !request.authSubjectHint || request.authSubjectHint === st.auth.subject),
        boolItem(MSG.consistencyAuthAttached || 'Authorization attachment matches evidence', request.authorizationHeaderPresent === undefined || request.authorizationHeaderPresent === st.auth.attached),
        boolItem(MSG.consistencyUser || 'Immediate response user matches current auth subject', !response.user || response.user === currentSubject),
        boolItem(MSG.consistencyTruthUser || 'Server truth userId matches current auth subject', !truth || !truth.userId || truth.userId === currentSubject),
        boolItem(MSG.consistencyTruthRequest || 'Server truth requestId matches evidence analysis requestId', !truth || !truth.requestId || truth.requestId === analysis.requestId),
        boolItem(MSG.consistencySseLinked || 'SSE events linked to current requestId', Boolean(consistency.sseLinked)),
        boolItem(MSG.consistencyAnalysisLinked || 'Analysis result linked to current requestId', Boolean(consistency.analysisRequestLinked)),
        stateItem(MSG.consistencyDecisionOutbox || 'Decision outbox linked to current requestId', consistency.decisionOutboxState || (consistency.decisionOutboxLinked ? 'MATCH' : 'PENDING')),
        stateItem(MSG.consistencyPromptAudit || 'Prompt audit outbox linked to current requestId', consistency.promptAuditState || (consistency.promptAuditLinked ? 'MATCH' : 'PENDING')),
        boolItem(MSG.consistencyContextBinding || 'Context binding hash exists', Boolean(consistency.contextBindingPresent)),
        boolItem(MSG.consistencyServerTruth || 'Server truth ready', Boolean(consistency.serverTruthReady)),
        stateItem(MSG.consistencySaasEvidence || 'SaaS evidence ready', consistency.saasEvidenceState || (consistency.saasEvidenceReady ? 'MATCH' : 'PENDING'))
    ].join(''));
}
function renderVerdict() {
    const evidence = st.requestId ? st.evidence.get(st.requestId) : null;
    const analysis = (evidence && evidence.analysis) || st.truth || {};
    const events = st.requestId ? (st.events.get(st.requestId) || []) : [];
    const action = analysis.action || deriveAction(events) || 'PENDING_ANALYSIS';

    setText(el.metricRisk, num(analysis.riskScore));
    setText(el.metricConfidence, num(analysis.confidence));
    setText(el.metricDepth, analysis.analysisDepth || '-');
    setText(el.metricContextHash, analysis.contextBindingHash || '-');
    setText(el.reasoningSummary, analysis.reasoningSummary || latestReasoning(events) || (MSG.noAnalysis || 'No analysis results yet.'));
    setText(el.proposedAction, analysis.llmProposedAction || action || '-');
    setText(el.verdictBadge, action);
    el.verdictBadge.className = 'verdict-badge ' + verdictClass(action);
}

function renderTimeline() {
    if (!st.requestId) {
        setHtml(el.timeline, empty(MSG.noSseEvents || 'No SSE events received yet.'));
        return;
    }
    const events = (st.events.get(st.requestId) || []).slice().sort(function (left, right) {
        return toSortableTime(left.timestamp) - toSortableTime(right.timestamp);
    });
    if (!events.length) {
        setHtml(el.timeline, empty(MSG.noSseEvents || 'No SSE events received yet.'));
        return;
    }
    setHtml(el.timeline, events.map(function (event) {
        return '<div class="timeline-item ' + timelineClass(event.type) + '">' +
            '<div class="timeline-head"><strong>' + esc(event.type || '-') + '</strong><span>' + esc(formatTimestamp(event.timestamp)) + '</span></div>' +
            '<div class="timeline-body">' +
            '<span>layer: ' + esc(event.layer || '-') + '</span>' +
            '<span>action: ' + esc(event.action || '-') + '</span>' +
            '<span>risk: ' + esc(num(event.riskScore)) + '</span>' +
            '<span>confidence: ' + esc(num(event.confidence)) + '</span>' +
            '<span>requestId: ' + esc(event.requestId || event.correlationId || st.requestId || '-') + '</span>' +
            '</div>' +
            '<p class="timeline-summary">' + esc(event.reasoningSummary || event.reasoning || '-') + '</p>' +
            '</div>';
    }).join(''));
}

function renderRequestHistory() {
    if (!st.history.length) {
        setHtml(el.requestHistory, empty(MSG.noRequests || 'No requests executed yet.'));
        return;
    }

    setHtml(el.requestHistory, st.history.map(function (item) {
        const response = item.body || {};
        const requestId = response.requestId || item.requestId;
        const activeClass = requestId === st.requestId ? 'active' : '';
        return '<button type="button" class="history-item ' + activeClass + '" data-request-id="' + esc(requestId) + '">' +
            '<div class="history-head"><strong>' + esc(phaseLabel(item.phase)) + '</strong><span>' + esc(item.scenario) + '</span></div>' +
            '<div class="history-body">' +
            '<span>requestId: ' + esc(requestId) + '</span>' +
            '<span>status: ' + esc(str(item.status)) + '</span>' +
            '<span>endpoint: ' + esc(response.endpointKey || '-') + '</span>' +
            '<span>deviceId: ' + esc(response.deviceId || '-') + '</span>' +
            '<span>sessionId: ' + esc(response.sessionId || '-') + '</span>' +
            '<span>auth: ' + esc(item.authCarrier || '-') + '</span>' +
            '</div>' +
            '</button>';
    }).join(''));

    el.requestHistory.querySelectorAll('[data-request-id]').forEach(function (button) {
        button.addEventListener('click', function () {
            st.requestId = button.dataset.requestId;
            setText(el.selectedRequestId, st.requestId);
            renderRequestHistory();
            const selectedResponse = st.responses.get(st.requestId) || null;
            if (selectedResponse) {
                const selectedScenario = SCENARIOS[selectedResponse.scenario] || {};
                renderHeaderPreview({
                    requestId: selectedResponse.requestId || st.requestId,
                    phase: selectedResponse.demoPhase || 'INITIAL',
                    scenarioKey: selectedResponse.scenario || st.scenario,
                    ip: selectedResponse.clientIp || selectedScenario.ip || '-',
                    uaLabel: resolveScenarioUaLabel(selectedScenario) || selectedResponse.userAgent || '-',
                    expectedAction: selectedResponse.expectedAction || selectedScenario.expect || '-',
                    deviceId: selectedResponse.deviceId || selectedScenario.deviceId || '-'
                });
            }
            renderImmediateResponse(selectedResponse);
            renderEvidenceLinks(st.responses.get(st.requestId) || null, st.evidence.get(st.requestId) || null);
            refreshEvidence(false);
        });
    });
}

function renderEvidenceLinks(response, evidence) {
    const links = resolveEvidenceLinks(response, evidence);
    st.activeLinks = links;
    if (!links) {
        setHtml(el.evidenceLinks, '');
        return;
    }

    setHtml(el.evidenceLinks,
        '<a href="' + esc(links.evidenceUrl) + '" target="_blank" rel="noopener">' + esc(MSG.evidenceJson || 'Evidence JSON') + '</a>' +
        '<a href="' + esc(links.evidenceExportUrl) + '" target="_blank" rel="noopener">' + esc(MSG.exportJson || 'Export JSON') + '</a>' +
        '<a href="' + esc(links.evidenceStreamUrl) + '" target="_blank" rel="noopener">' + esc(MSG.ndjsonStream || 'NDJSON Stream') + '</a>' +
        '<a href="' + esc(links.actionStatusUrl) + '" target="_blank" rel="noopener">' + esc(MSG.serverTruth || 'Server Truth') + '</a>'
    );
}

function refreshAuth() {
    restoreTokenMemory();
    const tokenMemory = window.TokenMemory || {};
    const accessToken = pick(tokenMemory.accessToken, safeGet(window.localStorage, STORE.access), safeGet(window.sessionStorage, STORE.access));
    const refreshToken = pick(tokenMemory.refreshToken, safeGet(window.localStorage, STORE.refresh), safeGet(window.sessionStorage, STORE.refresh));
    const source = resolveTokenSource(tokenMemory, accessToken);
    const mode = pick(safeGet(window.localStorage, STORE.mode), safeGet(window.sessionStorage, STORE.mode), accessToken ? 'header' : 'cookie');
    const subject = pick(resolveTokenSubject(accessToken), st.user, 'unknown');
    const attached = Boolean(accessToken);

    st.auth = {
        mode: mode,
        source: source,
        carrier: resolveAuthCarrier(mode, attached),
        subject: subject,
        attached: attached,
        accessToken: accessToken,
        refreshToken: refreshToken
    };

    setText(el.authTransport, st.auth.carrier);
    setText(el.authTokenSource, st.auth.mode + ' / ' + st.auth.source);
    setText(el.authTokenState, attached ? 'ATTACHED' : 'COOKIE_ONLY');
    setText(el.authSubject, subject);
}

function restoreTokenMemory() {
    const accessToken = pick(safeGet(window.localStorage, STORE.access), safeGet(window.sessionStorage, STORE.access));
    const refreshToken = pick(safeGet(window.localStorage, STORE.refresh), safeGet(window.sessionStorage, STORE.refresh));
    if (!window.TokenMemory) {
        window.TokenMemory = { accessToken: null, refreshToken: null };
    }
    if (!window.TokenMemory.accessToken && accessToken) {
        window.TokenMemory.accessToken = accessToken;
    }
    if (!window.TokenMemory.refreshToken && refreshToken) {
        window.TokenMemory.refreshToken = refreshToken;
    }
}

function buildHeaders(base) {
    const headers = Object.assign({}, base || {}, {
        'X-Contexa-Auth-Mode': st.auth.mode,
        'X-Contexa-Token-Source': st.auth.source,
        'X-Contexa-Auth-Carrier': st.auth.carrier,
        'X-Contexa-Auth-Subject': st.auth.subject,
        'X-Contexa-Authorization-Present': String(st.auth.attached)
    });
    if (st.auth.accessToken) {
        headers.Authorization = 'Bearer ' + st.auth.accessToken;
    }
    return headers;
}

function buildEndpointUrl(endpoint, resourceId) {
    const base = API.endpointBases[endpoint] || API.endpointBases.normal;
    return base + encodeURIComponent(resourceId);
}

function buildStatusUrl(requestId) {
    if (!requestId) {
        return API.status;
    }
    const separator = API.status.indexOf('?') >= 0 ? '&' : '?';
    return API.status + separator + 'requestId=' + encodeURIComponent(requestId);
}

function resolveEvidenceLinks(response, evidence) {
    const responseData = response || {};
    const evidenceData = evidence || {};
    const requestId = responseData.requestId || evidenceData.requestId || st.requestId;
    if (!requestId) {
        return null;
    }
    return {
        requestId: requestId,
        evidenceUrl: responseData.evidenceUrl || (API.evidenceBase + '/' + encodeURIComponent(requestId)),
        evidenceExportUrl: responseData.evidenceExportUrl || (API.evidenceBase + '/' + encodeURIComponent(requestId) + '/export'),
        evidenceStreamUrl: responseData.evidenceStreamUrl || (API.evidenceBase + '/' + encodeURIComponent(requestId) + '/stream'),
        actionStatusUrl: responseData.actionStatusUrl || buildStatusUrl(requestId)
    };
}
function resolveTokenSource(tokenMemory, accessToken) {
    if (tokenMemory && tokenMemory.accessToken && tokenMemory.accessToken === accessToken) {
        return 'memory';
    }
    if (safeGet(window.localStorage, STORE.access) === accessToken && accessToken) {
        return 'localStorage';
    }
    if (safeGet(window.sessionStorage, STORE.access) === accessToken && accessToken) {
        return 'sessionStorage';
    }
    return 'none';
}

function resolveTokenSubject(token) {
    const payload = decodeJwtPayload(token);
    if (!payload) {
        return null;
    }
    return pick(payload.sub, payload.username, payload.user_name);
}

function decodeJwtPayload(token) {
    if (!token) {
        return null;
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
        return null;
    }
    try {
        const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
        return JSON.parse(window.atob(padded));
    } catch (error) {
        return null;
    }
}

function resolveAuthCarrier(mode, attached) {
    if (attached) {
        return 'SESSION_COOKIE + BEARER';
    }
    if (mode === 'header' || mode === 'header_cookie') {
        return 'SESSION_COOKIE_ONLY (TOKEN_MISSING)';
    }
    return 'SESSION_COOKIE_ONLY';
}

function resolveSessionCookie() {
    const cookies = document.cookie.split(';');
    for (let index = 0; index < cookies.length; index += 1) {
        const cookie = cookies[index].trim();
        if (cookie.indexOf('JSESSIONID=') === 0) {
            return cookie.substring('JSESSIONID='.length);
        }
    }
    const latestHistory = st.history.length > 0 ? st.history[0] : null;
    return latestHistory && latestHistory.body && latestHistory.body.sessionId ? latestHistory.body.sessionId : '-';
}

function resolveDeviceId(scenario) {
    try {
        const stored = window.localStorage ? window.localStorage.getItem('deviceId') : null;
        if (stored && String(stored).trim() !== '') {
            return String(stored).trim();
        }
    } catch (error) {
        // ignore local storage access errors
    }
    return scenario && scenario.deviceId ? scenario.deviceId : '-';
}

function resolveScenarioUaHeader(scenario) {
    return scenario && scenario.uaHeader ? String(scenario.uaHeader).trim() : '-';
}

function resolveScenarioUaLabel(scenario) {
    return scenario && scenario.uaLabel ? String(scenario.uaLabel).trim() : '-';
}

function scenarioUaParts(uaLabel) {
    const text = String(uaLabel || '-');
    const parts = text.split('/').map(function (item) { return item.trim(); });
    return {
        browser: parts[0] || '-',
        os: parts[1] || '-'
    };
}

async function fetchJson(url, options) {
    const response = await fetch(url, options || {});
    return parseBody(response);
}

async function fetchText(url) {
    const response = await fetch(url, {
        headers: buildHeaders({ 'Accept': 'application/x-ndjson, text/plain, application/json' }),
        credentials: 'same-origin'
    });
    if (!response.ok) {
        throw new Error('HTTP ' + response.status);
    }
    return response.text();
}

async function parseBody(response) {
    const text = await response.text();
    if (!text) {
        return { httpStatus: response.status };
    }
    const parsed = asJson(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        if (parsed.httpStatus == null) {
            parsed.httpStatus = response.status;
        }
        return parsed;
    }
    return { raw: text, httpStatus: response.status };
}

function asJson(text) {
    if (!text) {
        return null;
    }
    try {
        return JSON.parse(text);
    } catch (error) {
        return null;
    }
}

function addTimelineEntry(type, summary, requestId) {
    const resolvedRequestId = requestId || st.requestId || 'unlinked';
    const list = st.events.get(resolvedRequestId) || [];
    list.push({
        type: type,
        requestId: resolvedRequestId,
        timestamp: Date.now(),
        reasoningSummary: summary,
        local: true
    });
    st.events.set(resolvedRequestId, list);
    if (resolvedRequestId === st.requestId) {
        renderTimeline();
    }
}

function boolItem(label, passed) {
    return consistencyItem(label, passed ? (MSG.match || 'Match') : (MSG.mismatch || 'Mismatch'), passed ? 'pass' : 'fail');
}

function stateItem(label, state) {
    const normalized = normalizeConsistencyState(state);
    if (normalized === 'MATCH') {
        return consistencyItem(label, MSG.match || 'Match', 'pass');
    }
    if (normalized === 'NOT_APPLICABLE') {
        return consistencyItem(label, MSG.notApplicable || 'Not Applicable', 'pending');
    }
    if (normalized === 'MISMATCH') {
        return consistencyItem(label, MSG.mismatch || 'Mismatch', 'fail');
    }
    return consistencyItem(label, MSG.waiting || 'Waiting', 'pending');
}

function normalizeConsistencyState(state) {
    const value = str(state).trim().toUpperCase();
    if (value === 'MATCH' || value === 'NOT_APPLICABLE' || value === 'MISMATCH' || value === 'PENDING') {
        return value;
    }
    return 'PENDING';
}

function consistencyItem(label, text, kind) {
    return '<div class="consistency-item ' + esc(kind) + '"><strong>' + esc(label) + '</strong><span>' + esc(text) + '</span></div>';
}

function card(title, pairs) {
    return '<article class="summary-card"><h3>' + esc(title) + '</h3>' + pairs.map(function (entry) {
        return row(entry[0], entry[1]);
    }).join('') + '</article>';
}

function row(label, value) {
    return '<div class="summary-row"><span>' + esc(label) + '</span><strong>' + esc(str(value)) + '</strong></div>';
}

function facts(items) {
    if (!items || !items.length) {
        return empty(MSG.noEvidence || 'No evidence selected');
    }
    return items.map(function (entry) {
        return '<div><dt>' + esc(entry[0]) + '</dt><dd>' + esc(str(entry[1])) + '</dd></div>';
    }).join('');
}

function snapshotSummary(snapshot) {
    if (!snapshot) {
        return MSG.snapshotNone || 'None';
    }
    const keys = Object.keys(snapshot).filter(function (key) {
        return snapshot[key] !== null && snapshot[key] !== undefined;
    });
    if (!keys.length) {
        return MSG.snapshotNone || 'None';
    }
    return keys.slice(0, 3).map(function (key) {
        return key + '=' + str(snapshot[key]);
    }).join(', ');
}

function deriveAction(events) {
    const list = events || [];
    for (let index = list.length - 1; index >= 0; index -= 1) {
        if (list[index] && list[index].action) {
            return list[index].action;
        }
    }
    return null;
}

function latestReasoning(events) {
    const list = events || [];
    for (let index = list.length - 1; index >= 0; index -= 1) {
        const event = list[index];
        if (event && (event.reasoningSummary || event.reasoning)) {
            return event.reasoningSummary || event.reasoning;
        }
    }
    return null;
}
function setSseState(kind, message) {
    el.sseIndicator.className = 'status-dot ' + kind;
    setText(el.sseText, message || '-');
}

function setRunButtonsBusy(busy) {
    [el.btnRunInitial, el.btnRunFollowUp, el.btnRefreshServer, el.btnExportEvidence, el.btnStreamEvidence, el.btnResetConsole].forEach(function (button) {
        if (button) {
            button.disabled = busy;
        }
    });
}

function phaseLabel(phase) {
    if (phase === 'INITIAL') {
        return '1st Request';
    }
    if (phase === 'FOLLOW_UP') {
        return 'Follow-up';
    }
    return str(phase);
}

function verdictClass(action) {
    const normalized = String(action || '').toUpperCase();
    if (normalized.indexOf('BLOCK') >= 0) {
        return 'block';
    }
    if (normalized.indexOf('CHALLENGE') >= 0) {
        return 'challenge';
    }
    if (normalized.indexOf('ESCALATE') >= 0) {
        return 'escalate';
    }
    if (normalized.indexOf('ALLOW') >= 0) {
        return 'allow';
    }
    return 'pending';
}

function timelineClass(type) {
    if (type === 'ERROR') {
        return 'error';
    }
    if (type === 'DECISION_APPLIED' || type === 'RESPONSE_BLOCKED') {
        return 'decision';
    }
    if (String(type || '').indexOf('LAYER2') >= 0) {
        return 'layer2';
    }
    if (String(type || '').indexOf('LAYER1') >= 0) {
        return 'layer1';
    }
    return 'context';
}

function toSortableTime(value) {
    if (typeof value === 'number') {
        return value;
    }
    if (!value) {
        return 0;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? 0 : parsed;
}

function formatTimestamp(value) {
    const timestamp = toSortableTime(value);
    if (!timestamp) {
        return '-';
    }
    return new Date(timestamp).toLocaleTimeString('ko-KR', { hour12: false });
}

function pretty(value) {
    return JSON.stringify(value || {}, null, 2);
}

function sizeOf(value) {
    if (Array.isArray(value)) {
        return value.length;
    }
    if (value && typeof value === 'object') {
        return Object.keys(value).length;
    }
    return value == null ? '-' : value;
}

function num(value) {
    if (value === null || value === undefined || value === '' || Number.isNaN(Number(value))) {
        return '-';
    }
    return Number(value).toFixed(2);
}

function str(value) {
    if (value === null || value === undefined || value === '') {
        return '-';
    }
    if (typeof value === 'object') {
        return JSON.stringify(value);
    }
    return String(value);
}

function pick() {
    for (let index = 0; index < arguments.length; index += 1) {
        const value = arguments[index];
        if (typeof value === 'string' && value.trim() !== '') {
            return value.trim();
        }
    }
    return null;
}

function safeGet(storage, key) {
    try {
        return storage ? storage.getItem(key) : null;
    } catch (error) {
        return null;
    }
}

function setHtml(node, value) {
    if (node) {
        node.innerHTML = value;
    }
}

function setText(node, value) {
    if (node) {
        node.textContent = value == null ? '' : String(value);
    }
}

function empty(message) {
    return '<div class="empty-state">' + esc(message) + '</div>';
}

function esc(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function toCamel(id) {
    return id.replace(/-([a-z])/g, function (_, letter) {
        return letter.toUpperCase();
    });
}

function createId(prefix) {
    return prefix + '-' + Date.now() + '-' + Math.random().toString(16).slice(2, 8);
}
})();
