package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationCcrExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationCcrExecutionService.CcrRunRecord, OfficialVerificationCcrExecutionService.EndpointDefinition> implements OfficialVerificationCcrExecutor {

    private static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "CCR",
                    OfficialVerificationCcrExecutionService.class.getName(),
                    "executeRun / buildRequestFacts / buildRawEvidence",
                    "metricCode"
            );

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE = new ParameterizedTypeReference<>() {
    };
    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String DEVICE_ID_HEADER = "X-Device-Id";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String CCR_CLIENT_IP = "192.168.1.100";
    private static final String CCR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String CCR_USER_AGENT_LABEL = "Chrome 120 / Windows 11";
    private static final String CCR_DEVICE_ID = "official-verification-ccr-admin-browser";

    private static final int ESSENTIAL_FIELD_COUNT = 10;

    public OfficialVerificationCcrExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper
    ) {
        super("CCR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, webClientBuilder, objectMapper, CcrRunRecord::runId, CcrRunRecord::startedAt);
    }

    @Override
    public synchronized CcrRunRecord executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
    ) {
        return executeRunTemplate(userId, endpointKey, resourceId, requestPath, requestedRunCount, rerun, contaminationSeed, baselineSeedRequested, request);
    }

    @Override
    protected String resolveVerificationUserId(String userId, String requestId) {
        return OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId);
    }

    @Override
    protected String requestIdPrefix() {
        return "enterprise-ccr-";
    }

    @Override
    protected void beforeInvocation(
            EndpointDefinition endpoint,
            String userId,
            String verificationUserId,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
    ) {
        primeSessionContext(endpoint, requestId, verificationUserId, contaminationSeed, baselineSeedRequested, request);
    }

    @Override
    protected EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.retargetProbeTarget(endpointKey, resourceId, requestPath, List.of("normal", "sensitive", "critical"));
        return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        }, replayTarget.requestPath(), replayTarget.resourceId());
    }
    @Override
    protected CcrRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
        Map<String, Object> decisionPayload = state.artifacts().decisionPayload();
        Map<String, Object> promptPayload = state.artifacts().promptPayload();
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events = state.artifacts().events();
        Map<String, Object> sessionMetadata = firstMetadata(events, "SESSION_CONTEXT_LOADED");
        Map<String, Object> behaviorMetadata = firstMetadata(events, "BEHAVIOR_ANALYSIS_COMPLETE");
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> eventMetadata = primaryEventMetadata(events);
        Map<String, Object> promptExecutionMetadata = firstPresent(extractPromptPayload(events), map(promptPayload.get("promptRuntimeTelemetry")), promptPayload);
        List<CcrCheckResult> checks = buildChecks(state.endpoint(), eventMetadata, sessionMetadata, behaviorMetadata, promptExecutionMetadata);
        int totalChecks = checks.size();
        int passedChecks = (int) checks.stream().filter(CcrCheckResult::pass).count();
        double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
        int relatedDocumentsCount = relatedDocumentsCount(promptPayload, decisionMetadata);
        int expectedRelatedDocuments = expectedRelatedDocuments(state.requestedRunCount());
        boolean relatedDocumentsExpectationSatisfied = relatedDocumentsCount >= expectedRelatedDocuments;
        boolean requestParitySatisfied = state.requestId().equals(text(state.invocation(), "requestId"))
                && state.requestId().equals(text(decisionPayload, "correlationId"))
                && state.requestId().equals(text(promptPayload, "correlationId"));
        return new CcrRunRecord(
                UUID.randomUUID().toString(),
                state.runOrdinal(),
                state.endpoint().key(),
                state.endpoint().label(),
                state.requestId(),
                score,
                passedChecks,
                totalChecks,
                state.processingTimeMs(),
                score >= 95.0d ? "Threshold passed" : "Threshold failed",
                score >= 95.0d ? "success" : "error",
                score >= 95.0d ? "Required context facts stayed aligned from request through the final decision." : buildMessage(score, relatedDocumentsExpectationSatisfied, requestParitySatisfied),
                KOREA_TIME.format(state.startedAt()),
                KOREA_TIME.format(state.completedAt()),
                checks,
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(state.endpoint(), state.userId(), state.requestId(), state.invocation(), state.requestedRunCount(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested()),
                        state.request()
                ),
                buildCcrEventFacts(events),
                buildCcrPromptFacts(decisionPayload, promptPayload),
                buildCcrAnalysisFacts(decisionPayload, state.artifacts().decisionOutbox(), sessionMetadata, behaviorMetadata, decisionAttributes),
                events.stream().map(this::toCcrEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildCcrRawEvidence(state.endpoint(), state.userId(), state.requestedRunCount(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), state.invocation(), events, state.artifacts().decisionOutbox(), state.artifacts().promptOutbox(), decisionPayload, promptPayload),
                        state.request()
                )
        );
    }

    @Override
    protected Map<String, Object> invokeProbe(
            EndpointDefinition endpoint,
            String requestId,
            String verificationUserId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
    ) {
        String baseUrl = resolveBaseUrl(request);
        WebClient client = webClientBuilder.baseUrl(baseUrl).build();
        Map<String, Object> payload = client.get()
                .uri(endpoint.path())
                .headers(headers -> forwardHeaders(
                        headers,
                        request,
                        requestId,
                        verificationUserId,
                        endpoint.resourceId(),
                        endpoint.path(),
                        requestedRunCount,
                        contaminationSeed,
                        baselineSeedRequested
                ))
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .block(Duration.ofSeconds(30));
        return payload != null ? payload : Map.of();
    }

    private void primeSessionContext(
            EndpointDefinition endpoint,
            String requestId,
            String verificationUserId,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
    ) {
        if (endpoint == null || !StringUtils.hasText(requestId)) {
            return;
        }
        EndpointDefinition warmupEndpoint = resolveEndpoint(endpoint.key(), endpoint.resourceId() + "-warmup", endpoint.path());
        invokeProbe(
                warmupEndpoint,
                requestId + "-warmup",
                verificationUserId,
                1,
                contaminationSeed,
                baselineSeedRequested,
                request
        );
        sleep(250L);
    }

        private void forwardHeaders(
            HttpHeaders headers,
            HttpServletRequest request,
            String requestId,
            String verificationUserId,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(HttpHeaders.USER_AGENT, CCR_BROWSER_USER_AGENT);
        headers.set(FORWARDED_FOR_HEADER, CCR_CLIENT_IP);
        headers.set(DEVICE_ID_HEADER, CCR_DEVICE_ID);
        headers.set(SIMULATED_USER_AGENT_HEADER, CCR_BROWSER_USER_AGENT);
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, CCR_USER_AGENT_LABEL);
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, verificationUserId);
        if (request == null) {
            return;
        }
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }
    private List<CcrCheckResult> buildChecks(
            EndpointDefinition endpoint,
            Map<String, Object> eventMetadata,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> promptExecutionMetadata
    ) {
        Map<String, Object> sessionSource = firstPresent(sessionMetadata, eventMetadata);
        Map<String, Object> behaviorSource = firstPresent(behaviorMetadata, eventMetadata);
        String requestPath = endpoint != null ? endpoint.path() : null;
        String expectedSensitivity = expectedSensitivity(requestPath);
        String expectedSensitiveResource = String.valueOf(expectedSensitiveResource(requestPath));
        String currentUserAgent = text(behaviorSource, "currentUserAgent", "userAgent");
        if (!StringUtils.hasText(currentUserAgent)) {
            currentUserAgent = text(eventMetadata, "userAgent");
        }
        String currentUserAgentOs = resolveCurrentUserAgentOs(behaviorSource, currentUserAgent);
        String currentUserAgentBrowser = resolveCurrentUserAgentBrowser(behaviorSource, currentUserAgent);
        return List.of(
                check(
                        "event metadata authMethod is populated",
                        "present",
                        text(eventMetadata, "authMethod"),
                        StringUtils.hasText(text(eventMetadata, "authMethod")),
                        "event.metadata.authMethod"
                ),
                check(
                        "event metadata authorizationEffect is populated",
                        "present",
                        text(eventMetadata, "authorizationEffect"),
                        StringUtils.hasText(text(eventMetadata, "authorizationEffect")),
                        "event.metadata.authorizationEffect"
                ),
                check(
                        "event metadata resourceSensitivity is populated",
                        value(expectedSensitivity),
                        text(eventMetadata, "resourceSensitivity"),
                        sameValue(expectedSensitivity, text(eventMetadata, "resourceSensitivity")),
                        "event.metadata.resourceSensitivity"
                ),
                check(
                        "event metadata isSensitiveResource is populated",
                        expectedSensitiveResource,
                        text(eventMetadata, "isSensitiveResource"),
                        sameValue(expectedSensitiveResource, text(eventMetadata, "isSensitiveResource")),
                        "event.metadata.isSensitiveResource"
                ),
                check(
                        "event metadata effectiveRoles is populated",
                        "1+",
                        joinList(eventMetadata.get("effectiveRoles")),
                        !castList(eventMetadata.get("effectiveRoles")).isEmpty(),
                        "event.metadata.effectiveRoles"
                ),
                check(
                        "event metadata effectivePermissions is populated",
                        "1+",
                        joinList(eventMetadata.get("effectivePermissions")),
                        !castList(eventMetadata.get("effectivePermissions")).isEmpty(),
                        "event.metadata.effectivePermissions"
                ),
                check(
                        "sessionCtx.userId is populated",
                        "present",
                        text(sessionSource, "userId"),
                        StringUtils.hasText(text(sessionSource, "userId")),
                        "sessionCtx.userId"
                ),
                check(
                        "sessionCtx.authMethod is populated",
                        "present",
                        text(sessionSource, "authMethod"),
                        StringUtils.hasText(text(sessionSource, "authMethod")),
                        "sessionCtx.authMethod"
                ),
                check(
                        "sessionCtx.requestCount is populated",
                        "1+",
                        text(sessionSource, "requestCount", "recentRequestCount"),
                        integer(sessionSource, "requestCount", "recentRequestCount") > 0,
                        "sessionCtx.requestCount"
                ),
                check(
                        "behaviorCtx.currentUserAgentOS is populated",
                        "present",
                        currentUserAgentOs,
                        StringUtils.hasText(currentUserAgentOs),
                        "behaviorCtx.currentUserAgentOS"
                ),
                check(
                        "behaviorCtx.currentUserAgentBrowser is populated",
                        "present",
                        currentUserAgentBrowser,
                        StringUtils.hasText(currentUserAgentBrowser),
                        "behaviorCtx.currentUserAgentBrowser"
                ),
                check(
                        "promptExecutionMetadata is captured",
                        "present",
                        promptExecutionMetadata.isEmpty() ? "absent" : "present",
                        !promptExecutionMetadata.isEmpty(),
                        "promptExecutionMetadata"
                )
        );
    }

    private CcrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new CcrCheckResult(label, value(expected), value(actual), pass, source);
    }

    private Map<String, String> buildRequestFacts(
            EndpointDefinition endpoint,
            String userId,
            String requestId,
            Map<String, Object> invocation,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("verificationUser", value(userId));
        facts.put("endpoint", endpoint.label());
        facts.put("resourceId", endpoint.resourceId());
        facts.put("requestId", requestId);
        facts.put("responseRequestId", value(text(invocation, "requestId")));
        facts.put("requestPath", value(text(invocation, "requestPath")));
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, CONTRACT_STATUS);
    }
    private Map<String, String> buildEventFacts(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Event count", String.valueOf(events.size()));
        facts.put("First event", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("Last event", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("Decision event present", events.stream().anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type())) ? "yes" : "no");
        return facts;
    }

    private Map<String, String> buildPromptFacts(Map<String, Object> decisionPayload, Map<String, Object> promptPayload) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Prompt key", value(text(decisionPayload, "promptKey")));
        facts.put("Template key", value(text(decisionPayload, "promptTemplateKey")));
        facts.put("Prompt hash", value(text(decisionPayload, "promptHash")));
        facts.put("System prompt hash", value(text(decisionPayload, "systemPromptHash")));
        facts.put("User prompt hash", value(text(decisionPayload, "userPromptHash")));
        facts.put("Retrieval purpose", value(text(promptPayload, "retrievalPurpose")));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(Map<String, Object> decisionPayload, SecurityDecisionForwardingOutboxRecord decisionOutbox) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Decision", value(text(decisionPayload, "decision")));
        facts.put("Risk score", value(text(decisionPayload, "llmAuditRiskScore")));
        facts.put("Confidence", value(text(decisionPayload, "effectiveConfidence")));
        facts.put("Outbox status", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        return facts;
    }

    private List<CcrEventItem> buildEventItems(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream()
                .map(this::toCcrEventItem)
                .toList();
    }

    private CcrEventItem toCcrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new CcrEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    private Map<String, String> buildCcrEventFacts(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("eventCount", String.valueOf(events.size()));
        facts.put("firstEvent", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("lastEvent", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("decisionEventPresent", Boolean.toString(events.stream().anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()))));
        facts.put("requestId", value(decisionMetadata != null ? text(decisionMetadata, "requestId", "correlationId") : null));
        facts.put("relatedDocumentsCount", String.valueOf(relatedDocumentsCount(extractPromptPayload(events), decisionMetadata)));
        return facts;
    }

    private Map<String, String> buildCcrPromptFacts(Map<String, Object> decisionPayload, Map<String, Object> promptPayload) {
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> promptSource = firstPresent(decisionPayload, decisionAttributes);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptKey", value(text(promptSource, "promptKey")));
        facts.put("templateKey", value(text(promptSource, "promptTemplateKey", "templateKey")));
        facts.put("promptVersion", value(text(promptSource, "promptVersion")));
        facts.put("promptHash", value(text(promptSource, "promptHash")));
        facts.put("promptSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptSource,
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload", decisionPayload),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        facts.put("retrievalPurpose", value(text(promptPayload, "retrievalPurpose")));
        facts.put("allowedDocumentCount", value(text(promptPayload, "allowedDocumentCount")));
        return facts;
    }

    private Map<String, String> buildCcrAnalysisFacts(
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> decisionAttributes
    ) {
        Map<String, Object> sessionSource = firstPresent(sessionMetadata, decisionAttributes);
        Map<String, Object> behaviorSource = firstPresent(behaviorMetadata, decisionAttributes);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(text(decisionPayload, "decision")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        facts.put("sessionSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                sessionSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[SESSION_CONTEXT_LOADED].metadata", sessionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        facts.put("behaviorSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                behaviorSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[BEHAVIOR_ANALYSIS_COMPLETE].metadata", behaviorMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        facts.put("previousPath", value(text(sessionSource, "previousPath")));
        facts.put("requestCount", value(text(sessionSource, "requestCount", "recentRequestCount")));
        facts.put("baselineEstablished", value(text(behaviorSource, "baselineEstablished", "organizationBaselineEstablished")));
        facts.put("personalBaselineEstablished", value(text(behaviorSource, "personalBaselineEstablished")));
        facts.put("newDevice", value(text(behaviorSource, "isNewDevice", "newDevice")));
        return facts;
    }

    private Map<String, Object> buildRawEvidence(
            EndpointDefinition endpoint,
            String userId,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("requestedPreset", Map.of(
                "verificationUser", value(userId),
                "endpointKey", endpoint.key(),
                "endpointLabel", endpoint.label(),
                "resourceId", endpoint.resourceId(),
                "requestedRunCount", requestedRunCount,
                "rerun", rerun,
                "contaminationSeed", contaminationSeed,
                "baselineSeedRequested", baselineSeedRequested
        ));
        evidence.put("invocation", invocation != null ? invocation : Map.of());
        evidence.put("analysisEvents", events);
                evidence.put("decisionOutbox", OfficialVerificationRuntimeEvidenceSupport.decisionOutboxSnapshot(
                decisionOutbox,
                decisionPayload
        ));
        evidence.put("promptAuditOutbox", OfficialVerificationRuntimeEvidenceSupport.promptAuditOutboxSnapshot(
                promptOutbox,
                promptPayload
        ));
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, CONTRACT_STATUS);
    }

    private Map<String, Object> buildCcrRawEvidence(
            EndpointDefinition endpoint,
            String userId,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
        Map<String, Object> evidence = buildRawEvidence(
                endpoint,
                userId,
                requestedRunCount,
                rerun,
                contaminationSeed,
                baselineSeedRequested,
                invocation,
                events,
                decisionOutbox,
                promptOutbox,
                decisionPayload,
                promptPayload
        );
        Map<String, Object> mutable = new LinkedHashMap<>(evidence);
        Map<String, Object> sessionMetadata = firstMetadata(events, "SESSION_CONTEXT_LOADED");
        Map<String, Object> behaviorMetadata = firstMetadata(events, "BEHAVIOR_ANALYSIS_COMPLETE");
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> sessionSource = firstPresent(sessionMetadata, decisionMetadata, decisionAttributes);
        Map<String, Object> behaviorSource = firstPresent(behaviorMetadata, decisionMetadata, decisionAttributes);
        Map<String, Object> promptSource = firstPresent(decisionPayload, decisionAttributes);
        mutable.put("sessionMetadata", sessionMetadata);
        mutable.put("behaviorMetadata", behaviorMetadata);
        mutable.put("decisionMetadata", decisionMetadata);
        mutable.put("decisionAttributes", decisionAttributes);
        mutable.put("sessionContextSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                sessionSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[SESSION_CONTEXT_LOADED].metadata", sessionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        mutable.put("sessionContextPrimaryPresent", !sessionMetadata.isEmpty());
        mutable.put("behaviorContextSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                behaviorSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[BEHAVIOR_ANALYSIS_COMPLETE].metadata", behaviorMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        mutable.put("behaviorContextPrimaryPresent", !behaviorMetadata.isEmpty());
        mutable.put("promptLineageSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptSource,
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload", decisionPayload),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        mutable.put("promptLineagePrimaryPresent", !decisionPayload.isEmpty());
        return Map.copyOf(mutable);
    }
    private Map<String, Object> firstMetadata(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events, String type) {
        return events.stream()
                .filter(item -> type.equalsIgnoreCase(item.type()))
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .filter(item -> item != null && !item.isEmpty())
                .findFirst()
                .map(LinkedHashMap::new)
                .orElseGet(LinkedHashMap::new);
    }


    private Map<String, Object> primaryEventMetadata(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream()
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .filter(item -> item != null && !item.isEmpty())
                .findFirst()
                .map(LinkedHashMap::new)
                .orElseGet(LinkedHashMap::new);
    }

    private String resolveCurrentUserAgentOs(Map<String, Object> behaviorSource, String rawUserAgent) {
        String explicit = text(behaviorSource, "currentUserAgentOS");
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        return SecurityEventEnricher.extractOSFromUserAgent(rawUserAgent);
    }

    private String resolveCurrentUserAgentBrowser(Map<String, Object> behaviorSource, String rawUserAgent) {
        String explicit = text(behaviorSource, "currentUserAgentBrowser");
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        return SecurityEventEnricher.extractBrowserSignature(rawUserAgent);
    }

    private String expectedSensitivity(String requestPath) {
        if (requestPath != null && requestPath.contains("/critical/")) {
            return "CRITICAL";
        }
        if (requestPath != null && requestPath.contains("/sensitive/")) {
            return "HIGH";
        }
        if (requestPath != null && requestPath.contains("/normal/")) {
            return "STANDARD";
        }
        return "UNKNOWN";
    }

    private boolean expectedSensitiveResource(String requestPath) {
        return requestPath != null && (requestPath.contains("/critical/") || requestPath.contains("/sensitive/"));
    }
    private Map<String, Object> firstPresent(Map<String, Object>... sources) {
        for (Map<String, Object> source : sources) {
            if (source != null && !source.isEmpty()) {
                return source;
            }
        }
        return Map.of();
    }

    private Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            raw.forEach((key, item) -> {
                if (key != null && item != null) {
                    normalized.put(String.valueOf(key), item);
                }
            });
            return Map.copyOf(normalized);
        }
        return Map.of();
    }


    private boolean sameValue(String left, String right) {
        if (!StringUtils.hasText(left) || !StringUtils.hasText(right)) {
            return false;
        }
        return left.trim().equalsIgnoreCase(right.trim());
    }

    private List<String> castList(Object value) {
        if (value instanceof List<?> items) {
            return items.stream()
                    .filter(item -> item != null && StringUtils.hasText(String.valueOf(item)))
                    .map(String::valueOf)
                    .toList();
        }
        if (value == null) {
            return List.of();
        }
        String normalized = String.valueOf(value).trim();
        if (!StringUtils.hasText(normalized)) {
            return List.of();
        }
        return List.of(normalized);
    }

    private String joinList(Object value) {
        List<String> items = castList(value);
        return items.isEmpty() ? null : String.join(", ", items);
    }
    private boolean containsValue(Map<String, Object> source, String... keys) {
        if (source == null) {
            return false;
        }
        for (String key : keys) {
            if (source.containsKey(key) && source.get(key) != null) {
                return true;
            }
        }
        return false;
    }

    private int integer(Map<String, Object> source, String... keys) {
        if (source == null) {
            return 0;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String textValue) {
                try {
                    return Integer.parseInt(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    private int expectedRelatedDocuments(int requestedRunCount) {
        return requestedRunCount <= 1 ? 0 : Math.min(2, requestedRunCount - 1);
    }

    private int relatedDocumentsCount(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        int allowedDocumentCount = integer(promptPayload, "allowedDocumentCount");
        if (allowedDocumentCount > 0) {
            return allowedDocumentCount;
        }
        Object contexts = promptPayload.get("contexts");
        if (contexts instanceof List<?> items && !items.isEmpty()) {
            return items.size();
        }
        return integer(decisionMetadata, "relatedDocumentsCount");
    }

        private boolean relatedDocumentsEvidenceCaptured(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        return containsValue(promptPayload, "allowedDocumentCount", "requestedDocumentCount")
                || promptPayload.containsKey("contexts")
                || containsValue(decisionMetadata, "relatedDocumentsCount");
    }

    private String relatedDocumentsEvidenceLabel(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        if (promptPayload.containsKey("contexts")) {
            return "contexts";
        }
        if (containsValue(promptPayload, "allowedDocumentCount")) {
            return "allowedDocumentCount";
        }
        if (containsValue(promptPayload, "requestedDocumentCount")) {
            return "requestedDocumentCount";
        }
        if (containsValue(decisionMetadata, "relatedDocumentsCount")) {
            return "decisionMetadata.relatedDocumentsCount";
        }
        return null;
    }

    private Map<String, Object> extractPromptPayload(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream()
                .filter(item -> item != null && item.metadata() != null && !item.metadata().isEmpty())
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .map(this::extractPromptPayload)
                .filter(item -> !item.isEmpty())
                .findFirst()
                .orElseGet(Map::of);
    }

    private Map<String, Object> extractPromptPayload(Map<String, Object> metadata) {
        Map<String, Object> promptExecutionMetadata = map(metadata.get("promptExecutionMetadata"));
        if (!promptExecutionMetadata.isEmpty()) {
            return promptExecutionMetadata;
        }
        Map<String, Object> promptMetadata = map(metadata.get("promptMetadata"));
        if (!promptMetadata.isEmpty()) {
            return promptMetadata;
        }
        return Map.of();
    }
    private String text(Map<String, Object> source, String... keys) {
        if (source == null) {
            return null;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value == null) {
                continue;
            }
            String normalized = String.valueOf(value).trim();
            if (!normalized.isBlank()) {
                return normalized;
            }
        }
        return null;
    }

    private String value(String input) {
        return StringUtils.hasText(input) ? input : "absent";
    }

    private String buildMessage(double score, boolean relatedDocumentsExpectationSatisfied, boolean requestParitySatisfied) {
        if (score < 95.0d) {
            return "CCR required fields are still missing in the enterprise evidence path.";
        }
        if (!requestParitySatisfied) {
            return "CCR field coverage is high, but browser requestId and outbox linkage are not fully aligned yet.";
        }
        if (!relatedDocumentsExpectationSatisfied) {
            return "CCR field coverage is high, but related document accumulation is below the expected round threshold.";
        }
        return "CCR required fields are populated and the enterprise evidence path is aligned.";
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }



    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record CcrRunSummary(
            String runId,
            int round,
            String endpointKey,
            String endpointLabel,
            String requestId,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String state,
            String stateTone,
            String startedAt,
            String completedAt) {
    }

    public record CcrRunRecord(
            String runId,
            int round,
            String endpointKey,
            String endpointLabel,
            String requestId,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String state,
            String stateTone,
            String message,
            String startedAt,
            String completedAt,
            List<CcrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<CcrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<CcrCheckResult, CcrEventItem> {

        public CcrRunSummary toSummary() {
            return new CcrRunSummary(
                    runId,
                    round,
                    endpointKey,
                    endpointLabel,
                    requestId,
                    score,
                    passedChecks,
                    totalChecks,
                    processingTimeMs,
                    state,
                    stateTone,
                    startedAt,
                    completedAt
            );
        }
    }

    public record CcrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record CcrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}











