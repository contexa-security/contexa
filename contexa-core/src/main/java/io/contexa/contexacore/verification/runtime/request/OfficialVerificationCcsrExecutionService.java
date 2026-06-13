package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
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
public class OfficialVerificationCcsrExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationCcsrExecutionService.CcsrRunRecord, OfficialVerificationCcsrExecutionService.EndpointDefinition> implements OfficialVerificationCcsrExecutor {

    private static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "CCSR",
                    OfficialVerificationCcsrExecutionService.class.getName(),
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
    private static final String CCSR_CLIENT_IP = "192.168.1.100";
    private static final String CCSR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String CCSR_USER_AGENT_LABEL = "Chrome 120 / Windows 11";
    private static final String CCSR_DEVICE_ID = "official-verification-ccsr-admin-browser";

    private static final int ESSENTIAL_FIELD_COUNT = 10;

    private final OfficialVerificationFreshOutboxReader freshOutboxReader;
    private final ZeroTrustActionRepository zeroTrustActionRepository;

    public OfficialVerificationCcsrExecutionService(
        SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
        PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
        OfficialVerificationAnalysisEventStore analysisEventStore,
        WebClient.Builder webClientBuilder,
        ObjectMapper objectMapper,
        OfficialVerificationFreshOutboxReader freshOutboxReader,
        ZeroTrustActionRepository zeroTrustActionRepository
) {
    super("CCSR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, webClientBuilder, objectMapper, CcsrRunRecord::runId, CcsrRunRecord::startedAt);
    this.freshOutboxReader = freshOutboxReader;
    this.zeroTrustActionRepository = zeroTrustActionRepository;
}

@Override
public synchronized CcsrRunRecord executeRun(
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
protected String requestIdPrefix() {
    return "enterprise-ccsr-";
}

@Override
protected String resolveVerificationUserId(String userId, String requestId) {
    return OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId);
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
    resetUserDecisionState(verificationUserId);
}

@Override
protected RequestMetricExecutionArtifacts refineArtifacts(String requestId, RequestMetricExecutionArtifacts artifacts) {
    SecurityDecisionForwardingOutboxRecord decisionOutbox = freshDecisionOutbox(requestId, artifacts.decisionOutbox());
    PromptContextAuditForwardingOutboxRecord promptOutbox = freshPromptAuditOutbox(requestId, artifacts.promptOutbox());
    return new RequestMetricExecutionArtifacts(
            artifacts.events(),
            decisionOutbox,
            promptOutbox,
            parseJson(decisionOutbox != null ? decisionOutbox.getPayloadJson() : null),
            parseJson(promptOutbox != null ? promptOutbox.getPayloadJson() : null)
    );
}

@Override
protected CcsrRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
    Map<String, Object> sessionMetadata = firstMetadata(state.artifacts().events(), "SESSION_CONTEXT_LOADED");
    Map<String, Object> behaviorMetadata = firstMetadata(state.artifacts().events(), "BEHAVIOR_ANALYSIS_COMPLETE");
    Map<String, Object> decisionAttributes = map(state.artifacts().decisionPayload().get("attributes"));
    Map<String, Object> primaryEventMetadata = primaryEventMetadata(state.artifacts().events());
    List<CcsrCheckResult> checks = buildChecks(
            state.endpoint(),
            state.invocation(),
            primaryEventMetadata,
            state.artifacts().promptPayload()
    );
    int totalChecks = checks.size();
    int passedChecks = (int) checks.stream().filter(CcsrCheckResult::pass).count();
    double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
    return new CcsrRunRecord(
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
            buildMessage(score),
            KOREA_TIME.format(state.startedAt()),
            KOREA_TIME.format(state.completedAt()),
            checks,
            OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                    buildRequestFacts(
                            state.endpoint(),
                            state.userId(),
                            state.requestId(),
                            state.invocation(),
                            state.requestedRunCount(),
                            state.rerun(),
                            state.contaminationSeed(),
                            state.baselineSeedRequested()
                    ),
                    state.request()
            ),
            buildCcsrEventFacts(state.artifacts().events()),
            buildCcsrPromptFacts(state.artifacts().decisionPayload(), state.artifacts().promptPayload()),
            buildCcsrAnalysisFacts(state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), sessionMetadata, behaviorMetadata, decisionAttributes),
            state.artifacts().events().stream().map(this::toCcsrEventItem).toList(),
            OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                    buildCcsrRawEvidence(
                            state.endpoint(),
                            state.userId(),
                            state.requestedRunCount(),
                            state.rerun(),
                            state.contaminationSeed(),
                            state.baselineSeedRequested(),
                            state.invocation(),
                            state.artifacts().events(),
                            state.artifacts().decisionOutbox(),
                            state.artifacts().promptOutbox(),
                            state.artifacts().decisionPayload(),
                            state.artifacts().promptPayload()
                    ),
                    state.request()
            )
    );
}

    @Override
protected EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
    OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = resolveStandardReplayTarget(
            endpointKey,
            resourceId,
            requestPath,
            List.of("normal", "sensitive", "critical")
    );
    return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
        case "sensitive" -> "Sensitive Resource";
        case "critical" -> "Critical Resource";
        default -> "Normal Resource";
    }, replayTarget.requestPath(), replayTarget.resourceId());
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
    return invokeProbeRequest(
            request,
            endpoint.path(),
            headers -> forwardHeaders(
                    headers,
                    request,
                    requestId,
                    verificationUserId,
                    endpoint.resourceId(),
                    requestedRunCount,
                    contaminationSeed,
                    baselineSeedRequested
            )
    );
}

private void resetUserDecisionState(String userId) {
        if (zeroTrustActionRepository == null || !StringUtils.hasText(userId)) {
            return;
        }
        zeroTrustActionRepository.removeAllUserData(userId.trim());
    }

    private SecurityDecisionForwardingOutboxRecord freshDecisionOutbox(
            String requestId,
            SecurityDecisionForwardingOutboxRecord fallback
    ) {
        if (freshOutboxReader == null) {
            return fallback;
        }
        return freshOutboxReader.findFreshDecisionOutbox(requestId).orElse(fallback);
    }

    private PromptContextAuditForwardingOutboxRecord freshPromptAuditOutbox(
            String requestId,
            PromptContextAuditForwardingOutboxRecord fallback
    ) {
        if (freshOutboxReader == null) {
            return fallback;
        }
        return freshOutboxReader.awaitPromptAuditOutbox(
                requestId,
                OfficialVerificationRuntimePollingSupport.DEFAULT_ARTIFACT_TIMEOUT,
                true
        ).orElse(fallback);
    }

    private void forwardHeaders(
            HttpHeaders headers,
            HttpServletRequest request,
            String requestId,
            String userId,
            String resourceId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(HttpHeaders.USER_AGENT, CCSR_BROWSER_USER_AGENT);
        headers.set(FORWARDED_FOR_HEADER, CCSR_CLIENT_IP);
        headers.set(DEVICE_ID_HEADER, CCSR_DEVICE_ID);
        headers.set(SIMULATED_USER_AGENT_HEADER, CCSR_BROWSER_USER_AGENT);
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, CCSR_USER_AGENT_LABEL);
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, userId);
        if (request == null) {
            return;
        }
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }

    private List<CcsrCheckResult> buildChecks(
            EndpointDefinition endpoint,
            Map<String, Object> invocation,
            Map<String, Object> eventMetadata,
            Map<String, Object> promptPayload
    ) {
        String userPrompt = text(promptPayload, "userPrompt");
        String eventRequestPath = text(eventMetadata, "requestPath", "requestUri", "servletPath");
        String eventClientIp = text(eventMetadata, "clientIp");
        boolean eventMfaVerified = Boolean.parseBoolean(value(text(eventMetadata, "mfaVerified")));
        String eventResourceSensitivity = text(eventMetadata, "resourceSensitivity");
        String expectedSensitivity = expectedSensitivity(endpoint.path());
        String eventAuthorizationEffect = text(eventMetadata, "authorizationEffect");
        String responseDemoPhase = text(invocation, "demoPhase");
        String eventDemoPhase = text(eventMetadata, "demoPhase");
        boolean requestPathReflected = StringUtils.hasText(eventRequestPath) && containsText(userPrompt, eventRequestPath);
        boolean clientIpReflected = StringUtils.hasText(eventClientIp) && containsText(userPrompt, eventClientIp);
        boolean mfaPromptMatches = eventMfaVerified == containsText(userPrompt, "MfaVerified: true");
        boolean sensitivityPromptMatches = expectedSensitivity.equalsIgnoreCase(value(eventResourceSensitivity))
                == containsText(userPrompt, "Sensitivity: " + expectedSensitivity);
        boolean authorizationEffectMatches = "ALLOW".equalsIgnoreCase(eventAuthorizationEffect)
                == containsText(userPrompt, "AuthorizationEffect: ALLOW");
        boolean demoPhaseMatches = sameNullableValue(responseDemoPhase, eventDemoPhase);
        return List.of(
                check(
                        "requestPath is reflected in user prompt",
                        value(eventRequestPath),
                        pair(eventRequestPath, boolText(requestPathReflected)),
                        requestPathReflected,
                        "analysis.events.metadata.requestPath -> promptAuditOutbox.payload.userPrompt"
                ),
                check(
                        "clientIp is reflected in user prompt",
                        value(eventClientIp),
                        pair(eventClientIp, boolText(clientIpReflected)),
                        clientIpReflected,
                        "analysis.events.metadata.clientIp -> promptAuditOutbox.payload.userPrompt"
                ),
                check(
                        "mfaVerified state matches user prompt",
                        boolText(eventMfaVerified),
                        pair(boolText(eventMfaVerified), boolText(containsText(userPrompt, "MfaVerified: true"))),
                        mfaPromptMatches,
                        "analysis.events.metadata.mfaVerified -> promptAuditOutbox.payload.userPrompt"
                ),
                check(
                        "resourceSensitivity matches user prompt",
                        expectedSensitivity,
                        pair(value(eventResourceSensitivity), boolText(containsText(userPrompt, "Sensitivity: " + expectedSensitivity))),
                        sensitivityPromptMatches,
                        "analysis.events.metadata.resourceSensitivity -> promptAuditOutbox.payload.userPrompt"
                ),
                check(
                        "authorizationEffect matches user prompt",
                        value(eventAuthorizationEffect),
                        pair(value(eventAuthorizationEffect), boolText(containsText(userPrompt, "AuthorizationEffect: ALLOW"))),
                        authorizationEffectMatches,
                        "analysis.events.metadata.authorizationEffect -> promptAuditOutbox.payload.userPrompt"
                ),
                check(
                        "demoPhase matches event metadata",
                        value(responseDemoPhase),
                        pair(responseDemoPhase, eventDemoPhase),
                        demoPhaseMatches,
                        "invocation.demoPhase -> analysis.events.metadata.demoPhase"
                )
        );
    }

    private CcsrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new CcsrCheckResult(label, value(expected), value(actual), pass, source);
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
        facts.put("eventCount", String.valueOf(events.size()));
        facts.put("firstEvent", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("lastEvent", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("decisionEventPresent", events.stream().anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type())) ? "yes" : "no");
        return facts;
    }

    private Map<String, String> buildPromptFacts(Map<String, Object> decisionPayload, Map<String, Object> promptPayload) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptKey", value(text(decisionPayload, "promptKey")));
        facts.put("templateKey", value(text(decisionPayload, "promptTemplateKey")));
        facts.put("promptHash", value(text(decisionPayload, "promptHash")));
        facts.put("systemPromptHash", value(text(decisionPayload, "systemPromptHash")));
        facts.put("userPromptHash", value(text(decisionPayload, "userPromptHash")));
        facts.put("retrievalPurpose", value(text(promptPayload, "retrievalPurpose")));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(Map<String, Object> decisionPayload, SecurityDecisionForwardingOutboxRecord decisionOutbox) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(text(decisionPayload, "decision")));
        facts.put("riskScore", value(text(decisionPayload, "llmAuditRiskScore")));
        facts.put("confidence", value(text(decisionPayload, "effectiveConfidence")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        return facts;
    }

    private List<CcsrEventItem> buildEventItems(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream()
                .map(this::toCcsrEventItem)
                .toList();
    }

    private CcsrEventItem toCcsrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new CcsrEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    private Map<String, String> buildCcsrEventFacts(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        Map<String, Object> eventMetadata = primaryEventMetadata(events);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("eventCount", String.valueOf(events.size()));
        facts.put("firstEvent", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("lastEvent", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("requestPath", value(text(eventMetadata, "requestPath", "requestUri", "servletPath")));
        facts.put("clientIp", value(text(eventMetadata, "clientIp")));
        facts.put("mfaVerified", value(text(eventMetadata, "mfaVerified")));
        facts.put("resourceSensitivity", value(text(eventMetadata, "resourceSensitivity")));
        facts.put("authorizationEffect", value(text(eventMetadata, "authorizationEffect")));
        facts.put("demoPhase", value(text(eventMetadata, "demoPhase")));
        return facts;
    }

    private Map<String, String> buildCcsrPromptFacts(Map<String, Object> decisionPayload, Map<String, Object> promptPayload) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptKey", value(text(promptPayload, "promptKey")));
        facts.put("templateKey", value(text(promptPayload, "templateKey", "promptTemplateKey")));
        facts.put("promptVersion", value(text(promptPayload, "promptVersion")));
        facts.put("promptHash", value(text(promptPayload, "promptHash")));
        facts.put("systemPromptHash", value(text(promptPayload, "systemPromptHash")));
        facts.put("userPromptHash", value(text(promptPayload, "userPromptHash")));
        facts.put("systemPromptPresent", StringUtils.hasText(text(promptPayload, "systemPrompt")) ? "true" : "absent");
        facts.put("userPromptPresent", StringUtils.hasText(text(promptPayload, "userPrompt")) ? "true" : "absent");
        facts.put("promptCorrelationId", value(text(promptPayload, "correlationId")));
        return facts;
    }

    private Map<String, String> buildCcsrAnalysisFacts(
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> decisionAttributes
    ) {
        Map<String, Object> requestPathSource = firstPresent(sessionMetadata, behaviorMetadata, decisionAttributes);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(text(decisionPayload, "decision")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        facts.put("decisionCorrelationId", value(text(decisionPayload, "correlationId")));
        facts.put("resourceId", value(text(decisionAttributes, "resourceId", "protectedResourceId")));
        facts.put("userId", value(text(decisionAttributes, "userId", "subjectId", "actorId")));
        facts.put("requestPathSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                requestPathSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[SESSION_CONTEXT_LOADED].metadata", sessionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[BEHAVIOR_ANALYSIS_COMPLETE].metadata", behaviorMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        facts.put("requestPath", value(text(requestPathSource, "requestPath")));
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

    private Map<String, Object> buildCcsrRawEvidence(
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
        Map<String, Object> requestPathSource = firstPresent(sessionMetadata, behaviorMetadata, decisionAttributes);
        mutable.put("sessionMetadata", sessionMetadata);
        mutable.put("behaviorMetadata", behaviorMetadata);
        mutable.put("decisionMetadata", decisionMetadata);
        mutable.put("decisionAttributes", decisionAttributes);
        mutable.put("decisionMetadataPrimaryPresent", !decisionMetadata.isEmpty());
        mutable.put("decisionPayloadPrimaryPresent", !decisionPayload.isEmpty());
        mutable.put("promptAuditPrimaryPresent", !promptPayload.isEmpty());
        mutable.put("decisionAttributesPrimaryPresent", !decisionAttributes.isEmpty());
        mutable.put("requestPathSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                requestPathSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[SESSION_CONTEXT_LOADED].metadata", sessionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[BEHAVIOR_ANALYSIS_COMPLETE].metadata", behaviorMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        return Map.copyOf(mutable);
    }

    private Map<String, Object> primaryEventMetadata(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        if (events == null || events.isEmpty()) {
            return Map.of();
        }
        for (OfficialVerificationAnalysisEventStore.AnalysisEvent event : events) {
            if (event != null && event.metadata() != null && !event.metadata().isEmpty()) {
                return new LinkedHashMap<>(event.metadata());
            }
        }
        return Map.of();
    }

    private boolean containsText(String source, String fragment) {
        return StringUtils.hasText(source) && StringUtils.hasText(fragment) && source.contains(fragment);
    }

    private String boolText(boolean value) {
        return value ? "true" : "false";
    }

    private boolean sameNullableValue(String left, String right) {
        if (!StringUtils.hasText(left) && !StringUtils.hasText(right)) {
            return true;
        }
        return StringUtils.hasText(left) && left.equals(right);
    }

    private String expectedSensitivity(String requestPath) {
        if (!StringUtils.hasText(requestPath)) {
            return "NORMAL";
        }
        String normalized = requestPath.toLowerCase(Locale.ROOT);
        if (normalized.contains("critical")) {
            return "CRITICAL";
        }
        if (normalized.contains("sensitive") || normalized.contains("delegated")) {
            return "HIGH";
        }
        return "NORMAL";
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

    private boolean relatedDocumentsEvidenceCaptured(Map<String, Object> promptPayload) {
        return containsValue(promptPayload, "allowedDocumentCount", "requestedDocumentCount")
                || promptPayload.containsKey("contexts");
    }

    private String relatedDocumentsEvidenceLabel(Map<String, Object> promptPayload) {
        if (promptPayload.containsKey("contexts")) {
            return "contexts";
        }
        if (containsValue(promptPayload, "allowedDocumentCount")) {
            return "allowedDocumentCount";
        }
        if (containsValue(promptPayload, "requestedDocumentCount")) {
            return "requestedDocumentCount";
        }
        return null;
    }

    private Map<String, Object> extractPromptPayload(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
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

    private boolean sameValue(String left, String right) {
        return StringUtils.hasText(left) && left.equals(right);
    }

    private String pair(String left, String right) {
        return value(left) + " | " + value(right);
    }

    private String buildMessage(double score) {
        if (score < 95.0d) {
            return "CCSR consistency mismatches are still present in the enterprise evidence path.";
        }
        return "CCSR confirms that request, event, prompt, and decision facts stay aligned across the enterprise evidence path.";
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }
    private String normalizeResourceId(String resourceId) {
        String normalized = StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001";
        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "-");
        return normalized.isBlank() ? "resource-001" : normalized;
    }

    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record CcsrRunSummary(
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

    public record CcsrRunRecord(
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
            List<CcsrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<CcsrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<CcsrCheckResult, CcsrEventItem> {

        public CcsrRunSummary toSummary() {
            return new CcsrRunSummary(
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

    public record CcsrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record CcsrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}








