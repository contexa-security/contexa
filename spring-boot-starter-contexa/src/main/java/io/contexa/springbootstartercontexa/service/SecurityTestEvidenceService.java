package io.contexa.springbootstartercontexa.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.contexacore.autonomous.saas.SaasBaselineSeedService;
import io.contexa.contexacore.autonomous.saas.SaasThreatIntelligenceService;
import io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgePackService;
import io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgeRuntimePolicyService;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgePackSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgeRuntimePolicySnapshot;
import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEvent;
import io.contexa.springbootstartercontexa.event.LlmAnalysisEventPublisher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityTestEvidenceService {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() { };
    private static final int DEFAULT_CONTEXT_SAMPLE_SIZE = 16;

    private final ZeroTrustActionRepository actionRepository;
    private final LlmAnalysisEventPublisher llmAnalysisEventPublisher;
    private final ObjectMapper objectMapper;
    private final ObjectProvider<SecurityDecisionForwardingOutboxRepository> securityDecisionOutboxRepositoryProvider;
    private final ObjectProvider<PromptContextAuditForwardingOutboxRepository> promptContextAuditForwardingOutboxRepositoryProvider;
    private final ObjectProvider<SecurityContextDataStore> securityContextDataStoreProvider;
    private final ObjectProvider<HCADDataStore> hcadDataStoreProvider;
    private final ObjectProvider<SaasBaselineSeedService> saasBaselineSeedServiceProvider;
    private final ObjectProvider<SaasThreatIntelligenceService> saasThreatIntelligenceServiceProvider;
    private final ObjectProvider<SaasThreatKnowledgePackService> saasThreatKnowledgePackServiceProvider;
    private final ObjectProvider<SaasThreatKnowledgeRuntimePolicyService> saasThreatKnowledgeRuntimePolicyServiceProvider;

    private final ConcurrentMap<String, RequestTrace> tracesByRequestId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> latestRequestByUser = new ConcurrentHashMap<>();

    public RequestRegistration registerRequest(
            HttpServletRequest request,
            String userId,
            String endpointKey,
            String resourceId,
            String analysisRequirement) {

        String requestId = firstNonBlank(request.getHeader("X-Request-ID"), UUID.randomUUID().toString());
        String correlationId = requestId;
        String scenario = trimToNull(request.getHeader("X-Contexa-Scenario"));
        String expectedAction = trimToNull(request.getHeader("X-Contexa-Expected-Action"));
        String demoRunId = trimToNull(request.getHeader("X-Contexa-Demo-Run-Id"));
        String demoPhase = trimToNull(request.getHeader("X-Contexa-Demo-Phase"));
        String clientIp = resolveClientIp(request);
        String userAgent = firstNonBlank(request.getHeader("X-Simulated-User-Agent"), request.getHeader("User-Agent"), "unknown");
        String sessionId = request.getSession(false) != null ? request.getSession(false).getId() : request.getRequestedSessionId();
        String requestPath = request.getRequestURI();
        String servletPath = request.getServletPath();
        String method = request.getMethod();
        String queryString = request.getQueryString();
        String authMode = trimToNull(request.getHeader("X-Contexa-Auth-Mode"));
        String tokenSource = trimToNull(request.getHeader("X-Contexa-Token-Source"));
        String authCarrier = trimToNull(request.getHeader("X-Contexa-Auth-Carrier"));
        String authSubjectHint = trimToNull(request.getHeader("X-Contexa-Auth-Subject"));
        boolean authorizationHeaderPresent = StringUtils.hasText(request.getHeader("Authorization"));

        RequestTrace trace = RequestTrace.builder()
                .requestId(requestId)
                .correlationId(correlationId)
                .userId(userId)
                .scenario(scenario)
                .expectedAction(expectedAction)
                .demoRunId(demoRunId)
                .demoPhase(demoPhase)
                .endpointKey(endpointKey)
                .analysisRequirement(analysisRequirement)
                .resourceId(resourceId)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .sessionId(sessionId)
                .method(method)
                .requestPath(requestPath)
                .servletPath(servletPath)
                .queryString(queryString)
                .authMode(authMode)
                .tokenSource(tokenSource)
                .authCarrier(authCarrier)
                .authSubjectHint(authSubjectHint)
                .authorizationHeaderPresent(authorizationHeaderPresent)
                .createdAt(Instant.now().toString())
                .build();

        tracesByRequestId.put(requestId, trace);
        if (StringUtils.hasText(userId)) {
            latestRequestByUser.put(userId, requestId);
        }

        return new RequestRegistration(
                requestId,
                correlationId,
                scenario,
                expectedAction,
                demoRunId,
                demoPhase,
                clientIp,
                userAgent,
                sessionId,
                requestPath,
                servletPath,
                analysisRequirement,
                authMode,
                tokenSource,
                authCarrier,
                authSubjectHint,
                authorizationHeaderPresent);
    }

    public void recordResponse(String requestId, int statusCode, boolean success, Map<String, Object> responseBody, long processingTimeMs) {
        RequestTrace trace = tracesByRequestId.get(requestId);
        if (trace == null) {
            return;
        }
        trace.setResponse(new ResponseTrace(
                statusCode,
                success,
                processingTimeMs,
                Instant.now().toString(),
                copyNullableMap(responseBody)));
    }

    public Map<String, Object> getCurrentEvidence(String userId) {
        String requestId = latestRequestByUser.get(userId);
        return buildEvidence(userId, requestId);
    }

    public Map<String, Object> getEvidence(String userId, String requestId) {
        return buildEvidence(userId, requestId);
    }

    public Map<String, Object> exportEvidence(String userId, String requestId) {
        Map<String, Object> evidence = new LinkedHashMap<>(buildEvidence(userId, requestId));
        evidence.put("exportedAt", Instant.now().toString());
        evidence.put("contentType", MediaType.APPLICATION_JSON_VALUE);
        return evidence;
    }

    public StreamingResponseBody streamEvidence(String userId, String requestId) {
        return outputStream -> {
            for (int index = 0; index < 12; index++) {
                Map<String, Object> snapshot = buildEvidence(userId, requestId);
                snapshot.put("streamIndex", index + 1);
                outputStream.write((writeJson(snapshot) + "\n").getBytes(StandardCharsets.UTF_8));
                outputStream.flush();

                Map<String, Object> consistency = castMap(snapshot.get("consistency"));
                boolean analysisLinked = Boolean.TRUE.equals(consistency.get("analysisRequestLinked"));
                boolean sseLinked = Boolean.TRUE.equals(consistency.get("sseLinked"));
                boolean decisionOutboxLinked = Boolean.TRUE.equals(consistency.get("decisionOutboxLinked"));
                boolean promptAuditLinked = Boolean.TRUE.equals(consistency.get("promptAuditLinked"));
                boolean responseCaptured = Boolean.TRUE.equals(consistency.get("responseCaptured"));

                if (responseCaptured && analysisLinked && sseLinked && (decisionOutboxLinked || promptAuditLinked)) {
                    break;
                }

                try {
                    Thread.sleep(750L);
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        };
    }

    private Map<String, Object> buildEvidence(String userId, String requestId) {
        RequestTrace trace = requestId != null ? tracesByRequestId.get(requestId) : null;
        String effectiveUserId = firstNonBlank(userId, trace != null ? trace.getUserId() : null);
        String effectiveRequestId = firstNonBlank(requestId, trace != null ? trace.getRequestId() : null);

        ZeroTrustAnalysisData analysisData = StringUtils.hasText(effectiveUserId)
                ? actionRepository.getAnalysisData(effectiveUserId)
                : ZeroTrustAnalysisData.pending();

        List<LlmAnalysisEvent> recentEvents = resolveRecentEvents(effectiveUserId, effectiveRequestId);
        SecurityDecisionForwardingOutboxRecord decisionOutbox = resolveDecisionOutbox(effectiveRequestId);
        PromptContextAuditForwardingOutboxRecord promptAuditOutbox = resolvePromptAuditOutbox(effectiveRequestId);

        Map<String, Object> requestSection = trace != null ? trace.toMap() : Map.of();
        Map<String, Object> responseSection = trace != null && trace.getResponse() != null ? trace.getResponse().toMap() : Map.of();
        Map<String, Object> analysisSection = toAnalysisMap(analysisData);
        Map<String, Object> sseSection = Map.of(
                "eventCount", recentEvents.size(),
                "events", recentEvents.stream().map(this::toEventMap).toList()
        );
        Map<String, Object> contextSection = buildContextSection(trace, effectiveUserId, analysisData);
        Map<String, Object> saasSection = buildSaasSection(decisionOutbox, promptAuditOutbox);
        Map<String, Object> consistencySection = buildConsistencySection(
                effectiveRequestId,
                trace,
                analysisData,
                recentEvents,
                decisionOutbox,
                promptAuditOutbox);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requestId", effectiveRequestId);
        result.put("userId", effectiveUserId);
        result.put("request", requestSection);
        result.put("response", responseSection);
        result.put("analysis", analysisSection);
        result.put("sse", sseSection);
        result.put("context", contextSection);
        result.put("saas", saasSection);
        result.put("consistency", consistencySection);
        result.put("generatedAt", Instant.now().toString());
        return result;
    }

    private List<LlmAnalysisEvent> resolveRecentEvents(String userId, String requestId) {
        if (!StringUtils.hasText(userId)) {
            return List.of();
        }
        return llmAnalysisEventPublisher.getRecentEvents(userId).stream()
                .filter(event -> !StringUtils.hasText(requestId)
                        || requestId.equals(event.getRequestId())
                        || requestId.equals(event.getCorrelationId()))
                .toList();
    }

    private SecurityDecisionForwardingOutboxRecord resolveDecisionOutbox(String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return null;
        }
        SecurityDecisionForwardingOutboxRepository repository =
                securityDecisionOutboxRepositoryProvider.getIfAvailable();
        if (repository == null) {
            return null;
        }
        return repository.findByCorrelationId(requestId).orElse(null);
    }

    private PromptContextAuditForwardingOutboxRecord resolvePromptAuditOutbox(String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return null;
        }
        PromptContextAuditForwardingOutboxRepository repository =
                promptContextAuditForwardingOutboxRepositoryProvider.getIfAvailable();
        if (repository == null) {
            return null;
        }
        return repository.findByCorrelationId(requestId).orElse(null);
    }

    private Map<String, Object> buildContextSection(RequestTrace trace, String userId, ZeroTrustAnalysisData analysisData) {
        Map<String, Object> context = new LinkedHashMap<>();
        SecurityContextDataStore securityContextDataStore = securityContextDataStoreProvider.getIfAvailable();
        HCADDataStore hcadDataStore = hcadDataStoreProvider.getIfAvailable();

        if (trace != null) {
            context.put("scenario", trace.getScenario());
            context.put("expectedAction", trace.getExpectedAction());
            context.put("clientIp", trace.getClientIp());
            context.put("userAgent", trace.getUserAgent());
            context.put("sessionId", trace.getSessionId());
            context.put("analysisRequirement", trace.getAnalysisRequirement());
        }

        if (analysisData != null && StringUtils.hasText(analysisData.contextBindingHash())) {
            context.put("contextBindingHash", analysisData.contextBindingHash());
        }

        if (securityContextDataStore != null && trace != null && StringUtils.hasText(trace.getSessionId())) {
            String sessionId = trace.getSessionId();
            context.put("recentSessionActions", securityContextDataStore.getRecentSessionActions(sessionId, DEFAULT_CONTEXT_SAMPLE_SIZE));
            context.put("recentNarrativeActionFamilies",
                    securityContextDataStore.getRecentSessionNarrativeActionFamilies(sessionId, DEFAULT_CONTEXT_SAMPLE_SIZE));
            context.put("recentProtectableAccesses",
                    securityContextDataStore.getRecentSessionProtectableAccesses(sessionId, DEFAULT_CONTEXT_SAMPLE_SIZE));
            context.put("recentRequestIntervalsMs",
                    securityContextDataStore.getRecentSessionRequestIntervals(sessionId, DEFAULT_CONTEXT_SAMPLE_SIZE));
            context.put("sessionStartedAt", securityContextDataStore.getSessionStartedAt(sessionId));
            context.put("sessionLastRequestTime", securityContextDataStore.getSessionLastRequestTime(sessionId));
            context.put("sessionPreviousPath", securityContextDataStore.getSessionPreviousPath(sessionId));
        }

        if (securityContextDataStore != null && StringUtils.hasText(userId)) {
            context.put("lastRequestTime", securityContextDataStore.getLastRequestTime(userId));
            context.put("previousPath", securityContextDataStore.getPreviousPath(userId));
            context.put("authorizationScopeState",
                    securityContextDataStore.getAuthorizationScopeState("default", userId));
            context.put("workProfileObservations",
                    securityContextDataStore.getRecentWorkProfileObservations("default", userId, DEFAULT_CONTEXT_SAMPLE_SIZE));
            context.put("permissionChangeObservations",
                    securityContextDataStore.getRecentPermissionChangeObservations("default", userId, DEFAULT_CONTEXT_SAMPLE_SIZE));
        }

        if (hcadDataStore != null && trace != null && StringUtils.hasText(trace.getSessionId())) {
            context.put("hcadSessionMetadata", copyMap(hcadDataStore.getSessionMetadata(trace.getSessionId())));
        }
        if (hcadDataStore != null && StringUtils.hasText(userId)) {
            context.put("hcadAnalysis", copyMap(hcadDataStore.getHcadAnalysis(userId)));
        }

        return context;
    }

    private Map<String, Object> buildSaasSection(
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptAuditOutbox) {

        Map<String, Object> saas = new LinkedHashMap<>();
        saas.put("securityDecisionOutbox", toOutboxMap(decisionOutbox));
        saas.put("promptContextAuditOutbox", toOutboxMap(promptAuditOutbox));
        saas.put("pullSnapshots", buildPullSnapshotSection());
        return saas;
    }

    private Map<String, Object> buildPullSnapshotSection() {
        Map<String, Object> pullSnapshots = new LinkedHashMap<>();
        pullSnapshots.put("baselineSeed", summarizeBaselineSeed());
        pullSnapshots.put("threatIntelligence", summarizeThreatIntelligence());
        pullSnapshots.put("knowledgePack", summarizeKnowledgePack());
        pullSnapshots.put("runtimePolicy", summarizeRuntimePolicy());
        return pullSnapshots;
    }

    private Map<String, Object> buildConsistencySection(
            String requestId,
            RequestTrace trace,
            ZeroTrustAnalysisData analysisData,
            List<LlmAnalysisEvent> recentEvents,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptAuditOutbox) {

        boolean requestRegistered = trace != null;
        boolean responseCaptured = trace != null && trace.getResponse() != null;
        boolean analysisRequestLinked = StringUtils.hasText(requestId)
                && analysisData != null
                && requestId.equals(analysisData.requestId());
        boolean sseLinked = recentEvents.stream().anyMatch(event ->
                requestId != null && (requestId.equals(event.getRequestId()) || requestId.equals(event.getCorrelationId())));
        boolean decisionOutboxLinked = decisionOutbox != null
                && requestId != null
                && requestId.equals(decisionOutbox.getCorrelationId());
        boolean promptAuditLinked = promptAuditOutbox != null
                && requestId != null
                && requestId.equals(promptAuditOutbox.getCorrelationId());
        boolean contextBindingPresent = analysisData != null && StringUtils.hasText(analysisData.contextBindingHash());

        Map<String, Object> consistency = new LinkedHashMap<>();
        consistency.put("requestRegistered", requestRegistered);
        consistency.put("responseCaptured", responseCaptured);
        consistency.put("analysisRequestLinked", analysisRequestLinked);
        consistency.put("sseLinked", sseLinked);
        consistency.put("decisionOutboxLinked", decisionOutboxLinked);
        consistency.put("promptAuditLinked", promptAuditLinked);
        consistency.put("contextBindingPresent", contextBindingPresent);
        consistency.put("serverTruthReady",
                requestRegistered && responseCaptured && sseLinked && analysisRequestLinked);
        consistency.put("saasEvidenceReady", decisionOutboxLinked || promptAuditLinked);
        return consistency;
    }

    private Map<String, Object> toAnalysisMap(ZeroTrustAnalysisData data) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("action", data.action());
        map.put("riskScore", data.riskScore());
        map.put("confidence", data.confidence());
        map.put("threatEvidence", data.threatEvidence());
        map.put("analysisDepth", data.analysisDepth());
        map.put("updatedAt", data.updatedAt());
        map.put("reasoning", data.reasoning());
        map.put("reasoningSummary", data.reasoningSummary());
        map.put("analysisRequirement", data.analysisRequirement());
        map.put("requestId", data.requestId());
        map.put("contextBindingHash", data.contextBindingHash());
        map.put("llmProposedAction", data.llmProposedAction());
        return map;
    }

    private Map<String, Object> toEventMap(LlmAnalysisEvent event) {
        return objectMapper.convertValue(event, MAP_TYPE);
    }

    private Map<String, Object> toOutboxMap(SecurityDecisionForwardingOutboxRecord record) {
        if (record == null) {
            return Map.of("present", false);
        }
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("present", true);
        map.put("status", record.getStatus());
        map.put("attemptCount", record.getAttemptCount());
        map.put("lastError", record.getLastError());
        map.put("createdAt", record.getCreatedAt());
        map.put("updatedAt", record.getUpdatedAt());
        map.put("deliveredAt", record.getDeliveredAt());
        map.put("correlationId", record.getCorrelationId());
        map.put("tenantExternalRef", record.getTenantExternalRef());
        map.put("payload", parseJson(record.getPayloadJson()));
        map.put("payloadJson", record.getPayloadJson());
        return map;
    }

    private Map<String, Object> toOutboxMap(PromptContextAuditForwardingOutboxRecord record) {
        if (record == null) {
            return Map.of("present", false);
        }
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("present", true);
        map.put("status", record.getStatus());
        map.put("attemptCount", record.getAttemptCount());
        map.put("lastError", record.getLastError());
        map.put("createdAt", record.getCreatedAt());
        map.put("updatedAt", record.getUpdatedAt());
        map.put("deliveredAt", record.getDeliveredAt());
        map.put("auditId", record.getAuditId());
        map.put("correlationId", record.getCorrelationId());
        map.put("tenantExternalRef", record.getTenantExternalRef());
        map.put("payload", parseJson(record.getPayloadJson()));
        map.put("payloadJson", record.getPayloadJson());
        return map;
    }

    private Map<String, Object> parseJson(String payloadJson) {
        if (!StringUtils.hasText(payloadJson)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(payloadJson, MAP_TYPE);
        } catch (JsonProcessingException exception) {
            log.warn("[SecurityTestEvidenceService] Failed to parse payload JSON", exception);
            return Map.of("raw", payloadJson, "parseError", exception.getMessage());
        }
    }

    private Map<String, Object> copyMap(Map<Object, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        source.forEach((key, value) -> copy.put(String.valueOf(key), value));
        return copy;
    }

    private Map<String, Object> copyNullableMap(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> copy = new LinkedHashMap<>();
        source.forEach(copy::put);
        return copy;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> castMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            map.forEach((key, entryValue) -> copy.put(String.valueOf(key), entryValue));
            return copy;
        }
        return Map.of();
    }

    private String writeJson(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Failed to serialize evidence snapshot", exception);
        }
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwardedFor)) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String trimToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private Map<String, Object> summarizeBaselineSeed() {
        SaasBaselineSeedService service = saasBaselineSeedServiceProvider.getIfAvailable();
        if (service == null) {
            return Map.of("present", false);
        }
        BaselineSeedSnapshot snapshot = service.getPromptSeed();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("present", true);
        summary.put("enabled", service.isEnabled());
        summary.put("seedAvailable", snapshot.seedAvailable());
        summary.put("cohortLabel", snapshot.cohortLabel());
        summary.put("industryCategory", snapshot.industryCategory());
        summary.put("region", snapshot.region());
        summary.put("cohortTenantCount", snapshot.cohortTenantCount());
        summary.put("sampleUserBaselineCount", snapshot.sampleUserBaselineCount());
        summary.put("topAccessHours", snapshot.topAccessHours());
        summary.put("topOperatingSystems", snapshot.topOperatingSystems());
        summary.put("snapshotDate", snapshot.snapshotDate());
        summary.put("generatedAt", snapshot.generatedAt());
        return summary;
    }

    private Map<String, Object> summarizeThreatIntelligence() {
        SaasThreatIntelligenceService service = saasThreatIntelligenceServiceProvider.getIfAvailable();
        if (service == null) {
            return Map.of("present", false);
        }
        List<ThreatIntelligenceSnapshot.ThreatSignalItem> signals = service.getPromptSignals();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("present", true);
        summary.put("enabled", service.isEnabled());
        summary.put("signalCount", signals.size());
        summary.put("topSignals", signals.stream()
                .limit(5)
                .map(signal -> Map.of(
                        "signalKey", signal.signalKey(),
                        "canonicalThreatClass", signal.canonicalThreatClass(),
                        "summary", signal.summary(),
                        "observationCount", signal.observationCount(),
                        "affectedTenantCount", signal.affectedTenantCount()))
                .toList());
        return summary;
    }

    private Map<String, Object> summarizeKnowledgePack() {
        SaasThreatKnowledgePackService service = saasThreatKnowledgePackServiceProvider.getIfAvailable();
        if (service == null) {
            return Map.of("present", false);
        }
        ThreatKnowledgePackSnapshot snapshot = service.currentSnapshot();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("present", true);
        summary.put("enabled", service.isEnabled());
        summary.put("runtimeReady", snapshot.runtimeReady());
        summary.put("promotionState", snapshot.promotionState());
        summary.put("promotedCaseCount", snapshot.promotedCaseCount());
        summary.put("conditionalCaseCount", snapshot.conditionalCaseCount());
        summary.put("restrictedCaseCount", snapshot.restrictedCaseCount());
        summary.put("topCases", snapshot.cases().stream()
                .limit(5)
                .map(item -> Map.of(
                        "signalKey", item.signalKey(),
                        "knowledgeKey", item.knowledgeKey(),
                        "canonicalThreatClass", item.canonicalThreatClass(),
                        "xaiSummary", item.xaiSummary(),
                        "promotionState", item.promotionState()))
                .toList());
        summary.put("generatedAt", snapshot.generatedAt());
        return summary;
    }

    private Map<String, Object> summarizeRuntimePolicy() {
        SaasThreatKnowledgeRuntimePolicyService service = saasThreatKnowledgeRuntimePolicyServiceProvider.getIfAvailable();
        if (service == null) {
            return Map.of("present", false);
        }
        ThreatKnowledgeRuntimePolicySnapshot snapshot = service.currentSnapshot();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("present", true);
        summary.put("enabled", service.isEnabled());
        summary.put("runtimeAllowed", service.isRuntimeAllowed());
        summary.put("killSwitchActive", snapshot.killSwitchActive());
        summary.put("policyState", snapshot.policyState());
        summary.put("approvedArtifactCount", snapshot.approvedArtifactCount());
        summary.put("withdrawnArtifactCount", snapshot.withdrawnArtifactCount());
        summary.put("reviewOnlyArtifactCount", snapshot.reviewOnlyArtifactCount());
        summary.put("topArtifacts", snapshot.artifacts().stream()
                .limit(5)
                .map(item -> Map.of(
                        "signalKey", item.signalKey(),
                        "knowledgeKey", item.knowledgeKey(),
                        "artifactVersion", item.artifactVersion(),
                        "governanceState", item.governanceState(),
                        "deploymentAction", item.deploymentAction(),
                        "runtimeApproved", item.runtimeApproved()))
                .toList());
        summary.put("generatedAt", snapshot.generatedAt());
        return summary;
    }

    @Getter
    public static final class RequestRegistration {
        private final String requestId;
        private final String correlationId;
        private final String scenario;
        private final String expectedAction;
        private final String demoRunId;
        private final String demoPhase;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String requestPath;
        private final String servletPath;
        private final String analysisRequirement;
        private final String authMode;
        private final String tokenSource;
        private final String authCarrier;
        private final String authSubjectHint;
        private final boolean authorizationHeaderPresent;

        public RequestRegistration(
                String requestId,
                String correlationId,
                String scenario,
                String expectedAction,
                String demoRunId,
                String demoPhase,
                String clientIp,
                String userAgent,
                String sessionId,
                String requestPath,
                String servletPath,
                String analysisRequirement,
                String authMode,
                String tokenSource,
                String authCarrier,
                String authSubjectHint,
                boolean authorizationHeaderPresent) {
            this.requestId = requestId;
            this.correlationId = correlationId;
            this.scenario = scenario;
            this.expectedAction = expectedAction;
            this.demoRunId = demoRunId;
            this.demoPhase = demoPhase;
            this.clientIp = clientIp;
            this.userAgent = userAgent;
            this.sessionId = sessionId;
            this.requestPath = requestPath;
            this.servletPath = servletPath;
            this.analysisRequirement = analysisRequirement;
            this.authMode = authMode;
            this.tokenSource = tokenSource;
            this.authCarrier = authCarrier;
            this.authSubjectHint = authSubjectHint;
            this.authorizationHeaderPresent = authorizationHeaderPresent;
        }
    }

    @Getter
    @Setter
    @Builder
    private static final class RequestTrace {
        private final String requestId;
        private final String correlationId;
        private final String userId;
        private final String scenario;
        private final String expectedAction;
        private final String demoRunId;
        private final String demoPhase;
        private final String endpointKey;
        private final String analysisRequirement;
        private final String resourceId;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String method;
        private final String requestPath;
        private final String servletPath;
        private final String queryString;
        private final String authMode;
        private final String tokenSource;
        private final String authCarrier;
        private final String authSubjectHint;
        private final boolean authorizationHeaderPresent;
        private final String createdAt;

        private volatile ResponseTrace response;

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("requestId", requestId);
            map.put("correlationId", correlationId);
            map.put("userId", userId);
            map.put("scenario", scenario);
            map.put("expectedAction", expectedAction);
            map.put("demoRunId", demoRunId);
            map.put("demoPhase", demoPhase);
            map.put("endpointKey", endpointKey);
            map.put("analysisRequirement", analysisRequirement);
            map.put("resourceId", resourceId);
            map.put("clientIp", clientIp);
            map.put("userAgent", userAgent);
            map.put("sessionId", sessionId);
            map.put("method", method);
            map.put("requestPath", requestPath);
            map.put("servletPath", servletPath);
            map.put("queryString", queryString);
            map.put("authMode", authMode);
            map.put("tokenSource", tokenSource);
            map.put("authCarrier", authCarrier);
            map.put("authSubjectHint", authSubjectHint);
            map.put("authorizationHeaderPresent", authorizationHeaderPresent);
            map.put("createdAt", createdAt);
            return map;
        }
    }

    private record ResponseTrace(
            int statusCode,
            boolean success,
            long processingTimeMs,
            String completedAt,
            Map<String, Object> body
    ) {
        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("statusCode", statusCode);
            map.put("success", success);
            map.put("processingTimeMs", processingTimeMs);
            map.put("completedAt", completedAt);
            map.put("body", body);
            return map;
        }
    }
}
