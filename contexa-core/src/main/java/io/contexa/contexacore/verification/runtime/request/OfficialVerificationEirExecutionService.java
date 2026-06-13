package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationEirExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationEirExecutionService.EirRunRecord, OfficialVerificationEirExecutionService.EndpointDefinition> implements OfficialVerificationEirExecutor {

    private static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "EIR",
                    OfficialVerificationEirExecutionService.class.getName(),
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
    private static final String DELEGATED_HEADER = "X-Contexa-Delegated";
    private static final String AGENT_ID_HEADER = "X-Contexa-Agent-Id";
    private static final String OBJECTIVE_ID_HEADER = "X-Contexa-Objective-Id";
    private static final String OBJECTIVE_FAMILY_HEADER = "X-Contexa-Objective-Family";
    private static final String OBJECTIVE_SUMMARY_HEADER = "X-Contexa-Objective-Summary";
    private static final String ALLOWED_OPERATIONS_HEADER = "X-Contexa-Allowed-Operations";
    private static final String ALLOWED_RESOURCES_HEADER = "X-Contexa-Allowed-Resources";
    private static final String APPROVAL_REQUIRED_HEADER = "X-Contexa-Approval-Required";
    private static final String PRIVILEGED_EXPORT_ALLOWED_HEADER = "X-Contexa-Privileged-Export-Allowed";
    private static final String CONTAINMENT_ONLY_HEADER = "X-Contexa-Containment-Only";
    private static final String DELEGATION_EXPIRES_AT_HEADER = "X-Contexa-Delegation-Expires-At";
    private static final String OFFICIAL_VERIFICATION_AGENT_ID = "official-verification-agent";
    private static final String OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY = "OFFICIAL_VERIFICATION";
    private static final String OFFICIAL_VERIFICATION_DELEGATION_EXPIRES_AT = "2026-04-05T00:00:00Z";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String DEVICE_ID_HEADER = "X-Device-Id";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String EIR_CLIENT_IP = "192.168.1.100";
    private static final String EIR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String EIR_USER_AGENT_LABEL = "Chrome 120 / Windows 11";
    private static final String EIR_DEVICE_ID = "official-verification-eir-admin-browser";

    public OfficialVerificationEirExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper
    ) {
        super("EIR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, webClientBuilder, objectMapper, EirRunRecord::runId, EirRunRecord::startedAt);
    }

    @Override
    public synchronized EirRunRecord executeRun(
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
        return "enterprise-eir-";
    }

    @Override
    protected EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.resolveProbeTarget(endpointKey, resourceId, requestPath, List.of("normal", "delegated", "sensitive", "critical"));
        return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
            case "delegated" -> "Delegated Resource";
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        }, replayTarget.requestPath(), replayTarget.resourceId());
    }
    @Override
    protected EirRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
        List<EirCheckResult> checks = buildChecks(
                state.requestId(),
                state.endpoint(),
                state.invocation(),
                state.artifacts().events(),
                state.contaminationSeed(),
                state.baselineSeedRequested()
        );
        int passedChecks = (int) checks.stream().filter(EirCheckResult::pass).count();
        int totalChecks = checks.size();
        double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
        return new EirRunRecord(
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
                score >= 95.0d
                        ? "Request, event, and decision fields stayed aligned through the final decision."
                        : "One or more request, event, or decision fields were missing or diverged during execution.",
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
                buildEventFacts(state.artifacts().events()),
                buildPromptFacts(state.artifacts().decisionPayload(), state.artifacts().promptPayload()),
                buildAnalysisFacts(state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), state.artifacts().events()),
                state.artifacts().events().stream().map(this::toEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildRawEvidence(
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
                        endpoint,
                        requestedRunCount,
                        contaminationSeed,
                        baselineSeedRequested
                ))
                .retrieve()
                .bodyToMono(MAP_TYPE)
                .block(Duration.ofSeconds(30));
        return payload != null ? payload : Map.of();
    }

    private void forwardHeaders(
            HttpHeaders headers,
            HttpServletRequest request,
            String requestId,
            String userId,
            EndpointDefinition endpoint,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set(HttpHeaders.USER_AGENT, EIR_BROWSER_USER_AGENT);
        headers.set(FORWARDED_FOR_HEADER, EIR_CLIENT_IP);
        headers.set(DEVICE_ID_HEADER, EIR_DEVICE_ID);
        headers.set(SIMULATED_USER_AGENT_HEADER, EIR_BROWSER_USER_AGENT);
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, EIR_USER_AGENT_LABEL);
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, endpoint != null && StringUtils.hasText(endpoint.resourceId()) ? endpoint.resourceId().trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId));
        applyDelegationHeaders(headers, endpoint);
        if (request == null) {
            return;
        }
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }

    private void applyDelegationHeaders(HttpHeaders headers, EndpointDefinition endpoint) {
        if (endpoint == null || !sameValue("delegated", endpoint.key())) {
            return;
        }
        headers.set(DELEGATED_HEADER, "true");
        headers.set(AGENT_ID_HEADER, OFFICIAL_VERIFICATION_AGENT_ID);
        headers.set(OBJECTIVE_ID_HEADER, "official-verification-delegated-" + endpoint.resourceId());
        headers.set(OBJECTIVE_FAMILY_HEADER, OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY);
        headers.set(OBJECTIVE_SUMMARY_HEADER, "Validate delegated execution lineage for the official enterprise verification probe.");
        headers.set(ALLOWED_OPERATIONS_HEADER, "READ,VERIFY");
        headers.set(ALLOWED_RESOURCES_HEADER, endpoint.resourceId());
        headers.set(APPROVAL_REQUIRED_HEADER, "true");
        headers.set(PRIVILEGED_EXPORT_ALLOWED_HEADER, "false");
        headers.set(CONTAINMENT_ONLY_HEADER, "true");
        headers.set(DELEGATION_EXPIRES_AT_HEADER, OFFICIAL_VERIFICATION_DELEGATION_EXPIRES_AT);
    }
    private List<EirCheckResult> buildChecks(
            String requestId,
            EndpointDefinition endpoint,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        String responseRequestId = text(invocation, "requestId");
        OfficialVerificationAnalysisEventStore.AnalysisEvent firstEvent = events.isEmpty() ? null : events.get(0);
        Map<String, Object> eventMetadata = primaryEventMetadata(events);
        String invocationRequestPath = text(invocation, "requestPath");
        String expectedSensitivity = endpoint.key().equalsIgnoreCase("critical")
                ? "CRITICAL"
                : endpoint.key().equalsIgnoreCase("sensitive") ? "HIGH" : "STANDARD";
        String expectedSensitiveResource = String.valueOf(!endpoint.key().equalsIgnoreCase("normal"));
        List<EirCheckResult> checks = new ArrayList<>(List.of(
                check("response requestId is preserved", requestId, responseRequestId, requestId.equals(responseRequestId), "probe.response.requestId"),
                check("selected resourceId is preserved", endpoint.resourceId(), text(invocation, "requestedResourceId"), endpoint.resourceId().equals(text(invocation, "requestedResourceId")), "probe.response.requestedResourceId"),
                check("contamination seed request is preserved", String.valueOf(contaminationSeed), text(invocation, "contaminationSeed"), String.valueOf(contaminationSeed).equalsIgnoreCase(text(invocation, "contaminationSeed")), "probe.response.contaminationSeed"),
                check("baseline seed request is preserved", String.valueOf(baselineSeedRequested), text(invocation, "baselineSeedRequested"), String.valueOf(baselineSeedRequested).equalsIgnoreCase(text(invocation, "baselineSeedRequested")), "probe.response.baselineSeedRequested"),
                check("client IP is preserved", EIR_CLIENT_IP, text(eventMetadata, "clientIp"), sameValue(EIR_CLIENT_IP, text(eventMetadata, "clientIp")), "analysis.events.metadata.clientIp"),
                check("first event requestId matches", requestId, firstEvent != null ? firstEvent.requestId() : null, firstEvent != null && requestId.equals(firstEvent.requestId()), "analysis.events[0].requestId"),
                check("event requestId matches", requestId, text(eventMetadata, "requestId"), requestId.equals(text(eventMetadata, "requestId")), "analysis.events.metadata.requestId"),
                check("request path is preserved", invocationRequestPath, text(eventMetadata, "requestPath", "requestUri"), sameValue(invocationRequestPath, text(eventMetadata, "requestPath", "requestUri")), "analysis.events.metadata.requestPath"),
                check("MFA verification is preserved", "true", text(eventMetadata, "mfaVerified"), sameValue("true", text(eventMetadata, "mfaVerified")), "analysis.events.metadata.mfaVerified"),
                check("resource sensitivity is preserved", expectedSensitivity, text(eventMetadata, "resourceSensitivity"), sameValue(expectedSensitivity, text(eventMetadata, "resourceSensitivity")), "analysis.events.metadata.resourceSensitivity"),
                check("sensitive resource flag is preserved", expectedSensitiveResource, text(eventMetadata, "isSensitiveResource"), sameValue(expectedSensitiveResource, text(eventMetadata, "isSensitiveResource")), "analysis.events.metadata.isSensitiveResource"),
                check("authentication method is preserved", "present", text(eventMetadata, "authMethod"), StringUtils.hasText(text(eventMetadata, "authMethod")), "analysis.events.metadata.authMethod"),
                check("authorization effect is preserved", "ALLOW", text(eventMetadata, "authorizationEffect"), StringUtils.hasText(text(eventMetadata, "authorizationEffect")) && !"UNKNOWN".equalsIgnoreCase(text(eventMetadata, "authorizationEffect")), "analysis.events.metadata.authorizationEffect"),
                check("effective roles are preserved", "1+", joinList(eventMetadata.get("effectiveRoles")), eventMetadata.containsKey("effectiveRoles") && StringUtils.hasText(joinList(eventMetadata.get("effectiveRoles"))), "analysis.events.metadata.effectiveRoles"),
                check("effective permissions are preserved", "1+", joinList(eventMetadata.get("effectivePermissions")), eventMetadata.containsKey("effectivePermissions") && StringUtils.hasText(joinList(eventMetadata.get("effectivePermissions"))), "analysis.events.metadata.effectivePermissions")
        ));
        if (sameValue("delegated", endpoint.key())) {
            checks.add(check("probe response reports delegated execution", "true", text(invocation, "bridgeDelegated"), sameValue("true", text(invocation, "bridgeDelegated")), "probe.response.bridgeDelegated"));
            checks.add(check("probe response preserves delegation objective family", OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY, text(invocation, "bridgeObjectiveFamily"), sameValue(OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY, text(invocation, "bridgeObjectiveFamily")), "probe.response.bridgeObjectiveFamily"));
            checks.add(check("probe response reached delegated bridge coverage", "DELEGATION_CONTEXT", text(invocation, "bridgeCoverageLevel"), sameValue("DELEGATION_CONTEXT", text(invocation, "bridgeCoverageLevel")), "probe.response.bridgeCoverageLevel"));
            checks.add(check("probe response bridge coverage score is elevated", "90+", text(invocation, "bridgeCoverageScore"), atLeastInt(text(invocation, "bridgeCoverageScore"), 90), "probe.response.bridgeCoverageScore"));
            checks.add(check("event metadata carries delegated execution flag", "true", text(eventMetadata, "delegated"), sameValue("true", text(eventMetadata, "delegated")), "analysis.events.metadata.delegated"));
            checks.add(check("event metadata preserves delegation objective family", OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY, text(eventMetadata, "objectiveFamily"), sameValue(OFFICIAL_VERIFICATION_OBJECTIVE_FAMILY, text(eventMetadata, "objectiveFamily")), "analysis.events.metadata.objectiveFamily"));
        }
        return List.copyOf(checks);
    }

    private EirCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new EirCheckResult(label, value(expected), value(actual), pass, source);
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
        Map<String, Object> eventMetadata = primaryEventMetadata(events);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Event count", String.valueOf(events.size()));
        facts.put("First event", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("Last event", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("Primary event metadata source", events.stream().filter(item -> item.metadata() != null && !item.metadata().isEmpty()).map(OfficialVerificationAnalysisEventStore.AnalysisEvent::type).findFirst().orElse("absent"));
        facts.put("Authorization effect provenance", value(text(eventMetadata, "authorizationEffectProvenance")));
        facts.put("Bridge coverage level", value(text(eventMetadata, "bridgeCoverageLevel")));
        facts.put("Bridge coverage score", value(text(eventMetadata, "bridgeCoverageScore")));
        facts.put("Bridge missing contexts", value(joinList(eventMetadata.get("bridgeMissingContexts"))));
        facts.put("Delegated execution", value(text(eventMetadata, "delegated")));
        facts.put("Delegation objective family", value(text(eventMetadata, "objectiveFamily")));
        facts.put("Delegation allowed operations", value(joinList(eventMetadata.get("allowedOperations"))));
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

    private Map<String, String> buildAnalysisFacts(
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events
    ) {
        Map<String, Object> eventMetadata = primaryEventMetadata(events);
        Map<String, Object> source = firstPresent(decisionPayload, eventMetadata);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Decision", value(text(source, "decision", "action", "proposedAction")));
        facts.put("Risk score", value(text(source, "llmAuditRiskScore", "riskScore")));
        facts.put("Confidence", value(text(source, "effectiveConfidence", "confidence")));
        facts.put("Outbox status", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        return facts;
    }

    private List<EirEventItem> buildEventItems(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream()
                .map(this::toEventItem)
                .toList();
    }

    private EirEventItem toEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new EirEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
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
        evidence.put("decisionMetadata", primaryEventMetadata(events));
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, CONTRACT_STATUS);
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

    private Map<String, Object> firstPresent(Map<String, Object>... sources) {
        for (Map<String, Object> source : sources) {
            if (source != null && !source.isEmpty()) {
                return source;
            }
        }
        return Map.of();
    }
    private boolean sameValue(String expected, String actual) {
        return StringUtils.hasText(expected)
                && StringUtils.hasText(actual)
                && expected.trim().equalsIgnoreCase(actual.trim());
    }

    private boolean atLeastInt(String actual, int minimum) {
        if (!StringUtils.hasText(actual)) {
            return false;
        }
        try {
            return Integer.parseInt(actual.trim()) >= minimum;
        }
        catch (NumberFormatException ignored) {
            return false;
        }
    }

    private boolean isRecognizedAuthorizationEffectProvenance(String provenance) {
        return sameValue("BRIDGE_AUTHORIZATION_STAMP", provenance)
                || sameValue("METHOD_INVOCATION_RESULT", provenance);
    }

    private String joinList(Object rawValue) {
        if (rawValue instanceof List<?> list && !list.isEmpty()) {
            return list.stream()
                    .filter(item -> item != null && StringUtils.hasText(String.valueOf(item)))
                    .map(String::valueOf)
                    .toList()
                    .toString();
        }
        return null;
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

    public record EirRunSummary(
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

    public record EirRunRecord(
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
            List<EirCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<EirEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<EirCheckResult, EirEventItem> {

        public EirRunSummary toSummary() {
            return new EirRunSummary(
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

    public record EirCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record EirEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}



















