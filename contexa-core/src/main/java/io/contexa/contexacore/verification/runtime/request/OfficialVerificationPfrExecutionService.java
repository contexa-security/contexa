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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationPfrExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationPfrExecutionService.PfrRunRecord, OfficialVerificationPfrExecutionService.EndpointDefinition> implements OfficialVerificationPfrExecutor {

    private static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "PFR",
                    OfficialVerificationPfrExecutionService.class.getName(),
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
    public OfficialVerificationPfrExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper
    ) {
        super("PFR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, webClientBuilder, objectMapper, PfrRunRecord::runId, PfrRunRecord::startedAt);
    }

    @Override
    public synchronized PfrRunRecord executeRun(
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
        return "enterprise-pfr-";
    }

    @Override
    protected PfrRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
        Map<String, Object> decisionMetadata = firstMetadata(state.artifacts().events(), "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(state.artifacts().decisionPayload().get("attributes"));
        Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
                decisionMetadata,
                decisionAttributes,
                state.artifacts().decisionPayload(),
                state.artifacts().promptPayload()
        );
        List<PfrCheckResult> checks = buildChecks(
                decisionMetadata,
                promptTelemetry,
                state.artifacts().decisionPayload(),
                decisionAttributes,
                state.artifacts().promptPayload()
        );
        int totalChecks = checks.size();
        int passedChecks = (int) checks.stream().filter(PfrCheckResult::pass).count();
        double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
        return new PfrRunRecord(
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
                buildPfrEventFacts(state.artifacts().events(), decisionMetadata, promptTelemetry),
                buildPfrPromptFacts(promptTelemetry, state.artifacts().decisionPayload(), state.artifacts().promptPayload()),
                buildPfrAnalysisFacts(promptTelemetry, state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), state.artifacts().promptPayload()),
                state.artifacts().events().stream().map(this::toPfrEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildPfrRawEvidence(
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
                                state.artifacts().promptPayload(),
                                decisionMetadata,
                                decisionAttributes
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
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId));
        if (request == null) {
            return;
        }
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }
    private List<PfrCheckResult> buildChecks(
            Map<String, Object> decisionMetadata,
            Map<String, Object> promptTelemetry,
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptPayload
    ) {
        String primaryPromptVersion = text(decisionMetadata, "promptVersion");
        String primaryPromptHash = text(decisionMetadata, "promptHash");
        String primaryTemplateKey = text(decisionMetadata, "templateKey", "promptTemplateKey");
        String promptVersion = text(promptTelemetry, "promptVersion");
        String promptHash = text(promptTelemetry, "promptHash");
        String systemPromptHash = text(promptTelemetry, "systemPromptHash");
        String userPromptHash = text(promptTelemetry, "userPromptHash");
        String templateKey = text(promptTelemetry, "templateKey", "promptTemplateKey");
        List<String> promptSectionSet = stringList(promptTelemetry, "promptSectionSet");
        boolean omittedSectionsTracked = promptTelemetry.containsKey("omittedSections");
        boolean omissionLedgerTracked = promptTelemetry.containsKey("omissionLedger");
        int omissionLedgerSize = listSize(promptTelemetry.get("omissionLedger"));
        int promptOmissionCount = integer(promptTelemetry, "promptOmissionCount");
        String promptEvidenceCompleteness = text(promptTelemetry, "promptEvidenceCompleteness");
        boolean promptLengthFieldsPresent = containsValue(promptTelemetry, "systemPromptLength")
                && containsValue(promptTelemetry, "userPromptLength")
                && containsValue(promptTelemetry, "totalPromptLength");
        boolean rawAndLlmLengthFieldsPresent = containsValue(promptTelemetry, "rawSystemPromptLength")
                && containsValue(promptTelemetry, "rawUserPromptLength")
                && containsValue(promptTelemetry, "rawTotalPromptLength")
                && containsValue(promptTelemetry, "llmSystemPromptLength")
                && containsValue(promptTelemetry, "llmUserPromptLength")
                && containsValue(promptTelemetry, "llmTotalPromptLength");
        String promptTokenEstimator = text(promptTelemetry, "promptTokenEstimator");
        boolean estimatedTokenFieldsPresent = containsValue(promptTelemetry, "estimatedSystemTokens")
                && containsValue(promptTelemetry, "estimatedUserTokens")
                && containsValue(promptTelemetry, "estimatedTotalTokens");        return List.of(
                check("decision metadata prompt telemetry exists", "present", decisionMetadata.isEmpty() ? "absent" : "present", !decisionMetadata.isEmpty(), "analysis.events[DECISION_APPLIED].metadata"),
                check("primary promptVersion is present", "present", value(primaryPromptVersion), StringUtils.hasText(primaryPromptVersion), "analysis.events[DECISION_APPLIED].metadata.promptVersion"),
                check("primary promptHash is present", "present", value(primaryPromptHash), StringUtils.hasText(primaryPromptHash), "analysis.events[DECISION_APPLIED].metadata.promptHash"),
                check("primary templateKey is present", "present", value(primaryTemplateKey), StringUtils.hasText(primaryTemplateKey), "analysis.events[DECISION_APPLIED].metadata.templateKey"),
                check("promptVersion is present", "present", value(promptVersion), StringUtils.hasText(promptVersion), "analysis.events[DECISION_APPLIED].metadata.promptVersion"),
                check("promptHash is present", "present", value(promptHash), StringUtils.hasText(promptHash), "analysis.events[DECISION_APPLIED].metadata.promptHash"),
                check("systemPromptHash is present", "present", value(systemPromptHash), StringUtils.hasText(systemPromptHash), "analysis.events[DECISION_APPLIED].metadata.systemPromptHash"),
                check("userPromptHash is present", "present", value(userPromptHash), StringUtils.hasText(userPromptHash), "analysis.events[DECISION_APPLIED].metadata.userPromptHash"),
                check("templateKey is present", "present", value(templateKey), StringUtils.hasText(templateKey), "analysis.events[DECISION_APPLIED].metadata.templateKey"),
                check("promptSectionSet is present", "present", String.valueOf(promptSectionSet.size()), !promptSectionSet.isEmpty(), "analysis.events[DECISION_APPLIED].metadata.promptSectionSet"),
                check("omittedSections are tracked", "present", omittedSectionsTracked ? "present" : "absent", omittedSectionsTracked, "analysis.events[DECISION_APPLIED].metadata.omittedSections"),
                check("omissionLedger is tracked", "present", omissionLedgerTracked ? "present" : "absent", omissionLedgerTracked, "analysis.events[DECISION_APPLIED].metadata.omissionLedger"),
                check("promptOmissionCount matches omissionLedger size", String.valueOf(promptOmissionCount), String.valueOf(omissionLedgerSize), promptOmissionCount >= 0 && promptOmissionCount == omissionLedgerSize, "analysis.events[DECISION_APPLIED].metadata.omissionLedger"),
                check("promptEvidenceCompleteness is present", "present", value(promptEvidenceCompleteness), StringUtils.hasText(promptEvidenceCompleteness), "analysis.events[DECISION_APPLIED].metadata.promptEvidenceCompleteness"),
                check("prompt length fields are present", "present", promptLengthFieldsPresent ? "present" : "absent", promptLengthFieldsPresent, "analysis.events[DECISION_APPLIED].metadata.totalPromptLength"),
                check("raw and llm prompt length fields are present", "present", rawAndLlmLengthFieldsPresent ? "present" : "absent", rawAndLlmLengthFieldsPresent, "analysis.events[DECISION_APPLIED].metadata.rawTotalPromptLength"),
                check("promptTokenEstimator is present", "present", value(promptTokenEstimator), StringUtils.hasText(promptTokenEstimator), "analysis.events[DECISION_APPLIED].metadata.promptTokenEstimator"),
                check("estimated token fields are present", "present", estimatedTokenFieldsPresent ? "present" : "absent", estimatedTokenFieldsPresent, "analysis.events[DECISION_APPLIED].metadata.estimatedTotalTokens")
        );
    }

    private PfrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new PfrCheckResult(label, value(expected), value(actual), pass, source);
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

    private List<PfrEventItem> buildEventItems(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream()
                .map(this::toPfrEventItem)
                .toList();
    }

    private PfrEventItem toPfrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new PfrEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    private Map<String, String> buildPfrEventFacts(
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            Map<String, Object> decisionMetadata,
            Map<String, Object> promptTelemetry
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("eventCount", String.valueOf(events.size()));
        facts.put("firstEvent", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("lastEvent", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("decisionEventPresent", Boolean.toString(events.stream().anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()))));
        facts.put("requestId", value(text(decisionMetadata, "requestId", "correlationId")));
        facts.put("requestPath", value(text(decisionMetadata, "requestPath")));
        facts.put("promptRuntimeTelemetryLinked", value(text(promptTelemetry, "promptRuntimeTelemetryLinked")));
        facts.put("promptRuntimeTelemetryLayer", value(text(promptTelemetry, "promptRuntimeTelemetryLayer")));
        facts.put("promptTelemetrySource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptTelemetry,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata)
        ));
        return facts;
    }

    private Map<String, String> buildPfrPromptFacts(
            Map<String, Object> promptTelemetry,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptKey", value(text(promptTelemetry, "promptKey")));
        facts.put("templateKey", value(text(promptTelemetry, "templateKey", "promptTemplateKey")));
        facts.put("promptVersion", value(text(promptTelemetry, "promptVersion")));
        facts.put("promptHash", value(text(promptTelemetry, "promptHash")));
        facts.put("systemPromptHash", value(text(promptTelemetry, "systemPromptHash")));
        facts.put("userPromptHash", value(text(promptTelemetry, "userPromptHash")));
        facts.put("promptSectionCount", String.valueOf(stringList(promptTelemetry, "promptSectionSet").size()));
        facts.put("omittedSectionCount", String.valueOf(stringList(promptTelemetry, "omittedSections").size()));
        facts.put("promptEvidenceCompleteness", value(text(promptTelemetry, "promptEvidenceCompleteness")));
        facts.put("rawTotalPromptLength", value(numberText(promptTelemetry, "rawTotalPromptLength")));
        facts.put("llmTotalPromptLength", value(numberText(promptTelemetry, "llmTotalPromptLength")));
        facts.put("decisionTemplateKey", value(text(decisionPayload, "promptTemplateKey", "templateKey")));
        facts.put("retrievalPurpose", value(text(promptPayload, "retrievalPurpose")));
        return facts;
    }

    private Map<String, String> buildPfrAnalysisFacts(
            Map<String, Object> promptTelemetry,
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            Map<String, Object> promptPayload
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(text(decisionPayload, "decision")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        facts.put("promptTokenEstimator", value(text(promptTelemetry, "promptTokenEstimator")));
        facts.put("estimatedTotalTokens", value(numberText(promptTelemetry, "estimatedTotalTokens")));
        facts.put("promptOmissionCount", value(numberText(promptTelemetry, "promptOmissionCount")));
        facts.put("promptGeneratedAtEpochMs", value(numberText(promptTelemetry, "promptGeneratedAtEpochMs")));
        facts.put("allowedDocumentCount", value(numberText(promptPayload, "allowedDocumentCount")));
        facts.put("deniedDocumentCount", value(numberText(promptPayload, "deniedDocumentCount")));
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

    private Map<String, Object> buildPfrRawEvidence(
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
            Map<String, Object> promptPayload,
            Map<String, Object> decisionMetadata,
            Map<String, Object> decisionAttributes
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
        Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
                decisionMetadata,
                decisionAttributes,
                decisionPayload,
                promptPayload
        );
        mutable.put("decisionMetadata", decisionMetadata);
        mutable.put("decisionAttributes", decisionAttributes);
        mutable.put("promptTelemetryPrimary", decisionMetadata);
        mutable.put("promptTelemetryResolved", promptTelemetry);
        mutable.put("promptTelemetrySource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptTelemetry,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload", decisionPayload),
                OfficialVerificationRuntimeEvidenceSupport.named("promptAuditOutbox.payload", promptPayload)
        ));
        mutable.put("promptTelemetryPrimaryPresent", !decisionMetadata.isEmpty());
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

    private List<String> stringList(Map<String, Object> source, String... keys) {
        if (source == null) {
            return List.of();
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof List<?> items) {
                return items.stream()
                        .filter(item -> item != null && StringUtils.hasText(String.valueOf(item)))
                        .map(item -> String.valueOf(item).trim())
                        .toList();
            }
        }
        return List.of();
    }

    private int listSize(Object value) {
        return value instanceof List<?> items ? items.size() : 0;
    }

    private List<String> firstNonEmptyList(List<String> primary, List<String> secondary) {
        if (primary != null && !primary.isEmpty()) {
            return primary;
        }
        if (secondary != null && !secondary.isEmpty()) {
            return secondary;
        }
        return List.of();
    }

    private String numberText(Map<String, Object> source, String... keys) {
        if (source == null) {
            return null;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof Number number) {
                return String.valueOf(number);
            }
            if (value instanceof String textValue) {
                String normalized = textValue.trim();
                if (!normalized.isBlank()) {
                    return normalized;
                }
            }
        }
        return null;
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
        return StringUtils.hasText(input) ? input : "n/a";
    }

    private boolean sameValue(String left, String right) {
        return StringUtils.hasText(left) && left.equals(right);
    }

    private String pair(String left, String right) {
        return value(left) + " | " + value(right);
    }

    private String buildMessage(double score) {
        if (score < 95.0d) {
            return "PFR detected prompt telemetry gaps in the enterprise verification path.";
        }
        return "PFR confirms that prompt telemetry stays complete, traceable, and synchronized for the enterprise verification path.";
    }
    private String normalizeResourceId(String resourceId) {
        String normalized = StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001";
        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "-");
        return normalized.isBlank() ? "resource-001" : normalized;
    }

    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record PfrRunSummary(
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

    public record PfrRunRecord(
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
            List<PfrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<PfrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<PfrCheckResult, PfrEventItem> {

        public PfrRunSummary toSummary() {
            return new PfrRunSummary(
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

    public record PfrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record PfrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}





