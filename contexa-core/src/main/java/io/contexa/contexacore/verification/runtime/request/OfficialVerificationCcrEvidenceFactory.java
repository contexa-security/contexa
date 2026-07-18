package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcrExecutionService.CcrCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcrExecutionService.CcrEventItem;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcrExecutionService.CcrRunRecord;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcrExecutionService.EndpointDefinition;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class OfficialVerificationCcrEvidenceFactory {

    private final OfficialVerificationCcrCheckEvaluator checkEvaluator = new OfficialVerificationCcrCheckEvaluator();

    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));

    CcrRunRecord buildRunRecord(CcrRunInput state) {
        CcrRunAssembly assembly = prepareRunAssembly(state);
        return assembleRunRecord(state, assembly);
    }

    private CcrRunAssembly prepareRunAssembly(CcrRunInput state) {
        Map<String, Object> sessionMetadata = firstMetadata(state.events(), "SESSION_CONTEXT_LOADED");
        Map<String, Object> behaviorMetadata = firstMetadata(state.events(), "BEHAVIOR_ANALYSIS_COMPLETE");
        Map<String, Object> decisionMetadata = firstMetadata(state.events(), "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(state.decisionPayload().get("attributes"));
        Map<String, Object> eventMetadata = primaryEventMetadata(state.events());
        Map<String, Object> promptExecutionMetadata = firstPresent(
                extractPromptPayload(state.events()),
                map(state.promptPayload().get("promptRuntimeTelemetry")),
                state.promptPayload()
        );
        List<CcrCheckResult> checks = checkEvaluator.evaluate(
                state.endpoint(), eventMetadata, sessionMetadata, behaviorMetadata, promptExecutionMetadata
        );
        int passedChecks = (int) checks.stream().filter(CcrCheckResult::pass).count();
        double score = checks.isEmpty() ? 0.0d : (passedChecks * 100.0d) / checks.size();
        int relatedDocumentsCount = relatedDocumentsCount(state.promptPayload(), decisionMetadata);
        boolean relatedDocumentsExpectationSatisfied = relatedDocumentsCount >= expectedRelatedDocuments(state.requestedRunCount());
        boolean requestParitySatisfied = state.requestId().equals(OfficialVerificationRequestEvidenceValues.text(state.invocation(), "requestId"))
                && state.requestId().equals(OfficialVerificationRequestEvidenceValues.text(state.decisionPayload(), "correlationId"))
                && state.requestId().equals(OfficialVerificationRequestEvidenceValues.text(state.promptPayload(), "correlationId"));
        return new CcrRunAssembly(sessionMetadata, behaviorMetadata, decisionAttributes,
                checks, passedChecks, score, relatedDocumentsExpectationSatisfied, requestParitySatisfied);
    }

    private CcrRunRecord assembleRunRecord(CcrRunInput state, CcrRunAssembly assembly) {
        boolean thresholdPassed = assembly.score() >= 95.0d;
        return new CcrRunRecord(
                UUID.randomUUID().toString(), state.runOrdinal(), state.endpoint().key(), state.endpoint().label(),
                state.requestId(), assembly.score(), assembly.passedChecks(), assembly.checks().size(), state.processingTimeMs(),
                thresholdPassed ? "Threshold passed" : "Threshold failed",
                thresholdPassed ? "success" : "error",
                thresholdPassed ? "Required context facts stayed aligned from request through the final decision."
                        : buildMessage(assembly.score(), assembly.relatedDocumentsExpectationSatisfied(), assembly.requestParitySatisfied()),
                KOREA_TIME.format(state.startedAt()), KOREA_TIME.format(state.completedAt()), assembly.checks(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(state.endpoint(), state.userId(), state.requestId(), state.invocation(),
                                state.requestedRunCount(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested()),
                        state.request()),
                buildCcrEventFacts(state.events()),
                buildCcrPromptFacts(state.decisionPayload(), state.promptPayload()),
                buildCcrAnalysisFacts(state.decisionPayload(), state.decisionOutbox(), assembly.sessionMetadata(),
                        assembly.behaviorMetadata(), assembly.decisionAttributes()),
                state.events().stream().map(this::toCcrEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildCcrRawEvidence(state.endpoint(), state.userId(), state.requestedRunCount(), state.rerun(),
                                state.contaminationSeed(), state.baselineSeedRequested(), state.invocation(), state.events(),
                                state.decisionOutbox(), state.promptOutbox(), state.decisionPayload(), state.promptPayload()),
                        state.request())
        );
    }

    record CcrRunInput(
            EndpointDefinition endpoint,
            String userId,
            String requestId,
            int runOrdinal,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request,
            Instant startedAt,
            Instant completedAt,
            Long processingTimeMs,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
    }

    private record CcrRunAssembly(
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> decisionAttributes,
            List<CcrCheckResult> checks,
            int passedChecks,
            double score,
            boolean relatedDocumentsExpectationSatisfied,
            boolean requestParitySatisfied
    ) {
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
        facts.put("responseRequestId", value(OfficialVerificationRequestEvidenceValues.text(invocation, "requestId")));
        facts.put("requestPath", value(OfficialVerificationRequestEvidenceValues.text(invocation, "requestPath")));
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, OfficialVerificationCcrExecutionService.CONTRACT_STATUS);
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
        facts.put("requestId", value(decisionMetadata != null ? OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "requestId", "correlationId") : null));
        facts.put("relatedDocumentsCount", String.valueOf(relatedDocumentsCount(extractPromptPayload(events), decisionMetadata)));
        return facts;
    }

    private Map<String, String> buildCcrPromptFacts(Map<String, Object> decisionPayload, Map<String, Object> promptPayload) {
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> promptSource = firstPresent(decisionPayload, decisionAttributes);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptKey", value(OfficialVerificationRequestEvidenceValues.text(promptSource, "promptKey")));
        facts.put("templateKey", value(OfficialVerificationRequestEvidenceValues.text(promptSource, "promptTemplateKey", "templateKey")));
        facts.put("promptVersion", value(OfficialVerificationRequestEvidenceValues.text(promptSource, "promptVersion")));
        facts.put("promptHash", value(OfficialVerificationRequestEvidenceValues.text(promptSource, "promptHash")));
        facts.put("promptSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptSource,
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload", decisionPayload),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        facts.put("retrievalPurpose", value(OfficialVerificationRequestEvidenceValues.text(promptPayload, "retrievalPurpose")));
        facts.put("allowedDocumentCount", value(OfficialVerificationRequestEvidenceValues.text(promptPayload, "allowedDocumentCount")));
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
        facts.put("decision", value(OfficialVerificationRequestEvidenceValues.text(decisionPayload, "decision")));
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
        facts.put("previousPath", value(OfficialVerificationRequestEvidenceValues.text(sessionSource, "previousPath")));
        facts.put("requestCount", value(OfficialVerificationRequestEvidenceValues.text(sessionSource, "requestCount", "recentRequestCount")));
        facts.put("baselineEstablished", value(OfficialVerificationRequestEvidenceValues.text(behaviorSource, "baselineEstablished", "organizationBaselineEstablished")));
        facts.put("personalBaselineEstablished", value(OfficialVerificationRequestEvidenceValues.text(behaviorSource, "personalBaselineEstablished")));
        facts.put("newDevice", value(OfficialVerificationRequestEvidenceValues.text(behaviorSource, "isNewDevice", "newDevice")));
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
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, OfficialVerificationCcrExecutionService.CONTRACT_STATUS);
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
        Map<String, Object> mutable = new LinkedHashMap<>(buildRawEvidence(
                endpoint, userId, requestedRunCount, rerun, contaminationSeed, baselineSeedRequested,
                invocation, events, decisionOutbox, promptOutbox, decisionPayload, promptPayload
        ));
        Map<String, Object> sessionMetadata = firstMetadata(events, "SESSION_CONTEXT_LOADED");
        Map<String, Object> behaviorMetadata = firstMetadata(events, "BEHAVIOR_ANALYSIS_COMPLETE");
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        appendContextSources(
                mutable, sessionMetadata, behaviorMetadata, decisionMetadata, decisionAttributes, decisionPayload
        );
        return Map.copyOf(mutable);
    }

    private void appendContextSources(
            Map<String, Object> evidence,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> decisionMetadata,
            Map<String, Object> decisionAttributes,
            Map<String, Object> decisionPayload
    ) {
        Map<String, Object> sessionSource = firstPresent(sessionMetadata, decisionMetadata, decisionAttributes);
        Map<String, Object> behaviorSource = firstPresent(behaviorMetadata, decisionMetadata, decisionAttributes);
        Map<String, Object> promptSource = firstPresent(decisionPayload, decisionAttributes);
        evidence.put("sessionMetadata", sessionMetadata);
        evidence.put("behaviorMetadata", behaviorMetadata);
        evidence.put("decisionMetadata", decisionMetadata);
        evidence.put("decisionAttributes", decisionAttributes);
        evidence.put("sessionContextSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                sessionSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[SESSION_CONTEXT_LOADED].metadata", sessionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        evidence.put("sessionContextPrimaryPresent", !sessionMetadata.isEmpty());
        evidence.put("behaviorContextSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                behaviorSource,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[BEHAVIOR_ANALYSIS_COMPLETE].metadata", behaviorMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        evidence.put("behaviorContextPrimaryPresent", !behaviorMetadata.isEmpty());
        evidence.put("promptLineageSource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptSource,
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload", decisionPayload),
                OfficialVerificationRuntimeEvidenceSupport.named("decisionOutbox.payload.attributes", decisionAttributes)
        ));
        evidence.put("promptLineagePrimaryPresent", !decisionPayload.isEmpty());
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


    private int expectedRelatedDocuments(int requestedRunCount) {
        return requestedRunCount <= 1 ? 0 : Math.min(2, requestedRunCount - 1);
    }

    private int relatedDocumentsCount(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        int allowedDocumentCount = OfficialVerificationRequestEvidenceValues.integer(promptPayload, "allowedDocumentCount");
        if (allowedDocumentCount > 0) {
            return allowedDocumentCount;
        }
        Object contexts = promptPayload.get("contexts");
        if (contexts instanceof List<?> items && !items.isEmpty()) {
            return items.size();
        }
        return OfficialVerificationRequestEvidenceValues.integer(decisionMetadata, "relatedDocumentsCount");
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

}
