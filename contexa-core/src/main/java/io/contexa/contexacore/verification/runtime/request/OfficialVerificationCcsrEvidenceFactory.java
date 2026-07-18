package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.*;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcsrExecutionService.CcsrCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcsrExecutionService.CcsrEventItem;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcsrExecutionService.CcsrRunRecord;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcsrExecutionService.EndpointDefinition;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class OfficialVerificationCcsrEvidenceFactory {

    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private final OfficialVerificationCcsrCheckEvaluator checkEvaluator =
            new OfficialVerificationCcsrCheckEvaluator();

    CcsrRunRecord buildRunRecord(CcsrRunInput state) {
        Map<String, Object> sessionMetadata = firstMetadata(state.events(), "SESSION_CONTEXT_LOADED");
        Map<String, Object> behaviorMetadata = firstMetadata(state.events(), "BEHAVIOR_ANALYSIS_COMPLETE");
        Map<String, Object> decisionAttributes = map(state.decisionPayload().get("attributes"));
        List<CcsrCheckResult> checks = checkEvaluator.evaluate(
                state.endpoint(), state.invocation(), primaryEventMetadata(state.events()), state.promptPayload()
        );
        int passedChecks = (int) checks.stream().filter(CcsrCheckResult::pass).count();
        double score = checks.isEmpty() ? 0.0d : (passedChecks * 100.0d) / checks.size();
        return assembleRunRecord(
                state, sessionMetadata, behaviorMetadata, decisionAttributes, checks, passedChecks, score
        );
    }

    private CcsrRunRecord assembleRunRecord(
            CcsrRunInput state,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> decisionAttributes,
            List<CcsrCheckResult> checks,
            int passedChecks,
            double score
    ) {
        boolean thresholdPassed = score >= 95.0d;
        return new CcsrRunRecord(
                UUID.randomUUID().toString(), state.runOrdinal(), state.endpoint().key(), state.endpoint().label(),
                state.requestId(), score, passedChecks, checks.size(), state.processingTimeMs(),
                thresholdPassed ? "Threshold passed" : "Threshold failed", thresholdPassed ? "success" : "error",
                buildMessage(score), KOREA_TIME.format(state.startedAt()), KOREA_TIME.format(state.completedAt()), checks,
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(state.endpoint(), state.userId(), state.requestId(), state.invocation(),
                                state.requestedRunCount(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested()),
                        state.request()),
                buildCcsrEventFacts(state.events()), buildCcsrPromptFacts(state.decisionPayload(), state.promptPayload()),
                buildCcsrAnalysisFacts(state.decisionPayload(), state.decisionOutbox(), sessionMetadata,
                        behaviorMetadata, decisionAttributes),
                state.events().stream().map(this::toCcsrEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildCcsrRawEvidence(state.endpoint(), state.userId(), state.requestedRunCount(), state.rerun(),
                                state.contaminationSeed(), state.baselineSeedRequested(), state.invocation(), state.events(),
                                state.decisionOutbox(), state.promptOutbox(), state.decisionPayload(), state.promptPayload()),
                        state.request())
        );
    }

    record CcsrRunInput(
            EndpointDefinition endpoint, String userId, String requestId, int runOrdinal, int requestedRunCount,
            boolean rerun, boolean contaminationSeed, boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request, Instant startedAt, Instant completedAt, Long processingTimeMs,
            Map<String, Object> invocation, List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox, PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload, Map<String, Object> promptPayload
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
        facts.put("responseRequestId", value(text(invocation, "requestId")));
        facts.put("requestPath", value(text(invocation, "requestPath")));
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, OfficialVerificationCcsrExecutionService.CONTRACT_STATUS);
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
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, OfficialVerificationCcsrExecutionService.CONTRACT_STATUS);
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

}
