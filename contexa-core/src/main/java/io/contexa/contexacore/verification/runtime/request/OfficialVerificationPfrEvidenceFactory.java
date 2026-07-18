package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationPfrExecutionService.EndpointDefinition;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationPfrExecutionService.PfrCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationPfrExecutionService.PfrEventItem;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.contexa.contexacore.verification.runtime.request.OfficialVerificationPfrExecutionService.*;

final class OfficialVerificationPfrEvidenceFactory {
    List<PfrCheckResult> buildChecks(
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
                && containsValue(promptTelemetry, "estimatedTotalTokens");
        return List.of(
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

    Map<String, String> buildRequestFacts(
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
    PfrEventItem toPfrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new PfrEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    Map<String, String> buildPfrEventFacts(
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

    Map<String, String> buildPfrPromptFacts(
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

    Map<String, String> buildPfrAnalysisFacts(
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

    Map<String, Object> buildPfrRawEvidence(
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
    Map<String, Object> firstMetadata(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events, String type) {
        return events.stream()
                .filter(item -> type.equalsIgnoreCase(item.type()))
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .filter(item -> item != null && !item.isEmpty())
                .findFirst()
                .map(LinkedHashMap::new)
                .orElseGet(LinkedHashMap::new);
    }

    Map<String, Object> map(Object value) {
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

    String buildMessage(double score) {
        if (score < 95.0d) {
            return "PFR detected prompt telemetry gaps in the enterprise verification path.";
        }
        return "PFR confirms that prompt telemetry stays complete, traceable, and synchronized for the enterprise verification path.";
    }
}
