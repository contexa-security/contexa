package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationMtrExecutionService.EndpointDefinition;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationMtrExecutionService.MtrCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationMtrExecutionService.MtrEventItem;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.contexa.contexacore.verification.runtime.request.OfficialVerificationMtrExecutionService.*;

final class OfficialVerificationMtrEvidenceFactory {
    List<MtrCheckResult> buildChecks(
            String requestId,
            Map<String, Object> invocation,
            Map<String, Object> decisionMetadata,
            Map<String, Object> promptTelemetry,
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox
    ) {
        String responseRequestId = text(invocation, "requestId");
        String eventRequestId = text(decisionMetadata, "requestId", "correlationId");
        String promptCorrelationId = text(promptPayload, "correlationId");
        String primaryPromptVersion = text(decisionMetadata, "promptVersion");
        String primaryPromptHash = text(decisionMetadata, "promptHash");
        String primaryTemplateKey = text(decisionMetadata, "templateKey", "promptTemplateKey");
        String promptVersion = text(promptTelemetry, "promptVersion");
        String promptHash = text(promptTelemetry, "promptHash");
        String systemPromptHash = text(promptTelemetry, "systemPromptHash");
        String userPromptHash = text(promptTelemetry, "userPromptHash");
        String promptKey = text(promptTelemetry, "promptKey");
        String templateKey = text(promptTelemetry, "templateKey", "promptTemplateKey");
        String promptOutboxCorrelationId = promptOutbox != null ? promptOutbox.getCorrelationId() : null;
        String promptAuditId = promptOutbox != null ? promptOutbox.getAuditId() : null;
        boolean telemetryLinked = Boolean.parseBoolean(text(decisionMetadata, "promptRuntimeTelemetryLinked"));
        return List.of(
                check("decision metadata prompt telemetry exists", "present", decisionMetadata.isEmpty() ? "absent" : "present", !decisionMetadata.isEmpty(), "analysis.events[DECISION_APPLIED].metadata"),
                check("primary promptVersion is present", "present", value(primaryPromptVersion), StringUtils.hasText(primaryPromptVersion), "analysis.events[DECISION_APPLIED].metadata.promptVersion"),
                check("primary promptHash is present", "present", value(primaryPromptHash), StringUtils.hasText(primaryPromptHash), "analysis.events[DECISION_APPLIED].metadata.promptHash"),
                check("primary templateKey is present", "present", value(primaryTemplateKey), StringUtils.hasText(primaryTemplateKey), "analysis.events[DECISION_APPLIED].metadata.templateKey"),
                check("requestId matches response payload", value(requestId), pair(requestId, responseRequestId), sameValue(requestId, responseRequestId), "probe.response.requestId"),
                check("requestId matches decision event metadata", value(requestId), pair(requestId, eventRequestId), sameValue(requestId, eventRequestId), "analysis.events[DECISION_APPLIED].metadata.requestId"),
                check("requestId matches prompt audit correlationId", value(requestId), pair(requestId, promptCorrelationId), sameValue(requestId, promptCorrelationId), "promptPayload.correlationId"),
                check("promptVersion is present", "present", value(promptVersion), StringUtils.hasText(promptVersion), "analysis.events[DECISION_APPLIED].metadata.promptVersion"),
                check("promptHash is present", "present", value(promptHash), StringUtils.hasText(promptHash), "analysis.events[DECISION_APPLIED].metadata.promptHash"),
                check("systemPromptHash is present", "present", value(systemPromptHash), StringUtils.hasText(systemPromptHash), "analysis.events[DECISION_APPLIED].metadata.systemPromptHash"),
                check("userPromptHash is present", "present", value(userPromptHash), StringUtils.hasText(userPromptHash), "analysis.events[DECISION_APPLIED].metadata.userPromptHash"),
                check("prompt governance key is stable", SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE.promptKey(), value(promptKey), sameValue(SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE.promptKey(), promptKey), "analysis.events[DECISION_APPLIED].metadata.promptKey"),
                check("prompt governance template is stable", SecurityDecisionStandardPromptTemplate.STANDARD_TEMPLATE_KEY, value(templateKey), sameValue(SecurityDecisionStandardPromptTemplate.STANDARD_TEMPLATE_KEY, templateKey), "analysis.events[DECISION_APPLIED].metadata.templateKey"),
                check("prompt runtime telemetry is linked", "true", telemetryLinked ? "true" : "false", telemetryLinked, "analysis.events[DECISION_APPLIED].metadata.promptRuntimeTelemetryLinked"),
                check("prompt audit record exists", "present", value(promptAuditId), StringUtils.hasText(promptAuditId), "promptAuditOutbox.auditId"),
                check("prompt outbox correlation is preserved", value(requestId), pair(requestId, promptOutboxCorrelationId), sameValue(requestId, promptOutboxCorrelationId), "promptAuditOutbox.correlationId")
        );
    }

    private MtrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new MtrCheckResult(label, value(expected), value(actual), pass, source);
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
    MtrEventItem toMtrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new MtrEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    Map<String, String> buildMtrEventFacts(
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
        facts.put("correlationId", value(text(decisionMetadata, "correlationId", "requestId")));
        facts.put("requestPath", value(text(decisionMetadata, "requestPath")));
        facts.put("promptRuntimeTelemetryLinked", value(text(promptTelemetry, "promptRuntimeTelemetryLinked")));
        facts.put("promptRuntimeTelemetryLayer", value(text(promptTelemetry, "promptRuntimeTelemetryLayer")));
        facts.put("promptTelemetrySource", OfficialVerificationRuntimeEvidenceSupport.sourceName(
                promptTelemetry,
                OfficialVerificationRuntimeEvidenceSupport.named("analysis.events[DECISION_APPLIED].metadata", decisionMetadata)
        ));
        return facts;
    }

    Map<String, String> buildMtrPromptFacts(
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
        facts.put("decisionPromptVersion", value(text(decisionPayload, "promptVersion")));
        facts.put("decisionTemplateKey", value(text(decisionPayload, "promptTemplateKey", "templateKey")));
        facts.put("decisionPromptHash", value(text(decisionPayload, "promptHash")));
        facts.put("promptAuditCorrelationId", value(text(promptPayload, "correlationId")));
        facts.put("promptAuditId", value(text(promptPayload, "auditId")));
        facts.put("retrievalPurpose", value(text(promptPayload, "retrievalPurpose")));
        return facts;
    }

    Map<String, String> buildMtrAnalysisFacts(
            Map<String, Object> promptTelemetry,
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> promptPayload
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(text(decisionPayload, "decision")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        facts.put("decisionCorrelationId", decisionOutbox != null ? value(decisionOutbox.getCorrelationId()) : "absent");
        facts.put("promptAuditStatus", promptOutbox != null ? value(promptOutbox.getStatus()) : "absent");
        facts.put("promptAuditCorrelationId", promptOutbox != null ? value(promptOutbox.getCorrelationId()) : "absent");
        facts.put("promptAuditId", promptOutbox != null ? value(promptOutbox.getAuditId()) : "absent");
        facts.put("promptTelemetryLayer", value(text(promptTelemetry, "promptRuntimeTelemetryLayer")));
        facts.put("promptGeneratedAtEpochMs", value(numberText(promptTelemetry, "promptGeneratedAtEpochMs")));
        facts.put("contextFingerprint", value(text(promptPayload, "contextFingerprint")));
        facts.put("allowedDocumentCount", value(numberText(promptPayload, "allowedDocumentCount")));
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

    Map<String, Object> buildMtrRawEvidence(
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
            return "MTR detected broken request, prompt, or evidence linkage in the enterprise verification path.";
        }
        return "MTR confirms that requestId, prompt governance metadata, and evidence lineage stay traceable end-to-end.";
    }

}
