package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCorExecutionService.ContaminationSummary;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCorExecutionService.CorCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCorExecutionService.CorEventItem;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCorExecutionService.EndpointDefinition;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static io.contexa.contexacore.verification.runtime.request.OfficialVerificationCorExecutionService.*;

final class OfficialVerificationCorEvidenceFactory {
    List<CorCheckResult> buildChecks(
            String requestId,
            Map<String, Object> invocation,
            Map<String, Object> decisionMetadata,
            Map<String, Object> promptPayload,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            ContaminationSummary contamination
    ) {
        String responseRequestId = OfficialVerificationRequestEvidenceValues.text(invocation, "requestId");
        String eventRequestId = OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "requestId", "correlationId");
        String promptCorrelationId = OfficialVerificationRequestEvidenceValues.text(promptPayload, "correlationId");
        String promptOutboxCorrelationId = promptOutbox != null ? promptOutbox.getCorrelationId() : null;
        String promptAuditId = promptOutbox != null ? promptOutbox.getAuditId() : null;
        boolean countsAligned = contamination.totalContextCount() == contamination.requestedDocumentCount();
        boolean allowedDeniedAligned =
                contamination.totalContextCount() == contamination.allowedDocumentCount() + contamination.deniedDocumentCount();
        boolean contaminationSurfaced = contamination.contaminatedCount() == 0
                || contamination.deniedDocumentCount() > 0
                || !contamination.deniedReasons().isEmpty();
        return List.of(
                check("requestId matches probe response", value(requestId), pair(requestId, responseRequestId), sameValue(requestId, responseRequestId), "probe.response.requestId"),
                check("requestId matches decision event metadata", value(requestId), pair(requestId, eventRequestId), sameValue(requestId, eventRequestId), "analysis.events[DECISION_APPLIED].metadata.requestId"),
                check("requestId matches prompt audit correlationId", value(requestId), pair(requestId, promptCorrelationId), sameValue(requestId, promptCorrelationId), "promptAuditPayload.correlationId"),
                check("prompt audit outbox correlation is preserved", value(requestId), pair(requestId, promptOutboxCorrelationId), sameValue(requestId, promptOutboxCorrelationId), "promptAuditOutbox.correlationId"),
                check("prompt audit record exists", "present", value(promptAuditId), StringUtils.hasText(promptAuditId), "promptAuditOutbox.auditId"),
                check("context ledger size matches requestedDocumentCount", String.valueOf(contamination.requestedDocumentCount()), String.valueOf(contamination.totalContextCount()), countsAligned, "promptAuditPayload.contexts"),
                check("allowed and denied counts reconcile with context ledger", String.valueOf(contamination.totalContextCount()), String.valueOf(contamination.allowedDocumentCount() + contamination.deniedDocumentCount()), allowedDeniedAligned, "promptAuditPayload.allowedDocumentCount/deniedDocumentCount"),
                check("contaminated document count is zero", "0", String.valueOf(contamination.contaminatedCount()), contamination.contaminatedCount() == 0, "promptAuditPayload.contexts"),
                check("foreign-user document count is zero", "0", String.valueOf(contamination.foreignUserCount()), contamination.foreignUserCount() == 0, "promptAuditPayload.contexts.userId"),
                check("retrieval-purpose mismatch count is zero", "0", String.valueOf(contamination.purposeMismatchCount()), contamination.purposeMismatchCount() == 0, "promptAuditPayload.contexts.retrievalPurpose"),
                check("access-scope violation count is zero", "0", String.valueOf(contamination.scopeViolationCount()), contamination.scopeViolationCount() == 0, "promptAuditPayload.contexts.authorizationDecision"),
                check("contaminated contexts included in prompt is zero", "0", String.valueOf(contamination.contaminatedIncludedCount()), contamination.contaminatedIncludedCount() == 0, "promptAuditPayload.contexts.includedInPrompt"),
                check("contamination denial is surfaced when contamination exists", "true", contaminationSurfaced ? "true" : "false", contaminationSurfaced, "promptAuditPayload.deniedDocumentCount")
        );
    }

    private CorCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new CorCheckResult(label, value(expected), value(actual), pass, source);
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
        facts.put("responseRequestId", value(OfficialVerificationRequestEvidenceValues.text(invocation, "requestId")));
        facts.put("requestPath", value(OfficialVerificationRequestEvidenceValues.text(invocation, "requestPath")));
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, CONTRACT_STATUS);
    }
    CorEventItem toCorEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new CorEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    Map<String, String> buildCorEventFacts(
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            Map<String, Object> decisionMetadata
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("eventCount", String.valueOf(events.size()));
        facts.put("firstEvent", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("lastEvent", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("decisionEventPresent", Boolean.toString(events.stream().anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()))));
        facts.put("requestId", value(OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "requestId", "correlationId")));
        facts.put("correlationId", value(OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "correlationId", "requestId")));
        facts.put("requestPath", value(OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "requestPath")));
        facts.put("promptRuntimeTelemetryLinked", value(OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "promptRuntimeTelemetryLinked")));
        facts.put("promptRuntimeTelemetryLayer", value(OfficialVerificationRequestEvidenceValues.text(decisionMetadata, "promptRuntimeTelemetryLayer")));
        return facts;
    }

    Map<String, String> buildCorPromptFacts(
            Map<String, Object> promptTelemetry,
            Map<String, Object> promptPayload,
            ContaminationSummary contamination
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptVersion", value(OfficialVerificationRequestEvidenceValues.text(promptTelemetry, "promptVersion")));
        facts.put("promptHash", value(OfficialVerificationRequestEvidenceValues.text(promptTelemetry, "promptHash")));
        facts.put("systemPromptHash", value(OfficialVerificationRequestEvidenceValues.text(promptTelemetry, "systemPromptHash")));
        facts.put("userPromptHash", value(OfficialVerificationRequestEvidenceValues.text(promptTelemetry, "userPromptHash")));
        facts.put("retrievalPurpose", value(contamination.retrievalPurpose()));
        facts.put("requestedDocumentCount", String.valueOf(contamination.requestedDocumentCount()));
        facts.put("allowedDocumentCount", String.valueOf(contamination.allowedDocumentCount()));
        facts.put("deniedDocumentCount", String.valueOf(contamination.deniedDocumentCount()));
        facts.put("contextLedgerCount", String.valueOf(contamination.totalContextCount()));
        facts.put("contaminatedDocumentCount", String.valueOf(contamination.contaminatedCount()));
        facts.put("contaminatedIncludedCount", String.valueOf(contamination.contaminatedIncludedCount()));
        facts.put("foreignUserDocumentCount", String.valueOf(contamination.foreignUserCount()));
        facts.put("purposeMismatchCount", String.valueOf(contamination.purposeMismatchCount()));
        facts.put("accessScopeViolationCount", String.valueOf(contamination.scopeViolationCount()));
        facts.put("promptAuditCorrelationId", value(OfficialVerificationRequestEvidenceValues.text(promptPayload, "correlationId")));
        facts.put("promptAuditId", value(OfficialVerificationRequestEvidenceValues.text(promptPayload, "auditId")));
        return facts;
    }

    Map<String, String> buildCorAnalysisFacts(
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> promptPayload,
            ContaminationSummary contamination
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(OfficialVerificationRequestEvidenceValues.text(decisionPayload, "decision")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        facts.put("decisionCorrelationId", decisionOutbox != null ? value(decisionOutbox.getCorrelationId()) : "absent");
        facts.put("promptAuditStatus", promptOutbox != null ? value(promptOutbox.getStatus()) : "absent");
        facts.put("promptAuditCorrelationId", promptOutbox != null ? value(promptOutbox.getCorrelationId()) : "absent");
        facts.put("promptAuditId", promptOutbox != null ? value(promptOutbox.getAuditId()) : "absent");
        facts.put("contextFingerprint", value(OfficialVerificationRequestEvidenceValues.text(promptPayload, "contextFingerprint")));
        facts.put("contaminationRate", String.format(Locale.ROOT, "%.2f", contamination.contaminationRate()));
        facts.put("contaminationScore", String.format(Locale.ROOT, "%.2f", Math.max(0.0d, 100.0d - contamination.contaminationRate())));
        facts.put("contaminationFree", contamination.contaminatedCount() == 0 ? "true" : "false");
        facts.put("deniedReasons", contamination.deniedReasons().isEmpty() ? "none" : String.join(", ", contamination.deniedReasons()));
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

    Map<String, Object> buildCorRawEvidence(
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
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptTelemetry,
            ContaminationSummary contamination
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
        mutable.put("decisionMetadata", decisionMetadata);
        mutable.put("decisionAttributes", decisionAttributes);
        mutable.put("promptTelemetry", promptTelemetry);
        mutable.put("promptContexts", contamination.contexts());
        mutable.put("contaminationSummary", contamination.toMap());
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

    Map<String, Object> firstPresent(Map<String, Object>... sources) {
        for (Map<String, Object> source : sources) {
            if (source != null && !source.isEmpty()) {
                return source;
            }
        }
        return Map.of();
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

    ContaminationSummary summarizeContamination(String expectedUserId, Map<String, Object> promptPayload) {
        List<Map<String, Object>> contexts = contextItems(promptPayload);
        String expectedPurpose = OfficialVerificationRequestEvidenceValues.text(promptPayload, "retrievalPurpose");
        int foreignUserCount = 0;
        int purposeMismatchCount = 0;
        int scopeViolationCount = 0;
        int contaminatedIncludedCount = 0;
        int contaminatedCount = 0;
        for (Map<String, Object> context : contexts) {
            boolean foreignUser = foreignUser(context, expectedUserId);
            boolean purposeMismatch = purposeMismatch(context, expectedPurpose);
            boolean scopeViolation = accessScopeViolation(context, foreignUser);
            boolean contaminated = foreignUser || purposeMismatch || scopeViolation;
            if (foreignUser) {
                foreignUserCount++;
            }
            if (purposeMismatch) {
                purposeMismatchCount++;
            }
            if (scopeViolation) {
                scopeViolationCount++;
            }
            if (contaminated) {
                contaminatedCount++;
                if (booleanValue(context.get("includedInPrompt"))) {
                    contaminatedIncludedCount++;
                }
            }
        }
        return new ContaminationSummary(
                contexts,
                OfficialVerificationRequestEvidenceValues.integer(promptPayload, "requestedDocumentCount"),
                OfficialVerificationRequestEvidenceValues.integer(promptPayload, "allowedDocumentCount"),
                OfficialVerificationRequestEvidenceValues.integer(promptPayload, "deniedDocumentCount"),
                expectedPurpose,
                stringList(promptPayload, "deniedReasons"),
                contaminatedCount,
                foreignUserCount,
                purposeMismatchCount,
                scopeViolationCount,
                contaminatedIncludedCount
        );
    }

    private List<Map<String, Object>> contextItems(Map<String, Object> promptPayload) {
        Object rawContexts = promptPayload.get("contexts");
        if (!(rawContexts instanceof List<?> items) || items.isEmpty()) {
            return List.of();
        }
        List<Map<String, Object>> contexts = new ArrayList<>(items.size());
        for (Object item : items) {
            if (item instanceof Map<?, ?> rawMap) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                rawMap.forEach((key, value) -> {
                    if (key != null) {
                        normalized.put(String.valueOf(key), value);
                    }
                });
                contexts.add(normalized);
            }
        }
        return List.copyOf(contexts);
    }

    private boolean foreignUser(Map<String, Object> context, String expectedUserId) {
        String actualUserId = OfficialVerificationRequestEvidenceValues.text(context, "userId");
        return StringUtils.hasText(actualUserId)
                && StringUtils.hasText(expectedUserId)
                && !actualUserId.equalsIgnoreCase(expectedUserId);
    }

    private boolean purposeMismatch(Map<String, Object> context, String expectedPurpose) {
        if (context.containsKey("purposeMatch") && !booleanValue(context.get("purposeMatch"))) {
            return true;
        }
        String actualPurpose = OfficialVerificationRequestEvidenceValues.text(context, "retrievalPurpose");
        return StringUtils.hasText(actualPurpose)
                && StringUtils.hasText(expectedPurpose)
                && !actualPurpose.equalsIgnoreCase(expectedPurpose);
    }

    private boolean accessScopeViolation(Map<String, Object> context, boolean foreignUser) {
        String authorizationDecision = OfficialVerificationRequestEvidenceValues.text(context, "authorizationDecision");
        if (StringUtils.hasText(authorizationDecision)
                && ("DENIED_USER_SCOPE".equalsIgnoreCase(authorizationDecision)
                || "DENIED_ORGANIZATION_SCOPE".equalsIgnoreCase(authorizationDecision)
                || "DENIED_TENANT_SCOPE".equalsIgnoreCase(authorizationDecision))) {
            return true;
        }
        String accessScope = OfficialVerificationRequestEvidenceValues.text(context, "accessScope");
        return "USER".equalsIgnoreCase(accessScope) && foreignUser;
    }

    private boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String textValue) {
            return Boolean.parseBoolean(textValue.trim());
        }
        return false;
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

    String buildMessage(ContaminationSummary contamination, PromptContextAuditForwardingOutboxRecord promptOutbox) {
        if (promptOutbox == null) {
            return "CoR could not verify contamination because the prompt context audit payload was not captured.";
        }
        if (contamination.contaminatedCount() > 0) {
            return "CoR detected "
                    + contamination.contaminatedCount()
                    + " contaminated context candidates across "
                    + contamination.totalContextCount()
                    + " retrieved documents.";
        }
        return "CoR confirms that foreign-user, wrong-purpose, and unauthorized-scope documents do not contaminate the enterprise context path.";
    }

}
