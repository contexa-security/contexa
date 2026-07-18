package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationRapExecutionService.AuthorizationSummary;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationRapExecutionService.EndpointDefinition;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationRapExecutionService.RapCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationRapExecutionService.RapEventItem;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static io.contexa.contexacore.verification.runtime.request.OfficialVerificationRapExecutionService.*;

final class OfficialVerificationRapEvidenceFactory {
    List<RapCheckResult> buildChecks(
            String requestId,
            Map<String, Object> invocation,
            Map<String, Object> decisionMetadata,
            Map<String, Object> promptPayload,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            AuthorizationSummary authorization
    ) {
        String responseRequestId = text(invocation, "requestId");
        String eventRequestId = text(decisionMetadata, "requestId", "correlationId");
        String promptCorrelationId = text(promptPayload, "correlationId");
        String promptOutboxCorrelationId = promptOutbox != null ? promptOutbox.getCorrelationId() : null;
        String promptAuditId = promptOutbox != null ? promptOutbox.getAuditId() : null;
        boolean countsAligned = authorization.totalContextCount() == authorization.requestedDocumentCount();
        boolean allowedDeniedAligned =
                authorization.totalContextCount() == authorization.allowedDocumentCount() + authorization.deniedDocumentCount();
        boolean denialSurfaced = authorization.deniedDocumentCount() == 0
                || !authorization.deniedReasons().isEmpty();
        return List.of(
                check("requestId matches probe response", value(requestId), pair(requestId, responseRequestId), sameValue(requestId, responseRequestId), "probe.response.requestId"),
                check("requestId matches decision event metadata", value(requestId), pair(requestId, eventRequestId), sameValue(requestId, eventRequestId), "analysis.events[DECISION_APPLIED].metadata.requestId"),
                check("requestId matches prompt audit correlationId", value(requestId), pair(requestId, promptCorrelationId), sameValue(requestId, promptCorrelationId), "promptAuditPayload.correlationId"),
                check("prompt audit outbox correlation is preserved", value(requestId), pair(requestId, promptOutboxCorrelationId), sameValue(requestId, promptOutboxCorrelationId), "promptAuditOutbox.correlationId"),
                check("prompt audit record exists", "present", value(promptAuditId), StringUtils.hasText(promptAuditId), "promptAuditOutbox.auditId"),
                check("context ledger size matches requestedDocumentCount", String.valueOf(authorization.requestedDocumentCount()), String.valueOf(authorization.totalContextCount()), countsAligned, "promptAuditPayload.contexts"),
                check("allowed and denied counts reconcile with context ledger", String.valueOf(authorization.totalContextCount()), String.valueOf(authorization.allowedDocumentCount() + authorization.deniedDocumentCount()), allowedDeniedAligned, "promptAuditPayload.allowedDocumentCount/deniedDocumentCount"),
                check("included contexts match allowedDocumentCount", String.valueOf(authorization.allowedDocumentCount()), String.valueOf(authorization.includedCount()), authorization.includedCount() == authorization.allowedDocumentCount(), "promptAuditPayload.contexts.includedInPrompt"),
                check("denied contexts are excluded from prompt", "0", String.valueOf(authorization.deniedIncludedCount()), authorization.deniedIncludedCount() == 0, "promptAuditPayload.contexts.includedInPrompt"),
                check("allowed contexts carry ALLOWED_* decisions", String.valueOf(authorization.allowedDocumentCount()), String.valueOf(authorization.allowedDecisionCount()), authorization.allowedDecisionCount() == authorization.allowedDocumentCount(), "promptAuditPayload.contexts.authorizationDecision"),
                check("denied contexts carry DENIED_* decisions", String.valueOf(authorization.deniedDocumentCount()), String.valueOf(authorization.deniedDecisionCount()), authorization.deniedDecisionCount() == authorization.deniedDocumentCount(), "promptAuditPayload.contexts.authorizationDecision"),
                check("denied reasons are captured when denials exist", "true", denialSurfaced ? "true" : "false", denialSurfaced, "promptAuditPayload.deniedReasons"),
                check("authorization precision meets official threshold", ">=95.0", String.format(Locale.ROOT, "%.2f", authorization.authorizationPrecision()), authorization.authorizationPrecision() >= 95.0d, "promptAuditPayload.allowedDocumentCount/requestedDocumentCount")
        );
    }

    private RapCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new RapCheckResult(label, value(expected), value(actual), pass, source);
    }

    Map<String, String> buildRequestFacts(
            EndpointDefinition endpoint,
            String userId,
            String requestId,
            Map<String, Object> invocation,
            int requestedRunCount,
            boolean rerun,
            boolean authorizationSeed,
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
        facts.put("authorizationSeed", authorizationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, CONTRACT_STATUS);
    }
    RapEventItem toRapEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new RapEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    Map<String, String> buildRapEventFacts(
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            Map<String, Object> decisionMetadata
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("eventCount", String.valueOf(events.size()));
        facts.put("firstEvent", events.isEmpty() ? "absent" : value(events.get(0).type()));
        facts.put("lastEvent", events.isEmpty() ? "absent" : value(events.get(events.size() - 1).type()));
        facts.put("decisionEventPresent", Boolean.toString(events.stream().anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()))));
        facts.put("requestId", value(text(decisionMetadata, "requestId", "correlationId")));
        facts.put("correlationId", value(text(decisionMetadata, "correlationId", "requestId")));
        facts.put("requestPath", value(text(decisionMetadata, "requestPath")));
        facts.put("promptRuntimeTelemetryLinked", value(text(decisionMetadata, "promptRuntimeTelemetryLinked")));
        facts.put("promptRuntimeTelemetryLayer", value(text(decisionMetadata, "promptRuntimeTelemetryLayer")));
        return facts;
    }

    Map<String, String> buildRapPromptFacts(
            Map<String, Object> promptTelemetry,
            Map<String, Object> promptPayload,
            AuthorizationSummary authorization
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("promptVersion", value(text(promptTelemetry, "promptVersion")));
        facts.put("promptHash", value(text(promptTelemetry, "promptHash")));
        facts.put("systemPromptHash", value(text(promptTelemetry, "systemPromptHash")));
        facts.put("userPromptHash", value(text(promptTelemetry, "userPromptHash")));
        facts.put("retrievalPurpose", value(authorization.retrievalPurpose()));
        facts.put("requestedDocumentCount", String.valueOf(authorization.requestedDocumentCount()));
        facts.put("allowedDocumentCount", String.valueOf(authorization.allowedDocumentCount()));
        facts.put("deniedDocumentCount", String.valueOf(authorization.deniedDocumentCount()));
        facts.put("contextLedgerCount", String.valueOf(authorization.totalContextCount()));
        facts.put("includedDocumentCount", String.valueOf(authorization.includedCount()));
        facts.put("allowedDecisionCount", String.valueOf(authorization.allowedDecisionCount()));
        facts.put("deniedDecisionCount", String.valueOf(authorization.deniedDecisionCount()));
        facts.put("deniedIncludedCount", String.valueOf(authorization.deniedIncludedCount()));
        facts.put("authorizationPrecision", String.format(Locale.ROOT, "%.2f", authorization.authorizationPrecision()));
        facts.put("promptAuditCorrelationId", value(text(promptPayload, "correlationId")));
        facts.put("promptAuditId", value(text(promptPayload, "auditId")));
        return facts;
    }

    Map<String, String> buildRapAnalysisFacts(
            Map<String, Object> decisionPayload,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> promptPayload,
            AuthorizationSummary authorization
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("decision", value(text(decisionPayload, "decision")));
        facts.put("outboxStatus", decisionOutbox != null ? value(decisionOutbox.getStatus()) : "absent");
        facts.put("decisionCorrelationId", decisionOutbox != null ? value(decisionOutbox.getCorrelationId()) : "absent");
        facts.put("promptAuditStatus", promptOutbox != null ? value(promptOutbox.getStatus()) : "absent");
        facts.put("promptAuditCorrelationId", promptOutbox != null ? value(promptOutbox.getCorrelationId()) : "absent");
        facts.put("promptAuditId", promptOutbox != null ? value(promptOutbox.getAuditId()) : "absent");
        facts.put("contextFingerprint", value(text(promptPayload, "contextFingerprint")));
        facts.put("authorizationPrecision", String.format(Locale.ROOT, "%.2f", authorization.authorizationPrecision()));
        facts.put("authorizationThresholdPassed", authorization.authorizationPrecision() >= 95.0d ? "true" : "false");
        facts.put("deniedReasons", authorization.deniedReasons().isEmpty() ? "none" : String.join(", ", authorization.deniedReasons()));
        return facts;
    }

    private Map<String, Object> buildRawEvidence(
            EndpointDefinition endpoint,
            String userId,
            int requestedRunCount,
            boolean rerun,
            boolean authorizationSeed,
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
                "authorizationSeed", authorizationSeed,
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

    Map<String, Object> buildRapRawEvidence(
            EndpointDefinition endpoint,
            String userId,
            int requestedRunCount,
            boolean rerun,
            boolean authorizationSeed,
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
            AuthorizationSummary authorization
    ) {
        Map<String, Object> evidence = buildRawEvidence(
                endpoint,
                userId,
                requestedRunCount,
                rerun,
                authorizationSeed,
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
        mutable.put("promptContexts", authorization.contexts());
        mutable.put("authorizationSummary", authorization.toMap());
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

    AuthorizationSummary summarizeAuthorization(Map<String, Object> promptPayload) {
        List<Map<String, Object>> contexts = contextItems(promptPayload);
        int includedCount = 0;
        int allowedDecisionCount = 0;
        int deniedDecisionCount = 0;
        int deniedIncludedCount = 0;
        for (Map<String, Object> context : contexts) {
            boolean included = booleanValue(context.get("includedInPrompt"));
            String authorizationDecision = text(context, "authorizationDecision");
            if (included) {
                includedCount++;
            }
            if (StringUtils.hasText(authorizationDecision) && authorizationDecision.startsWith("ALLOWED_")) {
                allowedDecisionCount++;
            }
            if (StringUtils.hasText(authorizationDecision) && authorizationDecision.startsWith("DENIED_")) {
                deniedDecisionCount++;
                if (included) {
                    deniedIncludedCount++;
                }
            }
        }
        return new AuthorizationSummary(
                contexts,
                integer(promptPayload, "requestedDocumentCount"),
                integer(promptPayload, "allowedDocumentCount"),
                integer(promptPayload, "deniedDocumentCount"),
                text(promptPayload, "retrievalPurpose"),
                stringList(promptPayload, "deniedReasons"),
                includedCount,
                allowedDecisionCount,
                deniedDecisionCount,
                deniedIncludedCount
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

    private boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String textValue) {
            return Boolean.parseBoolean(textValue.trim());
        }
        return false;
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

    String buildMessage(AuthorizationSummary authorization, PromptContextAuditForwardingOutboxRecord promptOutbox) {
        if (promptOutbox == null) {
            return "RAP could not verify authorization because the prompt context audit payload was not captured.";
        }
        if (authorization.authorizationPrecision() < 95.0d) {
            return "RAP detected insufficient authorization precision across the retrieved document candidates.";
        }
        return "RAP confirms that only authorized retrieved documents survive into the enterprise prompt context.";
    }

}
