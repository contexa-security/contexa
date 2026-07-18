package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationEirExecutionService.EndpointDefinition;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationEirExecutionService.EirCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationEirExecutionService.EirEventItem;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.contexa.contexacore.verification.runtime.request.OfficialVerificationEirExecutionService.*;

final class OfficialVerificationEirEvidenceFactory {
    List<EirCheckResult> buildChecks(
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
    Map<String, String> buildEventFacts(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
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

    Map<String, String> buildPromptFacts(Map<String, Object> decisionPayload, Map<String, Object> promptPayload) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("Prompt key", value(text(decisionPayload, "promptKey")));
        facts.put("Template key", value(text(decisionPayload, "promptTemplateKey")));
        facts.put("Prompt hash", value(text(decisionPayload, "promptHash")));
        facts.put("System prompt hash", value(text(decisionPayload, "systemPromptHash")));
        facts.put("User prompt hash", value(text(decisionPayload, "userPromptHash")));
        facts.put("Retrieval purpose", value(text(promptPayload, "retrievalPurpose")));
        return facts;
    }

    Map<String, String> buildAnalysisFacts(
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

    EirEventItem toEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new EirEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    Map<String, Object> buildRawEvidence(
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
    boolean sameValue(String expected, String actual) {
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

}
