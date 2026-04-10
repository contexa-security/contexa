package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.execution.DelegatedExecutionContext;

import java.util.LinkedHashMap;
import java.util.Map;

public final class CanonicalExecutionEventMetadataSupport {

    private CanonicalExecutionEventMetadataSupport() {
    }

    public static Map<String, Object> enrich(Map<String, Object> payload) {
        Map<String, Object> metadata = payload == null ? new LinkedHashMap<>() : new LinkedHashMap<>(payload);
        String subjectType = firstNonBlank(
                text(metadata.get("executionSubjectType")),
                inferSubjectType(metadata));
        String executionMode = firstNonBlank(
                text(metadata.get("executionMode")),
                Boolean.TRUE.equals(resolveBoolean(metadata.get("delegated")))
                        ? DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT
                        : DelegatedExecutionContext.EXECUTION_MODE_DIRECT_USER);
        String lineageState = firstNonBlank(
                text(metadata.get("lineageState")),
                Boolean.TRUE.equals(resolveBoolean(metadata.get("delegated")))
                        ? DelegatedExecutionContext.LINEAGE_STATE_DECLARED
                        : DelegatedExecutionContext.LINEAGE_STATE_DIRECT);
        String protocolType = firstNonBlank(
                text(metadata.get("executionProtocolType")),
                text(metadata.get("protocolType")),
                text(metadata.get("sourceProtocol")),
                "UNKNOWN");

        metadata.putIfAbsent("executionSubjectType", subjectType);
        metadata.putIfAbsent("executionMode", executionMode);
        metadata.putIfAbsent("lineageState", lineageState);
        metadata.putIfAbsent("sourceProtocol", protocolType);

        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("subjectType", subjectType);
        subject.put("actorUserId", firstNonBlank(text(metadata.get("actorUserId")), text(metadata.get("userId"))));
        subject.put("agentId", text(metadata.get("agentId")));
        subject.put("tenantId", firstNonBlank(text(metadata.get("tenantId")), text(metadata.get("organizationId"))));
        subject.put("clientId", text(metadata.get("clientId")));
        metadata.putIfAbsent("canonicalExecutionSubject", Map.copyOf(subject));

        Map<String, Object> execution = new LinkedHashMap<>();
        execution.put("executionId", firstNonBlank(text(metadata.get("executionId")), text(metadata.get("requestId"))));
        execution.put("delegationId", text(metadata.get("delegationId")));
        execution.put("executionMode", executionMode);
        execution.put("lineageState", lineageState);
        execution.put("objectiveId", firstNonBlank(text(metadata.get("objectiveId")), text(metadata.get("taskPurpose"))));
        execution.put("objectiveFamily", text(metadata.get("objectiveFamily")));
        execution.put("taskIntent", text(metadata.get("taskIntent")));
        execution.put("taskPurpose", text(metadata.get("taskPurpose")));
        execution.put("approvedScopes", metadata.get("approvedScopes"));
        execution.put("allowedOperations", metadata.get("allowedOperations"));
        execution.put("allowedResourceFamilies", firstNonBlankCollection(metadata.get("allowedResourceFamilies"), metadata.get("allowedResources")));
        execution.put("allowedToolChain", metadata.get("allowedToolChain"));
        execution.put("permitId", text(metadata.get("permitId")));
        execution.put("approvalId", text(metadata.get("approvalId")));
        execution.put("protocolType", protocolType);
        metadata.putIfAbsent("canonicalExecution", Map.copyOf(execution));
        return metadata;
    }

    private static String inferSubjectType(Map<String, Object> metadata) {
        String actorType = text(metadata.get("actorType"));
        String principalType = text(metadata.get("principalType"));
        if (actorType != null && (actorType.contains("AGENT") || actorType.contains("DELEGATED"))) {
            return "AGENT_RUNTIME";
        }
        if (principalType != null && (principalType.toUpperCase().contains("SERVICE") || principalType.toUpperCase().contains("CLIENT") || principalType.toUpperCase().contains("WORKLOAD"))) {
            return "SERVICE_CLIENT";
        }
        if (Boolean.TRUE.equals(resolveBoolean(metadata.get("delegated"))) || text(metadata.get("agentId")) != null) {
            return "AGENT_RUNTIME";
        }
        if (text(metadata.get("clientId")) != null && Boolean.TRUE.equals(resolveBoolean(metadata.get("serviceClientPrincipal")))) {
            return "SERVICE_CLIENT";
        }
        return "HUMAN_USER";
    }

    private static Object firstNonBlankCollection(Object primary, Object fallback) {
        return primary != null ? primary : fallback;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private static Boolean resolveBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        String text = text(value);
        return text != null ? Boolean.parseBoolean(text) : null;
    }
}