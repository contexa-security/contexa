package io.contexa.contexacore.autonomous.exception;

import org.springframework.util.StringUtils;

import java.util.*;

public class ObjectiveResourceCompatibilityCatalog {

    private final Map<String, ObjectiveContract> contracts;

    public ObjectiveResourceCompatibilityCatalog() {
        this.contracts = buildContracts();
    }

    public boolean hasObjectiveContract(String objectiveFamily) {
        return contracts.containsKey(normalize(objectiveFamily));
    }

    public ObjectiveContract resolve(String objectiveFamily) {
        return contracts.getOrDefault(normalize(objectiveFamily), ObjectiveContract.unknown());
    }

    public boolean supportsAllowedOperations(String objectiveFamily, List<String> allowedOperations) {
        ObjectiveContract contract = resolve(objectiveFamily);
        if (!contract.known() || allowedOperations == null || allowedOperations.isEmpty()) {
            return true;
        }
        Set<String> normalizedAllowed = normalizeSet(allowedOperations);
        return normalizedAllowed.stream().allMatch(contract.allowedOperations()::contains);
    }

    public boolean supportsAllowedResourceFamilies(String objectiveFamily, List<String> allowedResourceFamilies) {
        ObjectiveContract contract = resolve(objectiveFamily);
        if (!contract.known() || allowedResourceFamilies == null || allowedResourceFamilies.isEmpty()) {
            return true;
        }
        Set<String> normalizedAllowed = normalizeSet(allowedResourceFamilies);
        return normalizedAllowed.stream().allMatch(contract.allowedResourceFamilies()::contains);
    }

    public String resolveOperation(String requestedOperation, String toolName, String argumentsSummary, String requiredScope) {
        if (StringUtils.hasText(requestedOperation)) {
            return canonicalizeOperation(requestedOperation);
        }
        String surface = join(toolName, argumentsSummary, requiredScope);
        if (containsAny(surface, "export", "dump", "download")) {
            return "EXPORT";
        }
        if (containsAny(surface, "block", "contain", "quarantine", "isolate")) {
            return "CONTAIN";
        }
        if (containsAny(surface, "delete")) {
            return "DELETE";
        }
        if (containsAny(surface, "reset")) {
            return "RESET";
        }
        if (containsAny(surface, "reconfigure")) {
            return "RECONFIGURE";
        }
        if (containsAny(surface, "disable", "revoke", "write", "update", "modify")) {
            return "MODIFY";
        }
        if (containsAny(surface, "ingest", "telemetry", "feedback", "outcome")) {
            return "INGEST";
        }
        if (containsAny(surface, "audit")) {
            return "AUDIT";
        }
        if (containsAny(surface, "retrieve", "pull")) {
            return "RETRIEVE";
        }
        if (containsAny(surface, "query", "search")) {
            return "QUERY";
        }
        return "READ";
    }

    public String resolveResourceFamily(
            String resourceFamily,
            String requiredScope,
            String toolName,
            String capability,
            String resourceFingerprint) {
        if (StringUtils.hasText(resourceFamily)) {
            return normalize(resourceFamily).toUpperCase(Locale.ROOT);
        }
        String surface = join(requiredScope, toolName, capability, resourceFingerprint);
        if (containsAny(surface, "prompt")) {
            return "PROMPT_CONTEXT";
        }
        if (containsAny(surface, "memory")) {
            return "MEMORY_CONTEXT";
        }
        if (containsAny(surface, "baseline-seed", "baseline_seed")) {
            return "BASELINE_SEED";
        }
        if (containsAny(surface, "baseline")) {
            return "BASELINE_SIGNAL";
        }
        if (containsAny(surface, "telemetry", "model")) {
            return "MODEL_TELEMETRY";
        }
        if (containsAny(surface, "decision", "xai", "feedback")) {
            return "DECISION_SIGNAL";
        }
        if (containsAny(surface, "outcome")) {
            return "THREAT_OUTCOME";
        }
        if (containsAny(surface, "execution")) {
            return "DELEGATED_EXECUTION";
        }
        if (containsAny(surface, "threat-knowledge", "threat_knowledge")) {
            return "THREAT_KNOWLEDGE";
        }
        if (containsAny(surface, "threat")) {
            return "THREAT_INTELLIGENCE";
        }
        if (containsAny(surface, "audit")) {
            return "AUDIT_LOG";
        }
        if (containsAny(surface, "export", "dump", "tenant-data", "tenant_data")) {
            return "TENANT_DATA";
        }
        if (containsAny(surface, "connector")) {
            return "CONNECTOR_CONFIGURATION";
        }
        if (containsAny(surface, "ip_block", "indicator", "network")) {
            return "NETWORK_INDICATOR";
        }
        return "SECURITY_RESOURCE";
    }

    public boolean isMutatingOperation(String operation) {
        return switch (canonicalizeOperation(operation)) {
            case "CONTAIN", "MODIFY", "DELETE", "RESET", "RECONFIGURE", "EXPORT" -> true;
            default -> false;
        };
    }

    public boolean isExportOperation(String operation) {
        return "EXPORT".equals(canonicalizeOperation(operation));
    }

    private String canonicalizeOperation(String operation) {
        if (!StringUtils.hasText(operation)) {
            return "READ";
        }
        return switch (normalize(operation).toUpperCase(Locale.ROOT)) {
            case "QUERY", "SEARCH" -> "QUERY";
            case "RETRIEVE", "FETCH", "PULL" -> "RETRIEVE";
            case "INGEST", "WRITE_INGEST" -> "INGEST";
            case "AUDIT" -> "AUDIT";
            case "EXPORT", "EXFIL" -> "EXPORT";
            case "BLOCK", "CONTAIN", "ISOLATE", "QUARANTINE" -> "CONTAIN";
            case "DELETE" -> "DELETE";
            case "RESET" -> "RESET";
            case "RECONFIGURE" -> "RECONFIGURE";
            case "WRITE", "UPDATE", "MODIFY", "DISABLE", "REVOKE" -> "MODIFY";
            default -> "READ";
        };
    }

    private Map<String, ObjectiveContract> buildContracts() {
        Map<String, ObjectiveContract> map = new LinkedHashMap<>();
        register(map, "READ_ONLY_INCIDENT_SUMMARY", Set.of("AUDIT_LOG", "SECURITY_RESOURCE"), Set.of("READ", "QUERY"), true, false, false, false);
        register(map, "INCIDENT_CONTAINMENT", Set.of("NETWORK_INDICATOR", "SECURITY_RESOURCE"), Set.of("READ", "CONTAIN"), false, true, false, false);
        register(map, "INCIDENT_RESPONSE", Set.of("NETWORK_INDICATOR", "AUDIT_LOG", "DECISION_SIGNAL", "SECURITY_RESOURCE"), Set.of("READ", "QUERY", "INGEST", "CONTAIN"), false, true, false, false);
        register(map, "THREAT_KNOWLEDGE_RUNTIME_REUSE", Set.of("THREAT_KNOWLEDGE"), Set.of("READ", "RETRIEVE"), true, false, false, false);
        register(map, "GLOBAL_THREAT_AWARENESS", Set.of("THREAT_INTELLIGENCE"), Set.of("READ", "RETRIEVE"), true, false, false, false);
        register(map, "BASELINE_SEED_BOOTSTRAP", Set.of("BASELINE_SEED"), Set.of("READ", "RETRIEVE"), true, false, false, false);
        register(map, "COHORT_BASELINE_BOOTSTRAP", Set.of("BASELINE_SEED"), Set.of("READ", "RETRIEVE"), true, false, false, false);
        register(map, "LEARNING_OUTCOME_INGEST", Set.of("SECURITY_DECISION", "DECISION_FEEDBACK", "THREAT_OUTCOME"), Set.of("INGEST"), false, false, true, false);
        register(map, "XAI_LEARNING_LOOP", Set.of("SECURITY_DECISION"), Set.of("INGEST"), false, false, true, false);
        register(map, "DECISION_FEEDBACK_LOOP", Set.of("DECISION_FEEDBACK"), Set.of("INGEST"), false, false, true, false);
        register(map, "THREAT_OUTCOME_LEARNING", Set.of("THREAT_OUTCOME"), Set.of("INGEST"), false, false, true, false);
        register(map, "COHORT_BASELINE_LEARNING", Set.of("BASELINE_SIGNAL"), Set.of("INGEST"), false, false, true, false);
        register(map, "BASELINE_SIGNAL_INGEST", Set.of("BASELINE_SIGNAL"), Set.of("INGEST"), false, false, true, false);
        register(map, "MODEL_OBSERVABILITY_INGEST", Set.of("MODEL_TELEMETRY"), Set.of("INGEST"), false, false, true, false);
        register(map, "MODEL_PERFORMANCE_OBSERVABILITY", Set.of("MODEL_TELEMETRY"), Set.of("INGEST"), false, false, true, false);
        register(map, "DELEGATED_EXECUTION_AUDIT", Set.of("DELEGATED_EXECUTION"), Set.of("INGEST", "AUDIT"), false, false, true, false);
        register(map, "PROMPT_CONTEXT_GOVERNANCE", Set.of("PROMPT_CONTEXT", "MEMORY_CONTEXT"), Set.of("INGEST", "AUDIT"), false, false, true, false);
        register(map, "PROMPT_CONTEXT_GOVERNANCE_AUDIT", Set.of("PROMPT_CONTEXT", "MEMORY_CONTEXT"), Set.of("INGEST", "AUDIT"), false, false, true, false);
        register(map, "TENANT_RUNTIME_SERVICE", Set.of("TENANT_RUNTIME_RESOURCE"), Set.of("READ", "INGEST", "AUDIT"), false, false, false, false);
        register(map, "TENANT_RUNTIME_EXECUTION", Set.of("TENANT_RUNTIME_RESOURCE"), Set.of("READ", "INGEST", "AUDIT"), false, false, false, false);
        register(map, "DIRECT_USER", Set.of("INTERACTIVE_RESOURCE"), Set.of("READ", "MODIFY", "CONTAIN"), false, false, false, true);
        return Map.copyOf(map);
    }

    private void register(
            Map<String, ObjectiveContract> map,
            String objectiveFamily,
            Set<String> allowedResourceFamilies,
            Set<String> allowedOperations,
            boolean readOnlyObjective,
            boolean containmentObjective,
            boolean learningObjective,
            boolean allowsPrivilegedExport) {
        map.put(normalize(objectiveFamily), new ObjectiveContract(
                true,
                normalizeSet(allowedResourceFamilies),
                normalizeSet(allowedOperations),
                readOnlyObjective,
                containmentObjective,
                learningObjective,
                allowsPrivilegedExport));
    }

    private Set<String> normalizeSet(List<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                normalized.add(normalize(value).toUpperCase(Locale.ROOT));
            }
        }
        return Set.copyOf(normalized);
    }

    private Set<String> normalizeSet(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                normalized.add(normalize(value).toUpperCase(Locale.ROOT));
            }
        }
        return Set.copyOf(normalized);
    }

    private boolean containsAny(String value, String... tokens) {
        if (!StringUtils.hasText(value) || tokens == null) {
            return false;
        }
        String normalized = normalize(value);
        for (String token : tokens) {
            if (StringUtils.hasText(token) && normalized.contains(normalize(token))) {
                return true;
            }
        }
        return false;
    }

    private String join(String... values) {
        if (values == null || values.length == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                if (!builder.isEmpty()) {
                    builder.append(' ');
                }
                builder.append(value.trim());
            }
        }
        return builder.toString();
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : "";
    }

    public record ObjectiveContract(
            boolean known,
            Set<String> allowedResourceFamilies,
            Set<String> allowedOperations,
            boolean readOnlyObjective,
            boolean containmentObjective,
            boolean learningObjective,
            boolean allowsPrivilegedExport) {

        public ObjectiveContract {
            allowedResourceFamilies = allowedResourceFamilies == null ? Set.of() : Set.copyOf(allowedResourceFamilies);
            allowedOperations = allowedOperations == null ? Set.of() : Set.copyOf(allowedOperations);
        }

        public static ObjectiveContract unknown() {
            return new ObjectiveContract(false, Set.of(), Set.of(), false, false, false, false);
        }
    }
}
