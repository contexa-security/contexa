package io.contexa.contexacore.std.components.prompt;

import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;

public final class PromptFieldPolicyCatalog {

    public static final String LLM_DECISION_CONTRACT = "LLM_DECISION_CONTRACT";
    public static final String LLM_DECISION_SUPPORTING = "LLM_DECISION_SUPPORTING";
    public static final String AUDIT_ONLY_SEALED_SOURCE = "AUDIT_ONLY_SEALED_SOURCE";
    public static final String INTERNAL_RUNTIME_ONLY = "INTERNAL_RUNTIME_ONLY";

    private static final PromptFieldPolicy AUDIT_ONLY = new PromptFieldPolicy(
            "SOURCE_STATE_CAPTURED",
            "ALWAYS_CAPTURE_SOURCE_STATE",
            "SEALED_SOURCE_ONLY",
            AUDIT_ONLY_SEALED_SOURCE,
            List.of(),
            "SOURCE_CONTEXT_PRODUCER",
            "",
            false);

    private static final PromptFieldPolicy INTERNAL_RUNTIME = new PromptFieldPolicy(
            "INTERNAL_RUNTIME_FIELD",
            "CAPTURED_FOR_TRACE_ONLY",
            "NOT_PROJECTED_TO_USER_PROMPT",
            INTERNAL_RUNTIME_ONLY,
            List.of(),
            "PLATFORM_RUNTIME",
            "Internal trace field is not part of the LLM decision contract.",
            false);

    private static final List<PolicyRule> RULES = List.of(
            rule(SourceType.PROMPT_PROJECTION_DIFF, FieldMatch.anyField(), contract("PROMPT_FIELD_CONTRACT", "PROMPT_ASSEMBLER", List.of("PFR", "MTR"))),

            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("CURRENT_REQUEST_AND_EVENT"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("CURRENT_REQUEST_AND_EVENT"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("BRIDGE_RESOLUTION_CONTEXT"), support("BRIDGE_CONTEXT_SUPPORTING", "CONTEXT_ASSEMBLER", List.of("CCR", "CCSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("BRIDGE_RESOLUTION_CONTEXT"), support("BRIDGE_CONTEXT_SUPPORTING", "CONTEXT_ASSEMBLER", List.of("CCR", "CCSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("CONTEXT_COVERAGE"), support("CONTEXT_COVERAGE_SUPPORTING", "CONTEXT_COVERAGE_PRODUCER", List.of("CCR", "CCSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("CONTEXT_COVERAGE"), support("CONTEXT_COVERAGE_SUPPORTING", "CONTEXT_COVERAGE_PRODUCER", List.of("CCR", "CCSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("IDENTITY_AND_ROLE_CONTEXT"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "PFR", "EIR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("IDENTITY_AND_ROLE_CONTEXT"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "PFR", "EIR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("AUTHENTICATION_AND_ASSURANCE_CONTEXT"), contract("AUTHENTICATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "EIR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("AUTHENTICATION_AND_ASSURANCE_CONTEXT"), contract("AUTHENTICATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "EIR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("DEVICE_CONTEXT"), contract("DEVICE_CONTEXT_REQUIRED", "DEVICE_CONTEXT_PRODUCER", List.of("USNS", "BSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("DEVICE_CONTEXT"), contract("DEVICE_CONTEXT_REQUIRED", "DEVICE_CONTEXT_PRODUCER", List.of("USNS", "BSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("LOCATION_CONTEXT"), contract("LOCATION_CONTEXT_REQUIRED", "LOCATION_CONTEXT_PRODUCER", List.of("USNS", "BSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("LOCATION_CONTEXT"), contract("LOCATION_CONTEXT_REQUIRED", "LOCATION_CONTEXT_PRODUCER", List.of("USNS", "BSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("REQUEST_INTENT_SIGNAL_CONTEXT"), support("REQUEST_INTENT_SUPPORTING", "REQUEST_CONTEXT_PRODUCER", List.of("BSR", "CCR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("REQUEST_INTENT_SIGNAL_CONTEXT"), support("REQUEST_INTENT_SUPPORTING", "REQUEST_CONTEXT_PRODUCER", List.of("BSR", "CCR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("RESOURCE_AND_ACTION_CONTEXT"), contract("RESOURCE_CONTEXT_REQUIRED", "RESOURCE_CONTEXT_PRODUCER", List.of("PRE", "CCR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("RESOURCE_AND_ACTION_CONTEXT"), contract("RESOURCE_CONTEXT_REQUIRED", "RESOURCE_CONTEXT_PRODUCER", List.of("PRE", "CCR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("SESSION_NARRATIVE_CONTEXT"), contract("BEHAVIOR_CONTEXT_REQUIRED", "BEHAVIOR_CONTEXT_PRODUCER", List.of("BSR", "USNS"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("SESSION_NARRATIVE_CONTEXT"), contract("BEHAVIOR_CONTEXT_REQUIRED", "BEHAVIOR_CONTEXT_PRODUCER", List.of("BSR", "USNS"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("PERSONAL_WORK_PROFILE"), contract("BASELINE_CONTEXT_REQUIRED", "BASELINE_CONTEXT_PRODUCER", List.of("BMA", "USNS"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("PERSONAL_WORK_PROFILE"), contract("BASELINE_CONTEXT_REQUIRED", "BASELINE_CONTEXT_PRODUCER", List.of("BMA", "USNS"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("ROLE_AND_WORK_SCOPE_CONTEXT"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "BSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("ROLE_AND_WORK_SCOPE_CONTEXT"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "BSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("FRICTION_AND_APPROVAL_HISTORY"), contract("BEHAVIOR_CONTEXT_REQUIRED", "BEHAVIOR_CONTEXT_PRODUCER", List.of("BSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("FRICTION_AND_APPROVAL_HISTORY"), contract("BEHAVIOR_CONTEXT_REQUIRED", "BEHAVIOR_CONTEXT_PRODUCER", List.of("BSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("DELEGATED_OBJECTIVE_CONTEXT"), contract("DELEGATED_OBJECTIVE_CONTEXT_REQUIRED", "DELEGATION_CONTEXT_PRODUCER", List.of("CCR", "BSR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("DELEGATED_OBJECTIVE_CONTEXT"), contract("DELEGATED_OBJECTIVE_CONTEXT_REQUIRED", "DELEGATION_CONTEXT_PRODUCER", List.of("CCR", "BSR"))),
            rule(SourceType.RAW_USER_PROMPT_FIELD, FieldMatch.section("EXPLICIT_MISSING_KNOWLEDGE"), contract("CONTEXT_GAP_DISCLOSURE_REQUIRED", "CONTEXT_ASSEMBLER", List.of("CCR"))),
            rule(SourceType.FINAL_USER_PROMPT_FIELD, FieldMatch.section("EXPLICIT_MISSING_KNOWLEDGE"), contract("CONTEXT_GAP_DISCLOSURE_REQUIRED", "CONTEXT_ASSEMBLER", List.of("CCR"))),

            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.requestId"), contract("REQUEST_TRACEABILITY", "REQUEST_CONTEXT_PRODUCER", List.of("MTR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.correlationId"), contract("REQUEST_TRACEABILITY", "REQUEST_CONTEXT_PRODUCER", List.of("MTR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.requestPath"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.httpMethod"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.resourceId"), contract("RESOURCE_CONTEXT_REQUIRED", "RESOURCE_CONTEXT_PRODUCER", List.of("PRE", "CCR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.tenantId"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.organizationId"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.authorizationEffect"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "PFR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.effectiveRoles"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "PFR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.effectivePermissions"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "PFR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.authenticationType"), contract("AUTHENTICATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.mfaVerified"), contract("AUTHENTICATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.metadata.currentAccessHour"), contract("BASELINE_CONTEXT_REQUIRED", "BASELINE_CONTEXT_PRODUCER", List.of("BMA", "USNS"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.userId"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.sessionId"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.sourceIp"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("securityEvent.userAgent"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("sessionContext"), contract("REQUEST_CONTEXT_REQUIRED", "REQUEST_CONTEXT_PRODUCER", List.of("CCR", "CCSR", "EIR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("behaviorAnalysis.personalBaselineEvidence"), contract("BASELINE_CONTEXT_REQUIRED", "BASELINE_CONTEXT_PRODUCER", List.of("BMA", "USNS"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("behaviorAnalysis.sessionNarrativeProfile"), contract("BEHAVIOR_CONTEXT_REQUIRED", "BEHAVIOR_CONTEXT_PRODUCER", List.of("BSR", "USNS"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("behaviorAnalysis.roleScopeProfile"), contract("AUTHORIZATION_CONTEXT_REQUIRED", "AUTH_CONTEXT_PRODUCER", List.of("CCR", "BSR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("behaviorAnalysis.frictionProfile"), contract("BEHAVIOR_CONTEXT_REQUIRED", "BEHAVIOR_CONTEXT_PRODUCER", List.of("BSR"))),
            rule(SourceType.SOURCE_CONTEXT, FieldMatch.path("relatedDocuments"), contract("RAG_AUTHORIZATION_CONTEXT_REQUIRED", "RAG_CONTEXT_PRODUCER", List.of("RAP", "CoR")))
    );

    private PromptFieldPolicyCatalog() {
    }

    public static PromptFieldPolicy resolve(
            String fieldKey,
            String sourceType,
            String sourceFieldPath,
            String promptLabel) {
        SourceType type = SourceType.from(sourceType);
        String normalizedFieldKey = normalize(fieldKey);
        String normalizedPath = normalize(sourceFieldPath);
        if (!StringUtils.hasText(normalizedFieldKey) && !StringUtils.hasText(normalizedPath)) {
            return AUDIT_ONLY;
        }
        if (internalRuntimeField(type, normalizedFieldKey, normalizedPath)) {
            return INTERNAL_RUNTIME;
        }
        for (PolicyRule rule : RULES) {
            if (rule.matches(type, normalizedFieldKey, normalizedPath)) {
                return rule.policy();
            }
        }
        return AUDIT_ONLY;
    }

    private static boolean internalRuntimeField(SourceType type, String fieldKey, String path) {
        if (type == SourceType.PROMPT_FIELD_STATE_LEDGER
                || type == SourceType.PROMPT_SOURCE_CONTEXT_LEDGER
                || type == SourceType.PROMPT_FINAL_USER_FIELD_LEDGER
                || type == SourceType.PROMPT_RAW_USER_FIELD_LEDGER
                || type == SourceType.PROMPT_USER_FIELD_DIFF_LEDGER) {
            return true;
        }
        return explicitPrefix(fieldKey,
                "PROMPTSOURCECONTEXTLEDGER",
                "PROMPTFIELDSTATELEDGER",
                "PROMPTFINALUSERFIELDLEDGER",
                "PROMPTRAWUSERFIELDLEDGER",
                "PROMPTUSERFIELDDIFFLEDGER")
                || explicitSuffix(path, "__TYPE__", "__DEPTHLIMIT__", "__CYCLE__", "__ERROR__", "_SIZE");
    }

    private static PromptFieldPolicy contract(String requiredPolicy, String remediationOwner, List<String> metrics) {
        return new PromptFieldPolicy(
                requiredPolicy,
                "APPLIES_TO_POST_AUTH_ZERO_TRUST_LLM_DECISION",
                "MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY",
                LLM_DECISION_CONTRACT,
                metrics,
                remediationOwner,
                "",
                true);
    }

    private static PromptFieldPolicy support(String requiredPolicy, String remediationOwner, List<String> metrics) {
        return new PromptFieldPolicy(
                requiredPolicy,
                "APPLIES_AS_LLM_DECISION_SUPPORTING_CONTEXT",
                "MAY_BE_SUMMARIZED_WITH_FULL_SOURCE_AND_REASON",
                LLM_DECISION_SUPPORTING,
                metrics,
                remediationOwner,
                "",
                true);
    }

    private static PolicyRule rule(SourceType type, FieldMatch match, PromptFieldPolicy policy) {
        return new PolicyRule(type, match, policy);
    }

    private static boolean explicitPrefix(String value, String... prefixes) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        for (String prefix : prefixes) {
            if (value.startsWith(normalize(prefix))) {
                return true;
            }
        }
        return false;
    }

    private static boolean explicitSuffix(String value, String... suffixes) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        for (String suffix : suffixes) {
            if (value.endsWith(normalize(suffix))) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String value) {
        return value == null
                ? ""
                : value.replaceAll("([a-z])([A-Z])", "$1_$2")
                .replaceAll("[^\\p{IsAlphabetic}\\p{IsDigit}]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "")
                .toUpperCase(Locale.ROOT);
    }

    private enum SourceType {
        SOURCE_CONTEXT,
        RAW_USER_PROMPT_FIELD,
        FINAL_USER_PROMPT_FIELD,
        PROMPT_PROJECTION_DIFF,
        PROMPT_FIELD_STATE_LEDGER,
        PROMPT_SOURCE_CONTEXT_LEDGER,
        PROMPT_FINAL_USER_FIELD_LEDGER,
        PROMPT_RAW_USER_FIELD_LEDGER,
        PROMPT_USER_FIELD_DIFF_LEDGER,
        OTHER;

        static SourceType from(String sourceType) {
            if (!StringUtils.hasText(sourceType)) {
                return OTHER;
            }
            String normalized = normalize(sourceType);
            for (SourceType type : values()) {
                if (type.name().equals(normalized)) {
                    return type;
                }
            }
            return SOURCE_CONTEXT;
        }
    }

    private record FieldMatch(String prefix, boolean matchesAny) {
        static FieldMatch anyField() {
            return new FieldMatch("", true);
        }

        static FieldMatch section(String sectionKey) {
            return new FieldMatch(normalize(sectionKey), false);
        }

        static FieldMatch path(String sourcePathPrefix) {
            return new FieldMatch(normalize(sourcePathPrefix), false);
        }

        boolean matches(String fieldKey, String sourcePath) {
            if (matchesAny) {
                return true;
            }
            return explicitPrefix(fieldKey, prefix)
                    || explicitPrefix(sourcePath, prefix)
                    || explicitPrefix(fieldKey,
                    "RAW_USER_PROMPT_FIELD_" + prefix,
                    "FINAL_USER_PROMPT_FIELD_" + prefix)
                    || explicitPrefix(sourcePath,
                    "RAW_USER_PROMPT_" + prefix,
                    "USER_PROMPT_" + prefix);
        }
    }

    private record PolicyRule(SourceType sourceType, FieldMatch match, PromptFieldPolicy policy) {
        boolean matches(SourceType candidateType, String fieldKey, String sourcePath) {
            return sourceType == candidateType && match.matches(fieldKey, sourcePath);
        }
    }
}
