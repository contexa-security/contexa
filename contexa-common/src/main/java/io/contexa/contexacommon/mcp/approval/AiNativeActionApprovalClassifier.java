package io.contexa.contexacommon.mcp.approval;

import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AiNativeActionApprovalClassifier {

    private static final Set<String> EXPORT_KEYWORDS = Set.of(
            "export",
            "download",
            "dump",
            "backup",
            "extract",
            "csv",
            "archive",
            "all tenant",
            "all user");
    private static final Set<String> EXPORT_RISK_FLAGS = Set.of(
            "BULK_EXPORT",
            "PRIVILEGED_EXPORT",
            "TENANT_FILTER_BYPASS",
            "CROSS_TENANT_EXPORT");
    private static final Set<String> CONNECTOR_KEYWORDS = Set.of(
            "connector",
            "integration",
            "webhook",
            "oauth",
            "client secret",
            "credential",
            "api key",
            "token",
            "endpoint",
            "reconfigure",
            "registration");
    private static final Set<String> DESTRUCTIVE_KEYWORDS = Set.of(
            "block",
            "quarantine",
            "disable",
            "delete",
            "remove",
            "revoke",
            "reset",
            "terminate",
            "rotate",
            "isolate");

    private AiNativeActionApprovalClassifier() {
    }

    public static AiNativeActionApprovalCategory classify(
            String toolName,
            String requiredScope,
            String executionClass,
            Collection<String> parameterRiskFlags,
            String toolArgumentsSummary) {
        String combined = normalize(toolName) + " " + normalize(requiredScope) + " " + normalize(toolArgumentsSummary);
        List<String> flags = parameterRiskFlags == null
                ? List.of()
                : parameterRiskFlags.stream()
                .filter(StringUtils::hasText)
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .toList();

        if (containsAny(flags, EXPORT_RISK_FLAGS) || containsAny(combined, EXPORT_KEYWORDS)) {
            return AiNativeActionApprovalCategory.PRIVILEGED_EXPORT;
        }
        if (containsAny(combined, CONNECTOR_KEYWORDS)) {
            return AiNativeActionApprovalCategory.CONNECTOR_RECONFIGURATION;
        }
        if (isMutating(executionClass) || containsAny(combined, DESTRUCTIVE_KEYWORDS)) {
            return AiNativeActionApprovalCategory.DESTRUCTIVE_TOOL;
        }
        return AiNativeActionApprovalCategory.STANDARD_MUTATION;
    }

    private static boolean isMutating(String executionClass) {
        return StringUtils.hasText(executionClass)
                && !"READ".equalsIgnoreCase(executionClass.trim())
                && !"QUERY".equalsIgnoreCase(executionClass.trim());
    }

    private static boolean containsAny(Collection<String> actualValues, Set<String> expectedValues) {
        return actualValues.stream().anyMatch(expectedValues::contains);
    }

    private static boolean containsAny(String source, Set<String> keywords) {
        return keywords.stream().anyMatch(source::contains);
    }

    private static String normalize(String value) {
        return StringUtils.hasText(value) ? value.toLowerCase(Locale.ROOT) : "";
    }
}