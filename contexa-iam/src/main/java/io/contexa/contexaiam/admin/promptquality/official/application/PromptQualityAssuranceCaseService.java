package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityCaseLineage;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityDependencyImpact;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public interface PromptQualityAssuranceCaseService {

    List<PromptQualityAssuranceCase> cases();

    PromptQualityAssuranceCase recordEvidence(
            PromptQualityAssuranceScope scope,
            String bundleId,
            String summary);

    PromptQualityAssuranceCase recordVerification(
            PromptQualityAssuranceScope scope,
            String runId,
            int issueCount,
            String summary);

    PromptQualityAssuranceCase recordCertificate(
            PromptQualityAssuranceScope scope,
            String certificateId,
            int issueCount,
            String summary);

    PromptQualityAssuranceCase markReverifyRequired(
            PromptQualityAssuranceScope scope,
            String sourceType,
            String sourceRef,
            String reasonCode,
            String summary);

    PromptQualityAssuranceCase findCase(String caseId);

    PromptQualityAssuranceCase findCase(PromptQualityAssuranceScope scope);

    PromptQualityCaseLineage lineage(String caseId);

    List<PromptQualityDependencyImpact> impacts(String caseId);

    default Map<String, List<PromptQualityDependencyImpact>> impactsByCaseIds(List<String> caseIds) {
        Map<String, List<PromptQualityDependencyImpact>> grouped = new LinkedHashMap<>();
        if (caseIds == null) {
            return grouped;
        }
        for (String caseId : caseIds) {
            if (!StringUtils.hasText(caseId) || grouped.containsKey(caseId.trim())) {
                continue;
            }
            grouped.put(caseId.trim(), impacts(caseId.trim()));
        }
        return grouped;
    }

    default PromptQualityAssuranceCase findLatestCaseByResource(
            String tenantId,
            String resourceUrl,
            String resourceId,
            String httpMethod) {
        PromptQualityAssuranceCase tenantMatch = cases().stream()
                .filter(item -> item != null)
                .filter(item -> equalsIgnoreCase(item.tenantId(), valueOrDefault(tenantId, PromptQualityAssuranceScope.DEFAULT_TENANT_ID)))
                .filter(item -> equalsIgnoreCase(item.resourceUrl(), resourceUrl))
                .filter(item -> equalsIgnoreCase(item.resourceId(), resourceId))
                .filter(item -> equalsIgnoreCase(item.httpMethod(), valueOrDefault(httpMethod, PromptQualityAssuranceScope.DEFAULT_HTTP_METHOD)))
                .findFirst()
                .orElse(null);
        if (tenantMatch != null) {
            return tenantMatch;
        }
        return cases().stream()
                .filter(item -> item != null)
                .filter(item -> equalsIgnoreCase(item.resourceUrl(), resourceUrl))
                .filter(item -> equalsIgnoreCase(item.resourceId(), resourceId))
                .filter(item -> equalsIgnoreCase(item.httpMethod(), valueOrDefault(httpMethod, PromptQualityAssuranceScope.DEFAULT_HTTP_METHOD)))
                .findFirst()
                .orElse(null);
    }

    private static boolean equalsIgnoreCase(String left, String right) {
        return valueOrDefault(left, "").toLowerCase(Locale.ROOT)
                .equals(valueOrDefault(right, "").toLowerCase(Locale.ROOT));
    }

    private static String valueOrDefault(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}
