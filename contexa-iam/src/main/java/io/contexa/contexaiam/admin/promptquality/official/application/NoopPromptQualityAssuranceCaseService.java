package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityCaseLineage;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityDependencyImpact;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class NoopPromptQualityAssuranceCaseService implements PromptQualityAssuranceCaseService {

    private final Map<String, PromptQualityAssuranceCase> cases = new ConcurrentHashMap<>();

    @Override
    public List<PromptQualityAssuranceCase> cases() {
        return List.copyOf(cases.values());
    }

    @Override
    public PromptQualityAssuranceCase recordEvidence(
            PromptQualityAssuranceScope scope,
            String bundleId,
            String summary) {
        return remember(scope, "EVIDENCE_CAPTURED", bundleId, null, 0, summary);
    }

    @Override
    public PromptQualityAssuranceCase recordVerification(
            PromptQualityAssuranceScope scope,
            String runId,
            int issueCount,
            String summary) {
        return remember(scope, issueCount > 0 ? "OFFICIAL_VERIFICATION_BLOCKED" : "OFFICIAL_VERIFICATION_PASSED", null, runId, issueCount, summary);
    }

    @Override
    public PromptQualityAssuranceCase recordCertificate(
            PromptQualityAssuranceScope scope,
            String certificateId,
            int issueCount,
            String summary) {
        return remember(scope, issueCount > 0 ? "CERTIFICATE_BLOCKED" : "CERTIFICATE_READY", null, null, issueCount, summary, certificateId);
    }

    @Override
    public PromptQualityAssuranceCase markReverifyRequired(
            PromptQualityAssuranceScope scope,
            String sourceType,
            String sourceRef,
            String reasonCode,
            String summary) {
        return remember(scope, "REVERIFY_REQUIRED", null, sourceRef, 1, summary);
    }

    @Override
    public PromptQualityAssuranceCase findCase(String caseId) {
        return cases.get(caseId);
    }

    @Override
    public PromptQualityAssuranceCase findCase(PromptQualityAssuranceScope scope) {
        return cases.get(caseId(scope));
    }

    @Override
    public PromptQualityCaseLineage lineage(String caseId) {
        return new PromptQualityCaseLineage(findCase(caseId), List.of());
    }

    @Override
    public List<PromptQualityDependencyImpact> impacts(String caseId) {
        return List.of();
    }

    private PromptQualityAssuranceCase remember(
            PromptQualityAssuranceScope scope,
            String stage,
            String bundleId,
            String runId,
            int issueCount,
            String summary) {
        return remember(scope, stage, bundleId, runId, issueCount, summary, null);
    }

    private PromptQualityAssuranceCase remember(
            PromptQualityAssuranceScope scope,
            String stage,
            String bundleId,
            String runId,
            int issueCount,
            String summary,
            String certificateId) {
        PromptQualityAssuranceScope safeScope = scope == null
                ? new PromptQualityAssuranceScope(null, null, null, null, null, null, null)
                : scope;
        String caseId = caseId(safeScope);
        String now = Instant.now().toString();
        PromptQualityAssuranceCase existing = cases.get(caseId);
        PromptQualityAssuranceCase value = new PromptQualityAssuranceCase(
                caseId,
                caseId,
                safeScope.tenantId(),
                safeScope.resourceUrl(),
                safeScope.resourceId(),
                safeScope.httpMethod(),
                safeScope.promptContractVersion(),
                safeScope.modelProfile(),
                safeScope.verifierVersion(),
                stage,
                issueCount > 0 ? "DIRTY" : "CLEAN",
                bundleId != null ? bundleId : existing == null ? null : existing.latestBundleId(),
                runId != null ? runId : existing == null ? null : existing.latestRunId(),
                certificateId != null ? certificateId : existing == null ? null : existing.latestCertificateId(),
                issueCount,
                summary,
                existing == null ? now : existing.createdAt(),
                now);
        cases.put(caseId, value);
        return value;
    }

    private String caseId(PromptQualityAssuranceScope scope) {
        if (scope == null) {
            return "default||||";
        }
        return String.join("|",
                value(scope.tenantId(), PromptQualityAssuranceScope.DEFAULT_TENANT_ID),
                value(scope.resourceUrl(), ""),
                value(scope.resourceId(), ""),
                value(scope.httpMethod(), PromptQualityAssuranceScope.DEFAULT_HTTP_METHOD),
                value(scope.promptContractVersion(), PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION));
    }

    private String value(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
