package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityCaseLineage;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityDependencyImpact;

import java.util.List;

/**
 * OSS boundary for the Enterprise-only assurance-case and resolution workflow.
 * Official verification results, issues, and snapshots remain persisted by their
 * dedicated OSS writers; this service deliberately exposes no resolution cases.
 */
public final class NoResolutionPromptQualityAssuranceCaseService
        implements PromptQualityAssuranceCaseService {

    @Override
    public List<PromptQualityAssuranceCase> cases() {
        return List.of();
    }

    @Override
    public PromptQualityAssuranceCase recordEvidence(
            PromptQualityAssuranceScope scope,
            String bundleId,
            String summary) {
        return null;
    }

    @Override
    public PromptQualityAssuranceCase recordVerification(
            PromptQualityAssuranceScope scope,
            String runId,
            int issueCount,
            String summary) {
        return null;
    }

    @Override
    public PromptQualityAssuranceCase recordCertificate(
            PromptQualityAssuranceScope scope,
            String certificateId,
            int issueCount,
            String summary) {
        return null;
    }

    @Override
    public PromptQualityAssuranceCase markReverifyRequired(
            PromptQualityAssuranceScope scope,
            String sourceType,
            String sourceRef,
            String reasonCode,
            String summary) {
        return null;
    }

    @Override
    public PromptQualityAssuranceCase findCase(String caseId) {
        return null;
    }

    @Override
    public PromptQualityAssuranceCase findCase(PromptQualityAssuranceScope scope) {
        return null;
    }

    @Override
    public PromptQualityCaseLineage lineage(String caseId) {
        return new PromptQualityCaseLineage(null, List.of());
    }

    @Override
    public List<PromptQualityDependencyImpact> impacts(String caseId) {
        return List.of();
    }
}
