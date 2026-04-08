package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Expands baseline seed snapshots with first-sequence, session-band, and surface-transition priors.
 */
public class DefaultCohortSeedExpansionService implements CohortSeedExpansionService {

    private static final int DEFAULT_LIMIT = 5;

    @Override
    public CohortSeedPackSnapshot expand(CohortSeedExpansionInput input) {
        CohortSeedExpansionInput safeInput = input == null
                ? new CohortSeedExpansionInput(null, null, null, 0L, 0.0d, Map.of(), Map.of(), Map.of())
                : input;
        BaselineSeedSnapshot snapshot = safeInput.baselineSeedSnapshot();
        if (snapshot == null) {
            return CohortSeedPackSnapshot.empty();
        }

        CohortSeedQualificationDecision qualification = safeInput.qualificationDecision();
        return new CohortSeedPackSnapshot(
                snapshot.tenantId(),
                snapshot.featureEnabled(),
                snapshot.sharingEnabled(),
                snapshot.seedAvailable(),
                qualification.qualified(),
                cohortKey(snapshot, safeInput.sizeBand()),
                snapshot.industryCategory(),
                snapshot.region(),
                normalize(safeInput.sizeBand()),
                snapshot.cohortTenantCount(),
                snapshot.sampleUserBaselineCount(),
                qualification.supportLevel().name(),
                qualification.recommendedReleaseState().name(),
                safeInput.earlyAssessmentSampleCount(),
                safeInput.earlyQualityImprovementDelta(),
                snapshot.topAccessHours(),
                snapshot.topAccessDays(),
                snapshot.topOperatingSystems(),
                toDistributionItems(safeInput.firstSequenceFamilyDistribution()),
                toDistributionItems(safeInput.sessionLengthBandDistribution()),
                toDistributionItems(safeInput.surfaceTransitionPriorDistribution()),
                buildEvidenceFacts(snapshot, qualification, safeInput),
                LocalDateTime.now());
    }

    private List<CohortSeedPackSnapshot.DistributionItem> toDistributionItems(Map<String, Long> distribution) {
        if (distribution == null || distribution.isEmpty()) {
            return List.of();
        }
        return distribution.entrySet().stream()
                .filter(entry -> entry.getKey() != null && !entry.getKey().isBlank())
                .filter(entry -> entry.getValue() != null && entry.getValue() > 0L)
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(DEFAULT_LIMIT)
                .map(entry -> new CohortSeedPackSnapshot.DistributionItem(entry.getKey().trim(), entry.getValue()))
                .toList();
    }

    private List<String> buildEvidenceFacts(
            BaselineSeedSnapshot snapshot,
            CohortSeedQualificationDecision qualification,
            CohortSeedExpansionInput input) {
        return List.of(
                String.format(Locale.ROOT,
                        "Cohort %s/%s/%s has %d tenants and %d sampled user baselines.",
                        defaultText(snapshot.industryCategory(), "UNKNOWN"),
                        defaultText(snapshot.region(), "UNKNOWN"),
                        defaultText(input.sizeBand(), "UNKNOWN"),
                        snapshot.cohortTenantCount(),
                        snapshot.sampleUserBaselineCount()),
                String.format(Locale.ROOT,
                        "Qualification=%s supportLevel=%s earlyAssessmentSample=%d improvementDelta=%.1f.",
                        qualification.qualified(),
                        qualification.supportLevel().name(),
                        input.earlyAssessmentSampleCount(),
                        input.earlyQualityImprovementDelta()),
                String.format(Locale.ROOT,
                        "Expanded priors: firstSequenceFamilies=%d sessionLengthBands=%d surfaceTransitionPriors=%d.",
                        input.firstSequenceFamilyDistribution().size(),
                        input.sessionLengthBandDistribution().size(),
                        input.surfaceTransitionPriorDistribution().size()));
    }

    private String cohortKey(BaselineSeedSnapshot snapshot, String sizeBand) {
        String industry = normalize(snapshot.industryCategory());
        String region = normalize(snapshot.region());
        String size = normalize(sizeBand);
        return String.join("/", List.of(
                industry == null ? "general" : industry.toLowerCase(Locale.ROOT),
                region == null ? "global" : region.toLowerCase(Locale.ROOT),
                size == null ? "unspecified" : size.toLowerCase(Locale.ROOT)));
    }

    private String defaultText(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
