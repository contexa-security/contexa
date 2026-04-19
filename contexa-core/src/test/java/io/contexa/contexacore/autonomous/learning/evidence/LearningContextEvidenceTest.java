package io.contexa.contexacore.autonomous.learning.evidence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LearningContextEvidenceTest {

    @Test
    @DisplayName("representative comparable should prefer evidence aligned to the strongest delta dimension")
    void representativeComparableShouldPreferStrongestDeltaDimension() {
        RetrievedBehaviorEvidence browserOnly = new RetrievedBehaviorEvidence(
                LearningEvidenceScope.PERSONAL,
                "alice",
                "behavior",
                "doc-browser",
                0.98d,
                "10.10.0.20",
                "CORPORATE",
                "/admin/api/security-test/sensitive/resource-001",
                null,
                "10",
                "1",
                "Chrome",
                "Windows",
                "PASSWORD",
                "READ",
                "SELF_PROFILE",
                "HIGH",
                "resource",
                "15",
                null,
                "browser aligned");
        RetrievedBehaviorEvidence pathAware = new RetrievedBehaviorEvidence(
                LearningEvidenceScope.PERSONAL,
                "alice",
                "behavior",
                "doc-path",
                0.91d,
                "10.10.0.20",
                "CORPORATE",
                "/admin/api/security-test/sensitive/resource-001",
                "/admin/api/security-test/*",
                "10",
                "1",
                "Chrome",
                "Windows",
                "PASSWORD",
                "READ",
                "SELF_PROFILE",
                "HIGH",
                "resource",
                "15",
                null,
                "path aligned");

        LearningContextEvidence evidence = new LearningContextEvidence(
                new CurrentLearningContextSnapshot("10", "1", "CORPORATE", "Chrome", "Windows", "/admin/api/security-test/*", "PASSWORD", "READ", "SELF_PROFILE"),
                emptyBaseline(LearningEvidenceScope.PERSONAL),
                emptyBaseline(LearningEvidenceScope.SUPPORTING),
                List.of(browserOnly, pathAware),
                List.of(),
                new ObservedPatternSnapshot(
                        List.of("CORPORATE"),
                        List.of("10"),
                        List.of("1"),
                        List.of("Chrome"),
                        List.of("Windows"),
                        List.of("/admin/api/security-test/*"),
                        List.of("PASSWORD"),
                        List.of("READ"),
                        List.of("SELF_PROFILE")),
                List.of(new CurrentVsObservedDeltaSnapshot(
                        "pathFamily",
                        "/admin/api/security-test/sensitive/*",
                        "/admin/api/security-test/*",
                        false,
                        "path family unseen in observed paths",
                        LearningEvidenceScope.PERSONAL)),
                List.of("CurrentPathPresentInObservedPaths"),
                List.of());

        assertThat(evidence.representativeComparable(evidence.strongestDelta())).isEqualTo(pathAware);
    }

    private BaselineEvidenceSnapshot emptyBaseline(LearningEvidenceScope scope) {
        return new BaselineEvidenceSnapshot(
                scope,
                false,
                false,
                0L,
                null,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "");
    }
}
