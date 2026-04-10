package io.contexa.contexacore.autonomous.saas.learning.strategy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class DetectionStrategyLearningServiceTest {

    @Test
    @DisplayName("detection strategy engine should aggregate strategy family effectiveness")
    void shouldAggregateStrategyFamilyEffectiveness() {
        StrategyOutcomeJoinService joinService = input -> List.of(
                new StrategyLearningObservation("c1", "CORRECT", "ALLOW", "BLOCK", "CONFIRMED_ATTACK", "MALICIOUS", 2, true, 1, true, 0.35d, 0.10d, 0.20d, true, List.of("signal-1"), Map.of(), List.of("attack evidence")),
                new StrategyLearningObservation("c2", "FALSE_POSITIVE", "CHALLENGE", "ALLOW", "REVIEWED_BENIGN", "BENIGN", 2, true, 0, false, 0.10d, 0.00d, 0.15d, false, List.of("signal-2"), Map.of(), List.of("benign review")),
                new StrategyLearningObservation("c3", "FALSE_NEGATIVE", "ALLOW", "ALLOW", "SESSION_TAKEOVER", "COMPROMISED", 1, false, 0, true, 0.42d, 0.20d, 0.10d, true, List.of("signal-3"), Map.of(), List.of("missed attack")));
        StrategyFamilyResolver resolver = observation -> switch (observation.correlationId()) {
            case "c1", "c2" -> new StrategyFamilyResolution("POST_MFA_SURFACE_JUMP", List.of("resolved from post-mfa pattern"));
            case "c3" -> new StrategyFamilyResolution("PATH_SEQUENCE_DIVERGENCE", List.of("resolved from path divergence"));
            default -> StrategyFamilyResolution.unresolved();
        };
        DetectionStrategyLearningService service = new DetectionStrategyLearningService(joinService, resolver);

        DetectionStrategyLearningPortfolio portfolio = service.evaluate(DetectionStrategyLearningInput.empty());

        assertThat(portfolio.totalObservationCount()).isEqualTo(3);
        assertThat(portfolio.classifiedObservationCount()).isEqualTo(3);
        assertThat(portfolio.unclassifiedObservationCount()).isEqualTo(0);
        assertThat(portfolio.families()).hasSize(2);
        DetectionStrategyLearningFamilyResult family = portfolio.families().stream()
                .filter(item -> "POST_MFA_SURFACE_JUMP".equals(item.strategyFamily()))
                .findFirst()
                .orElseThrow();
        assertThat(family.metrics().sampleSize()).isEqualTo(2);
        assertThat(family.outcomeEvidenceCount()).isEqualTo(2);
        assertThat(family.falsePositiveCount()).isEqualTo(1);
        assertThat(family.confirmedAttackCount()).isEqualTo(1);
        assertThat(family.metrics().outcomeCoverageRate()).isEqualTo(1.0d);
        assertThat(family.metrics().localLiftRate()).isCloseTo(-1.0d / 6.0d, within(0.0001d));
    }

    @Test
    @DisplayName("unclassified observations should remain outside family aggregates")
    void shouldTrackUnclassifiedObservations() {
        StrategyOutcomeJoinService joinService = input -> List.of(
                new StrategyLearningObservation("c1", "CORRECT", "ALLOW", "ALLOW", null, null, 1, false, 0, false, 0.0d, 0.0d, 0.0d, false, List.of(), Map.of(), List.of()));
        StrategyFamilyResolver resolver = observation -> StrategyFamilyResolution.unresolved();
        DetectionStrategyLearningService service = new DetectionStrategyLearningService(joinService, resolver);

        DetectionStrategyLearningPortfolio portfolio = service.evaluate(DetectionStrategyLearningInput.empty());

        assertThat(portfolio.totalObservationCount()).isEqualTo(1);
        assertThat(portfolio.classifiedObservationCount()).isZero();
        assertThat(portfolio.unclassifiedObservationCount()).isEqualTo(1);
        assertThat(portfolio.families()).isEmpty();
    }
}
