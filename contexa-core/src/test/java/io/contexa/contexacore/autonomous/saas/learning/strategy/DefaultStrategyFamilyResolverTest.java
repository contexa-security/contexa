package io.contexa.contexacore.autonomous.saas.learning.strategy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultStrategyFamilyResolverTest {

    private final DefaultStrategyFamilyResolver resolver = new DefaultStrategyFamilyResolver();

    @Test
    @DisplayName("resolver should classify post MFA surface jumps")
    void shouldResolvePostMfaSurfaceJump() {
        StrategyLearningObservation observation = observation(
                "FALSE_NEGATIVE",
                "BLOCK",
                "CONFIRMED_ATTACK",
                "MALICIOUS",
                true,
                2,
                0.05d,
                0.20d,
                0.10d,
                List.of("credential_reuse"),
                Map.of(
                        "pathCategory", "sensitive_data",
                        "requestPath", "/admin/export/report",
                        "reasonCategory", "MFA_VERIFIED",
                        "isSensitiveResource", true));

        StrategyFamilyResolution resolution = resolver.resolve(observation);

        assertThat(resolution.strategyFamily()).isEqualTo(DefaultStrategyFamilyResolver.POST_MFA_SURFACE_JUMP);
        assertThat(resolution.resolutionFacts()).isNotEmpty();
    }

    @Test
    @DisplayName("resolver should classify initial request profile delta")
    void shouldResolveInitialRequestProfileDelta() {
        StrategyLearningObservation observation = observation(
                "FALSE_NEGATIVE",
                "BLOCK",
                "SESSION_TAKEOVER",
                "COMPROMISED",
                true,
                1,
                0.10d,
                0.20d,
                0.10d,
                List.of("new_device"),
                Map.of(
                        "pathCategory", "application",
                        "isNewDevice", true,
                        "personalBaselineEstablished", false,
                        "organizationBaselineEstablished", false));

        StrategyFamilyResolution resolution = resolver.resolve(observation);

        assertThat(resolution.strategyFamily()).isEqualTo(DefaultStrategyFamilyResolver.INITIAL_REQUEST_PROFILE_DELTA);
    }

    @Test
    @DisplayName("resolver should classify scope expansion sequence")
    void shouldResolveScopeExpansionSequence() {
        StrategyLearningObservation observation = observation(
                "CORRECT",
                "CHALLENGE",
                "REQUIRES_INVESTIGATION",
                "SUSPICIOUS",
                true,
                1,
                0.15d,
                0.18d,
                0.22d,
                List.of("privileged_flow"),
                Map.of(
                        "pathCategory", "administration",
                        "requestPath", "/admin/roles/export",
                        "isSensitiveResource", true,
                        "campaignThreatClasses", List.of("privilege_abuse")));

        StrategyFamilyResolution resolution = resolver.resolve(observation);

        assertThat(resolution.strategyFamily()).isEqualTo(DefaultStrategyFamilyResolver.SCOPE_EXPANSION_SEQUENCE);
    }

    @Test
    @DisplayName("resolver should classify path sequence divergence")
    void shouldResolvePathSequenceDivergence() {
        StrategyLearningObservation observation = observation(
                "FALSE_POSITIVE",
                "ALLOW",
                "REVIEWED_BENIGN",
                "BENIGN",
                true,
                3,
                0.12d,
                0.08d,
                0.17d,
                List.of("failed_login_burst"),
                Map.of(
                        "pathCategory", "authentication",
                        "requestPath", "/oauth/session/refresh",
                        "promptSectionSet", List.of("bridge"),
                        "omittedSections", List.of("reasoningMemory")));

        StrategyFamilyResolution resolution = resolver.resolve(observation);

        assertThat(resolution.strategyFamily()).isEqualTo(DefaultStrategyFamilyResolver.PATH_SEQUENCE_DIVERGENCE);
    }

    @Test
    @DisplayName("resolver should classify session entropy collapse when telemetry is elevated and evidence breadth is narrow")
    void shouldResolveSessionEntropyCollapse() {
        StrategyLearningObservation observation = observation(
                null,
                "CHALLENGE",
                null,
                null,
                false,
                0,
                0.44d,
                0.14d,
                0.24d,
                List.of(),
                Map.of(
                        "pathCategory", "administration",
                        "requestPath", "/admin/console"));

        StrategyFamilyResolution resolution = resolver.resolve(observation);

        assertThat(resolution.strategyFamily()).isEqualTo(DefaultStrategyFamilyResolver.SESSION_ENTROPY_COLLAPSE);
    }

    @Test
    @DisplayName("resolver should leave observations unresolved when signals are weak")
    void shouldRemainUnresolvedWhenSignalsAreWeak() {
        StrategyLearningObservation observation = observation(
                "CORRECT",
                "ALLOW",
                null,
                null,
                false,
                0,
                0.01d,
                0.00d,
                0.01d,
                List.of(),
                Map.of(
                        "pathCategory", "application",
                        "requestPath", "/profile"));

        StrategyFamilyResolution resolution = resolver.resolve(observation);

        assertThat(resolution.isResolved()).isFalse();
    }

    private StrategyLearningObservation observation(
            String feedbackType,
            String finalAction,
            String outcomeType,
            String finalDisposition,
            boolean promptAuditLinked,
            int deniedContextCount,
            double layer1EscalationRate,
            double blockRate,
            double challengeRate,
            List<String> signalKeys,
            Map<String, Object> strategySignals) {
        return new StrategyLearningObservation(
                "corr",
                feedbackType,
                "ALLOW",
                finalAction,
                outcomeType,
                finalDisposition,
                2,
                promptAuditLinked,
                deniedContextCount,
                true,
                layer1EscalationRate,
                blockRate,
                challengeRate,
                false,
                signalKeys,
                strategySignals,
                List.of("evidence"));
    }
}
