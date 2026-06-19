/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.hcad.promotion;

import io.contexa.contexacore.hcad.projection.HcadFieldProvenance;
import io.contexa.contexacore.hcad.projection.HcadBaselineComparison;
import io.contexa.contexacore.hcad.projection.HcadTrustedSource;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HcadPreProtectablePromotionScorerTest {

    @Test
    @DisplayName("trusted impossible travel with trusted failed login and request burst should cross the redline")
    void score_trustedImpossibleTravelWithCorroborators_shouldBeEligible() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                false,
                List.of(),
                properties.getPreTrigger().getFailedLoginBurstThreshold(),
                properties.getPreTrigger().getRequestBurstThreshold(),
                true,
                false,
                0.9,
                Map.of(
                        "impossibleTravel", HcadFieldProvenance.present(
                                "impossibleTravel",
                                HcadTrustedSource.STORE_DERIVED,
                                "test"),
                        "failedLoginBurst", HcadFieldProvenance.present(
                                "failedLoginBurst",
                                HcadTrustedSource.STORE_DERIVED,
                                "test"),
                        "requestBurst", HcadFieldProvenance.present(
                                "requestBurst",
                                HcadTrustedSource.STORE_DERIVED,
                                "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.eligible()).isTrue();
        assertThat(assessment.earlyAnalysisScore()).isGreaterThanOrEqualTo(properties.getPreTrigger().getRedlineScore());
        assertThat(assessment.anchorSignals()).contains("IMPOSSIBLE_TRAVEL", "FAILED_LOGIN_BURST");
        assertThat(assessment.corroboratingSignals()).contains("REQUEST_BURST");
        assertThat(assessment.band()).isEqualTo(HcadPreProtectablePromotionBand.REDLINE);
    }

    @Test
    @DisplayName("single weak signal should stay below the redline")
    void score_trustedSingleWeakSignal_shouldRemainLow() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                false,
                List.of(),
                0,
                properties.getPreTrigger().getRequestBurstThreshold(),
                false,
                false,
                0.9,
                Map.of("requestBurst", HcadFieldProvenance.present(
                        "requestBurst",
                        HcadTrustedSource.STORE_DERIVED,
                        "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.eligible()).isFalse();
        assertThat(assessment.band()).isEqualTo(HcadPreProtectablePromotionBand.LOW);
        assertThat(assessment.anchorSignals()).isEmpty();
    }

    @Test
    @DisplayName("recent permission changes and privileged authorization should cross the redline")
    void score_trustedPermissionChangeWithPrivilegedAuthorization_shouldBeEligible() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                true,
                List.of("ROLE_ADMIN granted to user-a"),
                0,
                properties.getPreTrigger().getRequestBurstThreshold(),
                false,
                false,
                0.9,
                Map.of(
                        "authorizationPrivileged", HcadFieldProvenance.present(
                                "authorizationPrivileged",
                                HcadTrustedSource.BRIDGE_VERIFIED,
                                "test"),
                        "recentPermissionChanges", HcadFieldProvenance.present(
                                "recentPermissionChanges",
                                HcadTrustedSource.STORE_DERIVED,
                                "test"),
                        "requestBurst", HcadFieldProvenance.present(
                                "requestBurst",
                                HcadTrustedSource.STORE_DERIVED,
                                "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.eligible()).isTrue();
        assertThat(assessment.anchorSignals()).contains("RECENT_PERMISSION_CHANGE", "PRIVILEGED_AUTHORIZATION");
        assertThat(assessment.rawSignalSnapshot())
                .containsEntry("authorizationPrivileged", true)
                .containsKey("recentPermissionChanges");
    }

    @Test
    @DisplayName("fresh MFA requirement without fresh verification should cross the redline with privileged authorization")
    void score_trustedFreshMfaRequiredWithoutFreshMfaWithPrivilegedAuthorization_shouldBeEligible() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                true,
                List.of(),
                0,
                properties.getPreTrigger().getRequestBurstThreshold(),
                false,
                true,
                10_000L,
                0.9,
                Map.of(
                        "verificationRequired", HcadFieldProvenance.present(
                                "verificationRequired",
                                HcadTrustedSource.BRIDGE_VERIFIED,
                                "test"),
                        "authorizationPrivileged", HcadFieldProvenance.present(
                                "authorizationPrivileged",
                                HcadTrustedSource.BRIDGE_VERIFIED,
                                "test"),
                        "requestBurst", HcadFieldProvenance.present(
                                "requestBurst",
                                HcadTrustedSource.STORE_DERIVED,
                                "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.eligible()).isTrue();
        assertThat(assessment.anchorSignals()).contains("FRESH_MFA_REQUIRED", "PRIVILEGED_AUTHORIZATION");
        assertThat(assessment.rawSignalSnapshot())
                .containsEntry("verificationRequired", true)
                .containsEntry("mfaFreshnessSeconds", 10_000L);
    }

    @Test
    @DisplayName("scorer must expose only trusted projection scoring")
    void score_shouldNotExposeLegacyHcadContextOverload() {
        assertThat(List.of(HcadPreProtectablePromotionScorer.class.getDeclaredMethods())
                .stream()
                .filter(method -> method.getName().equals("score"))
                .map(Method::getParameterTypes)
                .flatMap(Arrays::stream)
                .map(Class::getSimpleName))
                .containsExactly("TrustedHcadContextProjection");
    }

    @Test
    @DisplayName("anchor without corroborating signal should not be eligible")
    void score_trustedAnchorWithoutCorroborator_shouldNotBeEligible() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                true,
                List.of(),
                0,
                0,
                false,
                false,
                0.9,
                Map.of("authorizationPrivileged", HcadFieldProvenance.present(
                        "authorizationPrivileged",
                        HcadTrustedSource.BRIDGE_VERIFIED,
                        "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.anchorSignals()).contains("PRIVILEGED_AUTHORIZATION");
        assertThat(assessment.corroboratingSignals()).isEmpty();
        assertThat(assessment.eligible()).isFalse();
    }

    @Test
    @DisplayName("trusted anchor with corroborating signal should be eligible above redline")
    void score_trustedAnchorWithCorroborator_shouldBeEligible() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                true,
                List.of("ROLE_ADMIN granted"),
                0,
                properties.getPreTrigger().getRequestBurstThreshold(),
                false,
                false,
                0.9,
                Map.of(
                        "authorizationPrivileged", HcadFieldProvenance.present(
                                "authorizationPrivileged",
                                HcadTrustedSource.BRIDGE_VERIFIED,
                                "test"),
                        "recentPermissionChanges", HcadFieldProvenance.present(
                                "recentPermissionChanges",
                                HcadTrustedSource.STORE_DERIVED,
                                "test"),
                        "requestBurst", HcadFieldProvenance.present(
                                "requestBurst",
                                HcadTrustedSource.STORE_DERIVED,
                                "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.anchorSignals()).contains("PRIVILEGED_AUTHORIZATION", "RECENT_PERMISSION_CHANGE");
        assertThat(assessment.corroboratingSignals()).contains("REQUEST_BURST");
        assertThat(assessment.earlyAnalysisScore()).isGreaterThanOrEqualTo(properties.getPreTrigger().getRedlineScore());
        assertThat(assessment.eligible()).isTrue();
    }

    @Test
    @DisplayName("untrusted privileged flag should not become an HCAD anchor")
    void score_untrustedPrivilegedFlag_shouldNotAnchor() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        TrustedHcadContextProjection projection = trustedProjection(
                true,
                List.of(),
                0,
                properties.getPreTrigger().getRequestBurstThreshold(),
                false,
                false,
                0.9,
                Map.of(
                        "authorizationPrivileged", HcadFieldProvenance.ignored(
                                "authorizationPrivileged",
                                "client supplied"),
                        "requestBurst", HcadFieldProvenance.present(
                                "requestBurst",
                                HcadTrustedSource.STORE_DERIVED,
                                "test")));

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.anchorSignals()).doesNotContain("PRIVILEGED_AUTHORIZATION");
        assertThat(assessment.eligible()).isFalse();
    }

    @Test
    @DisplayName("trusted material baseline mismatch should corroborate but not anchor")
    void score_materialBaselineMismatch_shouldOnlyCorroborate() {
        HcadProperties properties = new HcadProperties();
        HcadPreProtectablePromotionScorer scorer = new HcadPreProtectablePromotionScorer(properties);
        Map<String, HcadFieldProvenance> provenance = Map.of(
                "baselineComparison", HcadFieldProvenance.present(
                        "baselineComparison",
                        HcadTrustedSource.STORE_DERIVED,
                        "test"),
                "authorizationPrivileged", HcadFieldProvenance.present(
                        "authorizationPrivileged",
                        HcadTrustedSource.BRIDGE_VERIFIED,
                        "test"));
        HcadBaselineComparison comparison = new HcadBaselineComparison(
                true,
                true,
                25L,
                20,
                5,
                3,
                0.40d,
                true,
                List.of("accessDay", "browser"),
                List.of("ipRange", "pathFamily", "authenticationType"),
                List.of(),
                Map.of("pathFamily", "/admin/users"),
                Map.of("frequentPaths", List.of("/dashboard")));
        TrustedHcadContextProjection projection = trustedProjection(
                true,
                List.of(),
                0,
                0,
                false,
                false,
                10L,
                0.9,
                provenance,
                comparison);

        HcadPreProtectablePromotionAssessment assessment = scorer.score(projection);

        assertThat(assessment.anchorSignals()).contains("PRIVILEGED_AUTHORIZATION");
        assertThat(assessment.anchorSignals()).doesNotContain("BASELINE_MATERIAL_MISMATCH");
        assertThat(assessment.corroboratingSignals()).contains("BASELINE_MATERIAL_MISMATCH");
        assertThat(assessment.eligible()).isFalse();
        assertThat(assessment.rawSignalSnapshot()).containsKey("baselineComparison");
    }

    private TrustedHcadContextProjection trustedProjection(
            Boolean authorizationPrivileged,
            List<String> recentPermissionChanges,
            int failedLoginBurst,
            int requestBurst,
            boolean impossibleTravel,
            boolean verificationRequired,
            double baselineConfidence,
            Map<String, HcadFieldProvenance> provenance) {
        return trustedProjection(
                authorizationPrivileged,
                recentPermissionChanges,
                failedLoginBurst,
                requestBurst,
                impossibleTravel,
                verificationRequired,
                10L,
                baselineConfidence,
                provenance,
                HcadBaselineComparison.unavailable(20));
    }

    private TrustedHcadContextProjection trustedProjection(
            Boolean authorizationPrivileged,
            List<String> recentPermissionChanges,
            int failedLoginBurst,
            int requestBurst,
            boolean impossibleTravel,
            boolean verificationRequired,
            Long mfaFreshnessSeconds,
            double baselineConfidence,
            Map<String, HcadFieldProvenance> provenance) {
        return trustedProjection(
                authorizationPrivileged,
                recentPermissionChanges,
                failedLoginBurst,
                requestBurst,
                impossibleTravel,
                verificationRequired,
                mfaFreshnessSeconds,
                baselineConfidence,
                provenance,
                HcadBaselineComparison.unavailable(20));
    }

    private TrustedHcadContextProjection trustedProjection(
            Boolean authorizationPrivileged,
            List<String> recentPermissionChanges,
            int failedLoginBurst,
            int requestBurst,
            boolean impossibleTravel,
            boolean verificationRequired,
            Long mfaFreshnessSeconds,
            double baselineConfidence,
            Map<String, HcadFieldProvenance> provenance,
            HcadBaselineComparison baselineComparison) {
        return new TrustedHcadContextProjection(
                "alice",
                "tenant-1",
                "org-1",
                "session-1",
                "ctx-1",
                "GET",
                "/admin/reports",
                "203.0.113.10",
                "mfa",
                "high",
                true,
                mfaFreshnessSeconds,
                "policy-1",
                authorizationPrivileged,
                verificationRequired,
                recentPermissionChanges,
                failedLoginBurst,
                requestBurst,
                false,
                "/admin",
                impossibleTravel,
                baselineConfidence,
                true,
                baselineComparison,
                provenance,
                Map.of());
    }
}
