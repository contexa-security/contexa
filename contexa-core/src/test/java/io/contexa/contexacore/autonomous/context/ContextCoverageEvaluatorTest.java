package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

class ContextCoverageEvaluatorTest {

    @Test
    @DisplayName("bridge가 있을 때 coverage 보고서는 bridge 근거와 빠진 컨텍스트를 함께 설명해야 한다")
    void evaluateShouldIncludeBridgeFactsInCoverageReport() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .roleSet(List.of("ANALYST"))
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .businessLabel("Customer Export Report")
                        .sensitivity("HIGH")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .bridge(CanonicalSecurityContext.Bridge.builder()
                        .coverageLevel("AUTHORIZATION_CONTEXT")
                        .authenticationSource("SECURITY_CONTEXT")
                        .authorizationSource("HEADER")
                        .delegationSource("REQUEST_ATTRIBUTE")
                        .missingContexts(List.of("DELEGATION"))
                        .build())
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("PERSONAL_WORK_PROFILE")
                        .provenanceSummary("collector=PROTECTABLE_WORK_PROFILE_COLLECTOR,window=7d,observations=3,daysCovered=1")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .qualityWarnings(List.of("Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent."))
                        .scopeLimitations(List.of("Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself."))
                        .build()))
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        // available/missing/warning이 동시에 나와야 LLM이 "무엇은 알고 무엇은 모르는지"를 구분할 수 있다.
        assertThat(report.availableFacts()).contains(
                "Bridge coverage metadata is available.",
                "Bridge authentication source is available.",
                "Bridge authorization source is available.",
                "Bridge delegation source is available.",
                "Context trust profile is available for PERSONAL_WORK_PROFILE.",
                "Context provenance summary: collector=PROTECTABLE_WORK_PROFILE_COLLECTOR,window=7d,observations=3,daysCovered=1");
        assertThat(report.missingCriticalFacts()).contains("Bridge missing context: DELEGATION.");
        assertThat(report.remediationHints()).contains("Attach peer cohort deltas through enterprise cohort enrichment when available.");
        assertThat(report.confidenceWarnings()).contains(
                "Peer cohort delta is missing; cohort-based deviation claims should remain conservative.",
                "Context evidence for PERSONAL_WORK_PROFILE is thin, fallback-heavy, or comparison-incomplete; do not use it as a standalone reasoning anchor.",
                "Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent.",
                "Scope limitation: Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself.");
        assertThat(report.summary()).contains("Bridge coverage: AUTHORIZATION_CONTEXT.");
    }

    @Test
    @DisplayName("얇은 개인 work profile은 미수집이 아니라 잠정 근거로 표시되어야 한다")
    void evaluateShouldTreatThinWorkProfileAsProvisionalInsteadOfUnavailable() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitivity("HIGH")
                        .build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Observed protectable resources /api/customer/list")
                        .frequentProtectableResources(List.of("/api/customer/list"))
                        .build())
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("PERSONAL_WORK_PROFILE")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .overallQualityScore(42)
                        .qualityWarnings(List.of("Work profile baseline is thin; treat pattern claims as provisional until more allowed observations accumulate."))
                        .build()))
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        // 얇은 profile을 unavailable로 찍으면 2차 3차 회차에서 학습이 진행되는 흐름을 설명할 수 없게 된다.
        assertThat(report.availableFacts()).contains("Personal work profile evidence is available but provisional.");
        assertThat(report.missingCriticalFacts()).doesNotContain("Personal work profile is unavailable.");
        assertThat(report.confidenceWarnings())
                .anyMatch(value -> value.contains("Personal work profile exists but remains thin"));
    }

    @Test
    @DisplayName("명시적 인가 사실이 없으면 role scope는 비교 근거로만 표현되어야 한다")
    void evaluateShouldDescribeRoleScopeAsComparisonEvidenceWhenExplicitAuthorizationFactsAreMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitivity("HIGH")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Current action family READ under observed protectable scope.")
                        .currentActionFamily("READ")
                        .build())
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        // role scope를 실제 authorization처럼 과장하면 모델이 허용 범위를 오해하게 된다.
        assertThat(report.availableFacts())
                .contains("Role scope comparison evidence is available, but explicit authorization facts are still partial.");
        assertThat(report.confidenceWarnings())
                .anyMatch(value -> value.contains("explicit authorization facts"));
    }

    @Test
    @DisplayName("scope가 있어도 authorization effect가 비어 있으면 coverage는 보수적으로 남아야 한다")
    void evaluateShouldKeepAuthorizationCoverageConservativeWhenEffectIsMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .authorizationEffect("UNKNOWN")
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitivity("HIGH")
                        .build())
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        // effect가 UNKNOWN인데 available로 단정하면 bridge 품질을 실제보다 높게 보고하게 된다.
        assertThat(report.availableFacts())
                .contains("Authorization scope evidence is available, but authorization effect is still partial.");
        assertThat(report.missingCriticalFacts())
                .contains("Authorization effect is unavailable.");
        assertThat(report.confidenceWarnings())
                .anyMatch(value -> value.contains("authorization effect"));
    }

    @Test
    @DisplayName("bridge 자체가 없으면 coverage 보고서는 이를 명시적으로 실패 근거로 남겨야 한다")
    void evaluateShouldFlagMissingBridgeContext() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .mfaVerified(true)
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .scopeTags(List.of("customer_data"))
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .sensitivity("HIGH")
                        .build())
                .build();

        ContextCoverageReport report = new ContextCoverageEvaluator().evaluate(context);

        // bridge 부재는 고객 컨텍스트 수집 실패이므로 숨기지 말고 직접 드러나야 한다.
        assertThat(report.missingCriticalFacts())
                .contains("Bridge-derived identity and authorization context is unavailable.");
        assertThat(report.remediationHints())
                .contains("Ensure bridge resolution remains active and propagates authentication, authorization, and request context before LLM evaluation.");
    }
}
