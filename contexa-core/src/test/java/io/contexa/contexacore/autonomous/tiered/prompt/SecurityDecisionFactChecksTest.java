package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W4-8 (S-28, VR-5): the boundaries of the v20 system text, the reason claims and the reason codes of dictionary 5,
 * checked on the canonical context the prompt was drawn from and on what the prompt drew. Each boundary is pointed at
 * when it should be and only then (the plan row's boundary contract tests).
 */
class SecurityDecisionFactChecksTest {

    private static final String SESSION = """
            === SESSION (host; time zone UTC) ===
            LoginMethod: PASSWORD, MFA not verified
            FailedLogins: %s in last 10 min
            RecentRequests: %s recent requests
            """;
    private static final String REQUEST = """
            === REQUEST (host) ===
            ResourceClass: %s
            Device: Chrome/140 on WINDOWS
            """;

    @Test
    void theDrawnPromptGivesItsStatedEntriesItsLineIdsAndTheIdsOfItsUnknownLine() {
        DrawnPrompt prompt = DrawnPrompt.of(prompt(0, 3, "NORMAL", """
                [F1] AuthorizationEffect: ALLOW
                [F2] PolicySatisfied: yes — approval APR-1
                """, "not-integrated: [U1] ClientSignals, [U2] PeerCohort; unavailable-now: [U3] PastRecord (not retrieved, TIMEOUT)"));

        assertThat(prompt.stated()).contains("SESSION.LoginMethod", "REQUEST.ResourceClass",
                "DECISION_FACTS.PolicySatisfied", "UNKNOWN.Unknown");
        assertThat(prompt.lineIds()).containsEntry("F2", "DECISION_FACTS.PolicySatisfied");
        assertThat(prompt.unknownIds()).containsEntry("U1", "ClientSignals").containsEntry("U3", "PastRecord");
        assertThat(DrawnPrompt.of("Plain v19 text\nAuthorizationEffect: ALLOW").stated()).isEmpty();
    }

    /** Two corroborated categories form the BLOCK boundary; a category whose line is not drawn states nothing. */
    @Test
    void twoCorroboratedCategoriesRequireBlockOnTheStatedLinesOnly() {
        CanonicalSecurityContext context = context(150, 120, "NORMAL", facts(List.of()));
        context.getDevice().setFingerprintMatch(false);
        DrawnPrompt drawn = DrawnPrompt.of(prompt(150, 120, "NORMAL", "[F1] AuthorizationEffect: ALLOW\n", null)
                .replace("Device: Chrome/140 on WINDOWS", "Device: Chrome/140 on WINDOWS (fingerprint does not match)"));

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "CHALLENGE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "BLOCK")).isNull();

        DrawnPrompt withoutTheFailures = DrawnPrompt.of(prompt(150, 120, "NORMAL", "[F1] AuthorizationEffect: ALLOW\n", null)
                .replace("FailedLogins: 150 in last 10 min\n", ""));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), withoutTheFailures, "BLOCK"))
                .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
    }

    /**
     * W5-10 D5: the RecentRequests line states the engine's count of the user's requests in the last 60 minutes beside
     * the host's count; either at the abuse count forms the request-rate category, as the line reads.
     */
    @Test
    void theEnginesCountOfTheLastHourFormsTheRequestRateCategoryAsTheHostsDoes() {
        CanonicalSecurityContext context = context(150, 3, "NORMAL", facts(List.of()));
        context.getDevice().setFingerprintMatch(false);
        context.setSessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                .userRequestsLastHour(120).build());
        DrawnPrompt drawn = DrawnPrompt.of(prompt(150, 3, "NORMAL", "[F1] AuthorizationEffect: ALLOW\n", null)
                .replace("Device: Chrome/140 on WINDOWS", "Device: Chrome/140 on WINDOWS (fingerprint does not match)"));

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "CHALLENGE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
    }

    /** One category is no BLOCK boundary, and the signal it names keeps the request from the low-risk boundary. */
    @Test
    void oneCategoryIsNoBlockBoundary() {
        CanonicalSecurityContext context = context(0, 3, "NORMAL", facts(List.of()));
        context.setIntent(CanonicalSecurityContext.Intent.builder().botUserAgent(true).build());
        DrawnPrompt drawn = DrawnPrompt.of(prompt(0, 3, "NORMAL", """
                [F1] AuthorizationEffect: ALLOW
                ClientSignals: bot UA: yes
                """, null));

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "BLOCK"))
                .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "CHALLENGE")).isNull();
    }

    @Test
    void aNegativeAuthorizationOrATenantConflictRequiresBlock() {
        CanonicalSecurityContext denied = context(0, 3, "NORMAL", facts(List.of()));
        denied.getAuthorization().setAuthorizationEffect("DENY");
        DrawnPrompt deniedPrompt = DrawnPrompt.of(prompt(0, 3, "NORMAL", "[F1] AuthorizationEffect: DENY\n", null));
        CanonicalSecurityContext conflicting = context(0, 3, "NORMAL", facts(List.of(
                fact("DataConflicts", "tenantId (request tenant-a, account tenant-b)", "TENANT_CONFLICT"))));
        DrawnPrompt conflictPrompt = DrawnPrompt.of(prompt(0, 3, "NORMAL", """
                [F1] AuthorizationEffect: ALLOW
                [F2] DataConflicts: tenantId (request tenant-a, account tenant-b)
                """, null));

        assertThat(SecurityDecisionFactChecks.boundaryViolation(denied, denied.getDecisionFacts(), deniedPrompt, "CHALLENGE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(conflicting, conflicting.getDecisionFacts(), conflictPrompt, "ESCALATE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
    }

    /** ALLOW, a class below SENSITIVE and no adverse fact require ALLOW, unverified MFA notwithstanding. */
    @Test
    void theLowRiskBoundaryRequiresAllowAndOnlyWithoutAnAdverseFact() {
        String allow = "[F1] AuthorizationEffect: ALLOW\n";
        CanonicalSecurityContext plain = context(0, 3, "NORMAL", facts(List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(plain, plain.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "NORMAL", allow, null)),
                "CHALLENGE")).isEqualTo(SecurityDecisionFactChecks.REQUIRED_LOW_RISK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(plain, plain.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "NORMAL", allow, null)),
                "ALLOW")).isNull();

        CanonicalSecurityContext sensitive = context(0, 3, "SENSITIVE", facts(List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(sensitive, sensitive.getDecisionFacts(),
                DrawnPrompt.of(prompt(0, 3, "SENSITIVE", allow, null)), "CHALLENGE")).isNull();

        CanonicalSecurityContext different = context(0, 3, "NORMAL", new DecisionFacts(List.of(
                fact("DeviationsFromBaseline", "time 03 seen 0 of 25 (unexplained)", "DEVIATION_TIME")),
                List.of(unexplained(DeviationDimension.TIME)), PolicySatisfaction.UNKNOWN, List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(different, different.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "NORMAL",
                allow + "[F2] DeviationsFromBaseline: time 03 seen 0 of 25 (unexplained)\n", null)), "CHALLENGE")).isNull();

        CanonicalSecurityContext unmet = context(0, 3, "NORMAL", new DecisionFacts(List.of(), List.of(),
                new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(), "no approval", List.of()), List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(unmet, unmet.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "NORMAL", allow
                + "[F2] Policy: EXPORT_APPROVAL requires a covering approval\n[F3] PolicySatisfied: no — no approval\n",
                null)), "CHALLENGE")).isNull();

        CanonicalSecurityContext failed = context(1, 3, "NORMAL", facts(List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(failed, failed.getDecisionFacts(), DrawnPrompt.of(prompt(1, 3, "NORMAL", allow, null)),
                "CHALLENGE")).isNull();
    }

    /** A role scope difference on provisional evidence is no anomaly; on trusted evidence it is. */
    @Test
    void aProvisionalRoleScopeDifferenceIsNoAnomaly() {
        String lines = "[F1] AuthorizationEffect: ALLOW\n[F2] RoleScope: action READ outside the scope group's actions (EXPORT)\n";
        CanonicalSecurityContext provisional = scoped(ContextQualityGrade.WEAK);
        CanonicalSecurityContext trusted = scoped(ContextQualityGrade.STRONG);

        assertThat(SecurityDecisionFactChecks.boundaryViolation(provisional, provisional.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "NORMAL", lines,
                null)), "CHALLENGE")).isEqualTo(SecurityDecisionFactChecks.REQUIRED_LOW_RISK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(trusted, trusted.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "NORMAL", lines,
                null)), "CHALLENGE")).isNull();
    }

    /** Covered work requires ALLOW at any class, and only without an unexplained difference or another adverse fact. */
    @Test
    void theCoveredWorkBoundaryRequiresAllowAndOnlyWithoutAnAdverseFact() {
        String covered = """
                [F1] AuthorizationEffect: ALLOW
                [F2] Policy: EXPORT_APPROVAL requires a covering approval
                [F3] PolicySatisfied: yes — approval APR-1
                [F4] DeviationsFromBaseline: time 03 seen 0 of 25 (explained by APR-1)
                """;
        DecisionFacts explained = new DecisionFacts(List.of(fact("DeviationsFromBaseline",
                "time 03 seen 0 of 25 (explained by APR-1)", "DEVIATION_TIME")),
                List.of(new Deviation(DeviationDimension.TIME, "x", true, true, 0, 10, "y", Deviation.Explanation.EXPLAINED,
                        "APR-1")), new PolicySatisfaction(true, null, List.of("APR-1"), "approval APR-1", List.of()), List.of());
        CanonicalSecurityContext context = context(0, 3, "CRITICAL", explained);

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "CRITICAL", covered,
                null)), "CHALLENGE")).isEqualTo(SecurityDecisionFactChecks.REQUIRED_COVERED_WORK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "CRITICAL", covered,
                null)), "ALLOW")).isNull();
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), DrawnPrompt.of(prompt(0, 3, "CRITICAL",
                covered + "ThreatMatch: campaign C-7 matches the request\n", null)), "CHALLENGE")).isNull();

        DecisionFacts unexplainedToo = new DecisionFacts(explained.facts(), List.of(unexplained(DeviationDimension.TIME)),
                explained.policy(), List.of());
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context(0, 3, "CRITICAL", unexplainedToo), context(0, 3, "CRITICAL", unexplainedToo).getDecisionFacts(),
                DrawnPrompt.of(prompt(0, 3, "CRITICAL", covered, null)), "CHALLENGE")).isNull();
    }

    @Test
    void aReasonClaimTheStatedFactsContradictIsPointedAt() {
        CanonicalSecurityContext context = context(0, 3, "CRITICAL", facts(List.of()));
        DrawnPrompt drawn = DrawnPrompt.of(prompt(0, 3, "CRITICAL", "[F1] AuthorizationEffect: ALLOW\n", null));

        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn, "MFA verified and the export is routine."))
                .isEqualTo("FALSE_MFA_VERIFIED_CLAIM");
        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn, "A low sensitivity resource."))
                .isEqualTo("FALSE_LOW_SENSITIVITY_CLAIM");
        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn, "Authorization denied for this export."))
                .isEqualTo("FALSE_AUTHORIZATION_DENIED_CLAIM");
        assertThat(SecurityDecisionFactChecks.claimViolation(context,
                DrawnPrompt.of(prompt(0, 3, "CRITICAL", "", null).replace("LoginMethod: PASSWORD, MFA not verified\n", "")),
                "MFA verified.")).isNull();
    }

    /**
     * Plan 6-2: the claim kinds the v19 response check read on its labels are read by the engine on the context the
     * prompt states: a verified MFA called unverified, a normal resource called highly sensitive, and a negated claim,
     * which states nothing wrong.
     */
    @Test
    void aClaimOfAnUnverifiedMfaOrOfAHighSensitivityTheStatedFactsContradictIsPointedAt() {
        CanonicalSecurityContext context = context(0, 3, "NORMAL", facts(List.of()));
        context.getSession().setMfaVerified(true);
        DrawnPrompt drawn = DrawnPrompt.of(prompt(0, 3, "NORMAL", "[F1] AuthorizationEffect: ALLOW\n", null)
                .replace("LoginMethod: PASSWORD, MFA not verified", "LoginMethod: PASSWORD, MFA verified"));

        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn, "MFA is not verified for this request."))
                .isEqualTo("FALSE_MFA_UNVERIFIED_CLAIM");
        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn, "The resource has high sensitivity."))
                .isEqualTo("FALSE_HIGH_SENSITIVITY_CLAIM");
        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn,
                "Fresh verification is not required for this request.")).isNull();
        assertThat(SecurityDecisionFactChecks.claimViolation(context, drawn,
                "Authorization allows the normal request; MFA is verified.")).isNull();
    }

    private static String prompt(int failed, int recent, String resourceClass, String facts, String unknown) {
        return SESSION.formatted(failed, recent) + "\n" + REQUEST.formatted(resourceClass)
                + "\n=== DECISION FACTS (computed) ===\n" + facts
                + (unknown != null ? "\n=== UNKNOWN ===\nUnknown: " + unknown + "\n" : "");
    }

    private static CanonicalSecurityContext context(int failed, int recent, String resourceClass, DecisionFacts facts) {
        return CanonicalSecurityContext.builder()
                .session(CanonicalSecurityContext.Session.builder().mfaVerified(false).failedLoginAttempts(failed)
                        .failedLoginWindowMinutes(10).recentRequestCount(recent).build())
                .device(CanonicalSecurityContext.Device.builder().build())
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass(resourceClass).actionFamily("EXPORT")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder().authorizationEffect("ALLOW").build())
                .decisionFacts(facts)
                .build();
    }

    private static CanonicalSecurityContext scoped(ContextQualityGrade grade) {
        CanonicalSecurityContext context = context(0, 3, "NORMAL", facts(List.of(
                fact("RoleScope", "action READ outside the scope group's actions (EXPORT)", "ROLE_SCOPE_OUTSIDE"))));
        context.setRoleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                .currentActionFamily("READ").expectedActionFamilies(new ArrayList<>(List.of("EXPORT"))).build());
        context.setContextTrustProfiles(new ArrayList<>(List.of(ContextTrustProfile.builder()
                .profileKey("ROLE_SCOPE_PROFILE").overallQualityGrade(grade).build())));
        return context;
    }

    private static DecisionFacts facts(List<DecisionFact> facts) {
        return new DecisionFacts(facts, List.of(), PolicySatisfaction.UNKNOWN, List.of());
    }

    private static DecisionFact fact(String name, String value, String code) {
        return new DecisionFact(null, name, value, List.of(code), List.of(), DecisionFact.COMPUTED);
    }

    private static Deviation unexplained(DeviationDimension dimension) {
        return new Deviation(dimension, "x", true, true, 0, 10, "y", Deviation.Explanation.UNEXPLAINED, null);
    }

}
