package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.Outcome;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.ReasonFinding;
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

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, drawn, "CHALLENGE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, drawn, "BLOCK")).isNull();

        DrawnPrompt withoutTheFailures = DrawnPrompt.of(prompt(150, 120, "NORMAL", "[F1] AuthorizationEffect: ALLOW\n", null)
                .replace("FailedLogins: 150 in last 10 min\n", ""));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, withoutTheFailures, "BLOCK"))
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

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, drawn, "CHALLENGE"))
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

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, drawn, "BLOCK"))
                .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, drawn, "CHALLENGE")).isNull();
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

        assertThat(SecurityDecisionFactChecks.boundaryViolation(denied, deniedPrompt, "CHALLENGE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(conflicting, conflictPrompt, "ESCALATE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
    }

    /** ALLOW, a class below SENSITIVE and no adverse fact require ALLOW, unverified MFA notwithstanding. */
    @Test
    void theLowRiskBoundaryRequiresAllowAndOnlyWithoutAnAdverseFact() {
        String allow = "[F1] AuthorizationEffect: ALLOW\n";
        CanonicalSecurityContext plain = context(0, 3, "NORMAL", facts(List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(plain, DrawnPrompt.of(prompt(0, 3, "NORMAL", allow, null)),
                "CHALLENGE")).isEqualTo(SecurityDecisionFactChecks.REQUIRED_LOW_RISK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(plain, DrawnPrompt.of(prompt(0, 3, "NORMAL", allow, null)),
                "ALLOW")).isNull();

        CanonicalSecurityContext sensitive = context(0, 3, "SENSITIVE", facts(List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(sensitive,
                DrawnPrompt.of(prompt(0, 3, "SENSITIVE", allow, null)), "CHALLENGE")).isNull();

        CanonicalSecurityContext different = context(0, 3, "NORMAL", new DecisionFacts(List.of(
                fact("DeviationsFromBaseline", "time 03 seen 0 of 25 (unexplained)", "DEVIATION_TIME")),
                List.of(unexplained(DeviationDimension.TIME)), PolicySatisfaction.UNKNOWN, List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(different, DrawnPrompt.of(prompt(0, 3, "NORMAL",
                allow + "[F2] DeviationsFromBaseline: time 03 seen 0 of 25 (unexplained)\n", null)), "CHALLENGE")).isNull();

        CanonicalSecurityContext unmet = context(0, 3, "NORMAL", new DecisionFacts(List.of(), List.of(),
                new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(), "no approval", List.of()), List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(unmet, DrawnPrompt.of(prompt(0, 3, "NORMAL", allow
                + "[F2] Policy: EXPORT_APPROVAL requires a covering approval\n[F3] PolicySatisfied: no — no approval\n",
                null)), "CHALLENGE")).isNull();

        CanonicalSecurityContext failed = context(1, 3, "NORMAL", facts(List.of()));
        assertThat(SecurityDecisionFactChecks.boundaryViolation(failed, DrawnPrompt.of(prompt(1, 3, "NORMAL", allow, null)),
                "CHALLENGE")).isNull();
    }

    /** A role scope difference on provisional evidence is no anomaly; on trusted evidence it is. */
    @Test
    void aProvisionalRoleScopeDifferenceIsNoAnomaly() {
        String lines = "[F1] AuthorizationEffect: ALLOW\n[F2] RoleScope: action READ outside the scope group's actions (EXPORT)\n";
        CanonicalSecurityContext provisional = scoped(ContextQualityGrade.WEAK);
        CanonicalSecurityContext trusted = scoped(ContextQualityGrade.STRONG);

        assertThat(SecurityDecisionFactChecks.boundaryViolation(provisional, DrawnPrompt.of(prompt(0, 3, "NORMAL", lines,
                null)), "CHALLENGE")).isEqualTo(SecurityDecisionFactChecks.REQUIRED_LOW_RISK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(trusted, DrawnPrompt.of(prompt(0, 3, "NORMAL", lines,
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

        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, DrawnPrompt.of(prompt(0, 3, "CRITICAL", covered,
                null)), "CHALLENGE")).isEqualTo(SecurityDecisionFactChecks.REQUIRED_COVERED_WORK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, DrawnPrompt.of(prompt(0, 3, "CRITICAL", covered,
                null)), "ALLOW")).isNull();
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, DrawnPrompt.of(prompt(0, 3, "CRITICAL",
                covered + "ThreatMatch: campaign C-7 matches the request\n", null)), "CHALLENGE")).isNull();

        DecisionFacts unexplainedToo = new DecisionFacts(explained.facts(), List.of(unexplained(DeviationDimension.TIME)),
                explained.policy(), List.of());
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context(0, 3, "CRITICAL", unexplainedToo),
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

    /** Dictionary 5: the ID is in the prompt, its line is one the code cites, and the code's condition holds. */
    @Test
    void eachReasonCodeIsCheckedOnItsIdItsLineAndItsCondition() {
        DecisionFacts decisionFacts = new DecisionFacts(List.of(
                fact("PolicySatisfied", "no — no approval", "POLICY_NOT_SATISFIED_NO_RECORD"),
                fact("DeviationsFromBaseline", "class CRITICAL seen 0 of 25 (unexplained)", "DEVIATION_RESOURCE_CLASS"),
                fact("DataConflicts", "authorizationEffect (policy ALLOW, method DENY)", "AUTHORIZATION_CONFLICT")),
                List.of(), new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(), "no approval", List.of()),
                List.of());
        CanonicalSecurityContext context = context(0, 3, "CRITICAL", decisionFacts);
        DrawnPrompt drawn = DrawnPrompt.of(prompt(0, 3, "CRITICAL", """
                [F1] AuthorizationEffect: ALLOW
                [F2] PolicySatisfied: no — no approval
                [F3] DeviationsFromBaseline: class CRITICAL seen 0 of 25 (unexplained)
                """, "not-integrated: [U1] ClientSignals").replace("=== UNKNOWN ===", """
                === PAST RECORDS (learned) ===
                [P1] PastRecord1: 09-29 10:12 EXPORT GB-500 ALLOW

                === UNKNOWN ==="""));

        List<ReasonFinding> findings = SecurityDecisionFactChecks.reasonFindings(context, MinimumActionRules.Settings.DEFAULTS,
                drawn, List.of(
                        citation("MIN_P3_POLICY_NOT_SATISFIED", "F2"),
                        citation("POLICY_NOT_SATISFIED_NO_RECORD", "f2"),
                        citation("POLICY_SATISFIED", "F2"),
                        citation("APPROVAL_COVERS", "F1"),
                        citation("DEVIATION_TIME", "F3"),
                        citation("MATERIAL_MISSING_EVIDENCE", "U1"),
                        citation("MATERIAL_MISSING_EVIDENCE", "U9"),
                        citation("POLICY_SATISFIED", "U1"),
                        citation("PAST_RECORD_SAME_TARGET", "P1"),
                        citation("NOT_A_CODE", "F1"),
                        citation("AUTHORIZATION_CONFLICT", "F1")));

        assertThat(findings).extracting(ReasonFinding::outcome).containsExactly(
                Outcome.MATCH, Outcome.MATCH, Outcome.MISMATCH, Outcome.MISMATCH, Outcome.MISMATCH, Outcome.MATCH,
                Outcome.MISMATCH, Outcome.MISMATCH, Outcome.UNDECIDED, Outcome.MISMATCH, Outcome.MATCH);
        assertThat(findings.get(7).reason()).isEqualTo("the code does not cite ClientSignals");
        assertThat(findings.get(3).reason()).isEqualTo("the code does not cite DECISION_FACTS.AuthorizationEffect");
        assertThat(findings.get(6).reason()).isEqualTo("the prompt gives no fact this ID");
        assertThat(findings.get(8).reason())
                .isEqualTo("the condition of PAST_RECORD_SAME_TARGET cannot be decided on the facts here");
        assertThat(SecurityDecisionFactChecks.reasonViolation(findings))
                .startsWith(SecurityDecisionFactChecks.REASON_CODE_MISMATCH + ": POLICY_SATISFIED F2 (")
                .doesNotContain("MIN_P3", "PAST_RECORD_SAME_TARGET");
        assertThat(SecurityDecisionFactChecks.reasonViolation(findings.subList(0, 2))).isNull();
    }

    /**
     * The minimum action codes need the host's rule settings; without them (a sealed package) they cannot be told, and
     * the reason says so rather than that the condition does not hold (the inspection screen showed it, W4-8).
     */
    @Test
    void withoutTheRuleSettingsAMinimumActionCodeCannotBeTold() {
        CanonicalSecurityContext context = context(0, 3, "CRITICAL", new DecisionFacts(List.of(), List.of(),
                new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(), "no approval", List.of()), List.of()));
        DrawnPrompt drawn = DrawnPrompt.of(prompt(0, 3, "CRITICAL", "[F1] PolicySatisfied: no — no approval\n", null));

        assertThat(SecurityDecisionFactChecks.reasonFindings(context, null, drawn,
                List.of(citation("MIN_P3_POLICY_NOT_SATISFIED", "F1")))).extracting(ReasonFinding::outcome)
                .containsExactly(Outcome.UNDECIDED);
        assertThat(SecurityDecisionFactChecks.reasonFindings(context, null, drawn,
                List.of(citation("MIN_P3_POLICY_NOT_SATISFIED", "F1")))).extracting(ReasonFinding::reason)
                .containsExactly("the minimum action settings are not sealed, so the condition of"
                        + " MIN_P3_POLICY_NOT_SATISFIED cannot be decided");
        assertThat(SecurityDecisionFactChecks.reasonFindings(context, MinimumActionRules.Settings.DEFAULTS, drawn,
                List.of(citation("MIN_P3_POLICY_NOT_SATISFIED", "F1")))).extracting(ReasonFinding::outcome)
                .containsExactly(Outcome.MATCH);
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

    private static SecurityDecisionOutputContract.Citation citation(String code, String fact) {
        return new SecurityDecisionOutputContract.Citation(code, fact);
    }
}
