package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fact accuracy check on the SESSION lines: each line says what the sealed session, session narrative,
 * authentication state and observed scope say, with times on the sealed event clock and distances from the sealed
 * request time.
 */
class PromptInspectionSessionFactsTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);
    private static final Instant REQUEST = Instant.parse("2026-10-12T07:15:00Z");

    @Test
    void theSessionAgeIsComparedWithTheSealedNarrative() {
        assertLine(context -> {
                    narrative(context).setSessionAgeMinutes(42);
                    narrative(context).setSessionAgeBasis("LOGIN");
                }, null, "SessionAge: 42 min since login", "SessionAge: 5 min since login",
                "canonicalContext.sessionNarrativeProfile.sessionAgeMinutes");
    }

    @Test
    void theLoginMethodIsComparedWithTheSealedAuthenticationState() {
        assertLine(context -> {
                    CanonicalSecurityContext.Session session = session(context);
                    session.setAuthenticationType("PASSWORD");
                    session.setAuthenticationAssurance("AAL1");
                    session.setMfaVerified(false);
                }, "{\"authMethod\":\"PASSWORD\"}",
                "LoginMethod: PASSWORD (assurance AAL1), MFA not verified; source host",
                "LoginMethod: MFA (assurance AAL2), MFA verified; source host",
                "authStateJson.authMethod");
    }

    /** R1b-5: a sealed authentication state that does not read leaves the login method unchecked, not compared. */
    @Test
    void aSealedAuthenticationStateThatDoesNotReadLeavesTheLoginMethodUnchecked() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== SESSION"));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        context.setRequestObservedAt(REQUEST);
        session(context).setAuthenticationType("PASSWORD");
        String prompt = withLine(render.userPrompt(), "LoginMethod",
                "LoginMethod: PASSWORD (assurance AAL1), MFA not verified; source host");

        assertThat(check(prompt, render, context, "{not json").findings())
                .filteredOn(finding -> "LoginMethod".equals(finding.entry()))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                    assertThat(finding.sourceRef()).isEqualTo("authStateJson.authMethod");
                    assertThat(finding.reason()).contains("does not read");
                });
    }

    @Test
    void aLoginMethodSayingMfaWasVerifiedWhenTheSealedSessionSaysNotIsPointedAt() {
        assertLine(context -> {
                    CanonicalSecurityContext.Session session = session(context);
                    session.setAuthenticationType("PASSWORD");
                    session.setMfaVerified(false);
                    session.setAuthenticationAssurance(null);
                }, "{\"authMethod\":\"PASSWORD\"}",
                "LoginMethod: PASSWORD, MFA not verified; source host",
                "LoginMethod: PASSWORD, MFA verified; source host",
                "canonicalContext.session.mfaVerified");
    }

    @Test
    void theChallengeVerificationTimeIsComparedOnTheSealedClock() {
        assertLine(context -> session(context).setChallengeVerifiedAt("2026-10-12T07:00:00Z"), null,
                "ChallengeVerified: at 07:00 (15 min before this request)",
                "ChallengeVerified: none",
                "canonicalContext.session.challengeVerifiedAt");
    }

    @Test
    void anMfaElsewhereIsComparedWithTheSealedSession() {
        assertLine(context -> session(context).setRecentMfaElsewhereAt("2026-10-12T05:15:00Z"), null,
                "RecentMfaElsewhere: MFA completed in another session 2 h before this request",
                "RecentMfaElsewhere: MFA completed in another session 5 min before this request",
                "canonicalContext.session.recentMfaElsewhereAt");
    }

    @Test
    void theSessionCountsAreComparedWithTheSealedSession() {
        assertLine(context -> {
                    session(context).setFailedLoginAttempts(3);
                    session(context).setFailedLoginWindowMinutes(5);
                }, null, "FailedLogins: 3 in last 5 min", "FailedLogins: 0 in last 5 min",
                "canonicalContext.session.failedLoginAttempts");
        assertLine(context -> session(context).setRecentMfaFailureCount(2), null,
                "MfaFailures: 2 recent MFA failures (window not stated)",
                "MfaFailures: 0 recent MFA failures (window not stated)",
                "canonicalContext.session.recentMfaFailureCount");
        // W5-10 D5: a request whose seal holds the engine's own count of the last 60 minutes states it before the host's
        // count; this assertion changes the host's count only.
        String engine = engineCountOf(InspectionGolden.render(text -> text.contains("=== SESSION")).userPrompt());
        assertLine(context -> session(context).setRecentRequestCount(17), null,
                "RecentRequests: " + engine + "host count 17, window not stated",
                "RecentRequests: " + engine + "host count 1, window not stated",
                "canonicalContext.session.recentRequestCount");
        assertLine(context -> session(context).setConcurrentSessions(2), null,
                "ConcurrentSessions: 2 concurrent sessions", "ConcurrentSessions: 1 concurrent sessions",
                "canonicalContext.session.concurrentSessions");
        assertLine(context -> session(context).setPasswordAgeDays(90), null,
                "PasswordAge: 90 days since the password changed", "PasswordAge: 9 days since the password changed",
                "canonicalContext.session.passwordAgeDays");
        assertLine(context -> scope(context).setRecentSensitiveAccessCount(4), null,
                "RecentSensitiveAccess: 4 recent sensitive accesses", "RecentSensitiveAccess: 0 recent sensitive accesses",
                "canonicalContext.observedScope.recentSensitiveAccessCount");
    }

    @Test
    void theRequestsInSessionAreComparedWithTheSealedSessionDecisions() {
        assertLine(context -> narrative(context).setSessionDecisions(List.of(
                        new SessionDecisionRecord(Instant.parse("2026-10-12T07:05:00Z"), "GET", "/a", null, "READ", "ALLOW"),
                        new SessionDecisionRecord(Instant.parse("2026-10-12T07:10:00Z"), "POST", "/b", null, "EXPORT",
                                "CHALLENGE"))), null,
                "RequestsInSession: 2 so far: 07:05 (10 min before this request) READ -> ALLOW; "
                        + "07:10 (5 min before this request) EXPORT -> CHALLENGE",
                "RequestsInSession: 2 so far: 07:05 (10 min before this request) READ -> ALLOW; "
                        + "07:10 (5 min before this request) EXPORT -> ALLOW",
                "canonicalContext.sessionNarrativeProfile.sessionDecisions");
    }

    /**
     * R1b-2: requests of the same time are drawn in the render's list order (time, then text); the inspector reads them
     * by the render's own function, so the order it expects is the render's.
     */
    @Test
    void requestsOfTheSameTimeAreExpectedInTheRenderOrder() {
        assertLine(context -> narrative(context).setSessionDecisions(List.of(
                        new SessionDecisionRecord(Instant.parse("2026-10-12T07:05:00Z"), "GET", "/a", null, "READ", "ALLOW"),
                        new SessionDecisionRecord(Instant.parse("2026-10-12T07:05:00Z"), "POST", "/b", null, "EXPORT",
                                "CHALLENGE"))), null,
                "RequestsInSession: 2 so far: 07:05 (10 min before this request) EXPORT -> CHALLENGE; "
                        + "07:05 (10 min before this request) READ -> ALLOW",
                "RequestsInSession: 2 so far: 07:05 (10 min before this request) EXPORT -> ALLOW; "
                        + "07:05 (10 min before this request) READ -> ALLOW",
                "canonicalContext.sessionNarrativeProfile.sessionDecisions");
    }

    @Test
    void theRecentDenialsAreComparedWithTheSealedSessionDecisionsAndScope() {
        assertLine(context -> {
                    narrative(context).setSessionDecisions(List.of(new SessionDecisionRecord(
                            Instant.parse("2026-10-12T07:05:00Z"), "GET", "/a", null, "READ",
                            SessionDecisionRecord.AUTHORIZATION_DENIED, "this", null)));
                    scope(context).setRecentDeniedAccessCount(3);
                }, null,
                "RecentDenied: 1 denied in this session (07:05 GET this); 3 recent denied accesses (host count)",
                "RecentDenied: 3 recent denied accesses (host count)",
                "canonicalContext.sessionNarrativeProfile.sessionDecisions");
    }

    /**
     * R1b-2: the inspector expects what the render draws. The render of a golden case whose sealed session carries an
     * MFA elsewhere and every count (one without its window) is inspected without a finding on those lines.
     */
    @Test
    void theDrawnLinesAreWhatTheInspectorExpects() {
        InspectionGolden.Render base = InspectionGolden.render(text -> text.contains("=== SESSION"));
        InspectionGolden.Render render = InspectionGolden.renderWith(base, context -> {
            context.setRequestObservedAt(REQUEST);
            CanonicalSecurityContext.Session session = session(context);
            session.setRecentMfaElsewhereAt("2026-10-12T05:15:00Z");
            session.setFailedLoginAttempts(3);
            session.setFailedLoginWindowMinutes(null);
            session.setRecentMfaFailureCount(2);
            session.setRecentRequestCount(17);
            session.setConcurrentSessions(2);
            session.setPasswordAgeDays(90);
            scope(context).setRecentSensitiveAccessCount(4);
        });
        List<String> labels = List.of("RecentMfaElsewhere", "FailedLogins", "MfaFailures", "RecentRequests",
                "ConcurrentSessions", "PasswordAge", "RecentSensitiveAccess");

        for (String label : labels) {
            assertThat(InspectionGolden.hasLine(render.userPrompt(), label + ": ")).as(label).isTrue();
        }
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
        assertThat(result.checks().get(0).findings().stream()
                .filter(finding -> "SESSION".equals(finding.block()) && labels.contains(finding.entry())))
                .isEmpty();
    }

    /** A kept line has no mismatch; a broken line is the single mismatch of the SESSION block, of the given source. */
    private static void assertLine(Consumer<CanonicalSecurityContext> sealedSource, String authState, String kept,
                                   String broken, String sourceRef) {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== SESSION"));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        context.setRequestObservedAt(REQUEST);
        sealedSource.accept(context);
        String label = kept.substring(0, kept.indexOf(": "));

        assertThat(mismatches(check(withLine(render.userPrompt(), label, kept), render, context, authState), label))
                .as(kept).isEmpty();
        List<PromptInspectionFinding> found =
                mismatches(check(withLine(render.userPrompt(), label, broken), render, context, authState), label);
        assertThat(found).as(broken).hasSize(1);
        assertThat(found.get(0).entry()).isEqualTo(label);
        assertThat(found.get(0).sourceRef()).isEqualTo(sourceRef);
    }

    /**
     * The engine's part of the golden render's RecentRequests line as the line puts it before a host count: the text
     * before the host count, or the engine's own count with its separator; none without an engine count.
     */
    private static String engineCountOf(String userPrompt) {
        return Arrays.stream(userPrompt.split("\n")).map(InspectionGolden::bare)
                .filter(line -> line.startsWith("RecentRequests: ")).findFirst()
                .map(line -> line.substring("RecentRequests: ".length()))
                .map(value -> value.contains("host count") ? value.substring(0, value.indexOf("host count"))
                        : value.contains(" requests in last ") ? value + "; " : "")
                .orElse("");
    }

    private static String withLine(String userPrompt, String label, String line) {
        String text = userPrompt;
        String existing = Arrays.stream(text.split("\n")).filter(drawn -> drawn.startsWith(label + ": ")).findFirst()
                .orElse(null);
        if (existing != null) {
            text = text.replace(existing + "\n", "");
        }
        String header = Arrays.stream(text.split("\n")).filter(drawn -> drawn.startsWith("=== SESSION")).findFirst()
                .orElseThrow();
        return text.replace(header + "\n", header + "\n" + line + "\n");
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render,
                                                     CanonicalSecurityContext context, String authState) {
        var sealed = render.sealed(userPrompt);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));
        if (authState != null) {
            sealed.setAuthStateJson(authState);
        }
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    /** The mismatches of the line under test (other lines of the golden case answer to their own sources). */
    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check, String label) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .filter(finding -> "SESSION".equals(finding.block()) && label.equals(finding.entry())).toList();
    }

    private static CanonicalSecurityContext.Session session(CanonicalSecurityContext context) {
        if (context.getSession() == null) {
            context.setSession(new CanonicalSecurityContext.Session());
        }
        return context.getSession();
    }

    private static CanonicalSecurityContext.SessionNarrativeProfile narrative(CanonicalSecurityContext context) {
        if (context.getSessionNarrativeProfile() == null) {
            context.setSessionNarrativeProfile(new CanonicalSecurityContext.SessionNarrativeProfile());
        }
        return context.getSessionNarrativeProfile();
    }

    private static CanonicalSecurityContext.ObservedScope scope(CanonicalSecurityContext context) {
        if (context.getObservedScope() == null) {
            context.setObservedScope(new CanonicalSecurityContext.ObservedScope());
        }
        return context.getObservedScope();
    }
}
