package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fact accuracy check on the DECISION FACTS lines the block draws from other sealed fields than the resolver's
 * facts: the authorization effect, the trusted signal, the client signals, the blocked user, break-glass, the recent
 * permission changes and the temporary elevation.
 */
class PromptInspectionDecisionLineFactsTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);

    @Test
    void theAuthorizationEffectIsComparedUpToTheUnsealedProvenance() {
        assertLine(context -> {
                    CanonicalSecurityContext.Authorization authorization = authorization(context);
                    authorization.setAuthorizationEffect("ALLOW");
                    authorization.setPolicyId("POLICY-7");
                    authorization.setPolicyVersion("v3");
                },
                "AuthorizationEffect: ALLOW by policy POLICY-7 v3 (METHOD_AUTHORIZATION_CHECK)",
                "AuthorizationEffect: ALLOW by policy W314-CHECK (METHOD_AUTHORIZATION_CHECK)",
                "canonicalContext.authorization.authorizationEffect");
    }

    /** R4-T (Q-78 request 4): the server-issued trusted signal is no fact of the v20 prompt or its dictionary. */
    @Test
    void theFormerTrustedSignalIsNoFactOfThePrompt() {
        InspectionGolden.Render base = InspectionGolden.render(text -> text.contains("=== DECISION FACTS"));
        InspectionGolden.Render render = InspectionGolden.renderWith(base, context -> {
            CanonicalSecurityContext.Intent intent = intent(context);
            intent.setAnomalySignal("CREDENTIAL_STUFFING");
            intent.setAnomalySignalSource("OFFICIAL_VERIFICATION_INTERNAL");
        });

        assertThat(InspectionGolden.hasLine(render.userPrompt(), "TrustedSignal: ")).isFalse();
        assertThat(SecurityDecisionPromptDictionary.ENTRIES).extracting(PromptDictionaryEntry::name)
                .doesNotContain("TrustedSignal");
    }

    @Test
    void theClientSignalsAreComparedWithTheSealedIntent() {
        assertLine(context -> {
                    CanonicalSecurityContext.Intent intent = intent(context);
                    intent.setBotUserAgent(false);
                    intent.setImpossibleTravel(true);
                },
                "ClientSignals: bot UA: no; impossible travel: yes",
                "ClientSignals: bot UA: no; impossible travel: no",
                "canonicalContext.intent");
    }

    @Test
    void theBlockedUserIsComparedWithTheSealedRecords() {
        assertLine(context -> {
                    if (context.getSession() == null) {
                        context.setSession(new CanonicalSecurityContext.Session());
                    }
                    context.getSession().setBlockedUser(true);
                },
                "BlockedUser: blocked (session record)",
                "BlockedUser: blocked (company record)",
                "canonicalContext.session.blockedUser");
    }

    @Test
    void breakGlassIsComparedWithTheSealedCompanyRecord() {
        assertLine(context -> friction(context).setBreakGlass(true),
                "BreakGlass: break-glass declared (company record)",
                "BreakGlass: break-glass declared (session record)",
                "canonicalContext.frictionProfile.breakGlass");
    }

    @Test
    void theRecentPermissionChangesAreComparedAsTheSealedSet() {
        assertLine(context -> roleScope(context).setRecentPermissionChanges(List.of("granted EXPORT", "revoked ADMIN")),
                "RecentPermissionChanges: granted EXPORT; revoked ADMIN",
                "RecentPermissionChanges: granted EXPORT",
                "canonicalContext.roleScopeProfile.recentPermissionChanges");
    }

    @Test
    void theTemporaryElevationIsComparedWithTheSealedRoleScope() {
        assertLine(context -> {
                    CanonicalSecurityContext.RoleScopeProfile roleScope = roleScope(context);
                    roleScope.setTemporaryElevation(true);
                    roleScope.setElevatedPrivilegeWindowActive(true);
                },
                "TemporaryElevation: active, window open",
                "TemporaryElevation: none",
                "canonicalContext.roleScopeProfile.temporaryElevation");
    }

    @Test
    void theMethodOutcomeAfterAuthorizationIsComparedWithTheSealedAuthorization() {
        assertLine(context -> {
                    CanonicalSecurityContext.Authorization authorization = authorization(context);
                    authorization.setAuthorizationEffect("ALLOW");
                    authorization.setMethodExecutionOutcome("FAILED");
                    authorization.setMethodExecutionFailure("IllegalStateException");
                },
                "AuthorizationEffect: ALLOW; method FAILED with IllegalStateException after authorization",
                "AuthorizationEffect: ALLOW; method SUCCEEDED with IllegalStateException after authorization",
                "canonicalContext.authorization.methodExecutionFailure");
    }

    /**
     * R1b-2: the inspector expects what the render draws. The render of a golden case whose sealed context carries every
     * part of these lines (the policy, the method failure, padded words) is inspected without a finding on them.
     */
    @Test
    void theDrawnLinesAreWhatTheInspectorExpects() {
        InspectionGolden.Render base = InspectionGolden.render(text -> text.contains("=== DECISION FACTS"));
        InspectionGolden.Render render = InspectionGolden.renderWith(base, context -> {
            CanonicalSecurityContext.Authorization authorization = authorization(context);
            authorization.setAuthorizationEffect(" ALLOW ");
            authorization.setPolicyId(" POLICY-7 ");
            authorization.setPolicyVersion("v3");
            authorization.setMethodExecutionFailure(" IllegalStateException ");
            CanonicalSecurityContext.Intent intent = intent(context);
            intent.setMissingReferer(true);
            intent.setLanguageMismatch(false);
            if (context.getSession() == null) {
                context.setSession(new CanonicalSecurityContext.Session());
            }
            context.getSession().setBlockedUser(true);
            friction(context).setBlockedUser(true);
            CanonicalSecurityContext.RoleScopeProfile roleScope = roleScope(context);
            roleScope.setTemporaryElevation(true);
            roleScope.setElevatedPrivilegeWindowActive(false);
            roleScope.setElevationWindowSummary(" until 18:00 ");
        });
        List<String> labels = List.of("AuthorizationEffect", "ClientSignals", "BlockedUser", "TemporaryElevation");

        for (String label : labels) {
            assertThat(InspectionGolden.hasLine(render.userPrompt(), label + ": ")).as(label).isTrue();
        }
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
        assertThat(result.checks().get(0).findings().stream()
                .filter(finding -> "DECISION FACTS".equals(finding.block()) && labels.contains(finding.entry())))
                .isEmpty();
    }

    /** A kept line has no mismatch; a broken line is the single mismatch, of the given source. */
    private static void assertLine(Consumer<CanonicalSecurityContext> sealedSource, String kept, String broken,
                                   String sourceRef) {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== DECISION FACTS"));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        sealedSource.accept(context);
        String label = kept.substring(0, kept.indexOf(": "));

        assertThat(mismatches(check(withLine(render.userPrompt(), label, kept), render, context))).as(kept).isEmpty();
        List<PromptInspectionFinding> found = mismatches(check(withLine(render.userPrompt(), label, broken), render, context));
        assertThat(found).as(broken).hasSize(1);
        assertThat(found.get(0).entry()).isEqualTo(label);
        assertThat(found.get(0).block()).isEqualTo("DECISION FACTS");
        assertThat(found.get(0).sourceRef()).isEqualTo(sourceRef);
    }

    /** The prompt with the line in the DECISION FACTS block, replacing a drawn line of that label. */
    private static String withLine(String userPrompt, String label, String line) {
        String text = userPrompt;
        String existing = Arrays.stream(text.split("\n"))
                .filter(drawn -> drawn.replaceFirst("^\\[F\\d+] ", "").startsWith(label + ": "))
                .findFirst().orElse(null);
        if (existing != null) {
            text = text.replace(existing + "\n", "");
        }
        // The header names the time zone when a fact of the block is on the event clock (W3-13).
        String header = Arrays.stream(text.split("\n")).filter(drawn -> drawn.startsWith("=== DECISION FACTS"))
                .findFirst().orElseThrow();
        return text.replace(header + "\n", header + "\n" + line + "\n");
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render,
                                                     CanonicalSecurityContext context) {
        var sealed = render.sealed(userPrompt);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .filter(finding -> "DECISION FACTS".equals(finding.block())).toList();
    }

    private static CanonicalSecurityContext.Authorization authorization(CanonicalSecurityContext context) {
        // A fresh part, so that sealed fields of the golden case do not join the expected value.
        context.setAuthorization(new CanonicalSecurityContext.Authorization());
        return context.getAuthorization();
    }

    private static CanonicalSecurityContext.Intent intent(CanonicalSecurityContext context) {
        // A fresh part, so that sealed fields of the golden case do not join the expected value.
        context.setIntent(new CanonicalSecurityContext.Intent());
        return context.getIntent();
    }

    private static CanonicalSecurityContext.FrictionProfile friction(CanonicalSecurityContext context) {
        if (context.getFrictionProfile() == null) {
            context.setFrictionProfile(new CanonicalSecurityContext.FrictionProfile());
        }
        return context.getFrictionProfile();
    }

    private static CanonicalSecurityContext.RoleScopeProfile roleScope(CanonicalSecurityContext context) {
        // A fresh part, so that sealed fields of the golden case do not join the expected value.
        context.setRoleScopeProfile(new CanonicalSecurityContext.RoleScopeProfile());
        return context.getRoleScopeProfile();
    }
}
