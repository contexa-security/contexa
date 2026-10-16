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
package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionRawOutputContractInspectorTest {

    private final SecurityDecisionRawOutputContractInspector inspector =
            new SecurityDecisionRawOutputContractInspector();

    @Test
    void shouldNotRejectNegatedFreshVerificationClaim() {
        assertNoViolation(
                "VerificationRequired: false",
                "Fresh verification is not required for this request.");
    }

    @Test
    void shouldRejectFalseMfaVerifiedClaim() {
        assertViolation(
                "MfaVerified: false",
                "MFA is verified and supports access.",
                "FALSE_MFA_VERIFIED_CLAIM");
    }

    @Test
    void shouldRejectFalseMfaUnverifiedClaim() {
        assertViolation(
                "MfaVerified: true",
                "MFA is not verified for this request.",
                "FALSE_MFA_UNVERIFIED_CLAIM");
    }

    @Test
    void shouldRejectFalseLowSensitivityClaim() {
        assertViolation(
                "Sensitivity: CRITICAL",
                "The resource has low sensitivity.",
                "FALSE_LOW_SENSITIVITY_CLAIM");
    }

    @Test
    void shouldRejectFalseHighSensitivityClaim() {
        assertViolation(
                "Sensitivity: MEDIUM",
                "The resource has high sensitivity.",
                "FALSE_HIGH_SENSITIVITY_CLAIM");
    }

    @Test
    void shouldRejectFalseAuthorizationDeniedClaim() {
        assertViolation(
                "AuthorizationEffect: ALLOW",
                "Authorization is denied for this request.",
                "FALSE_AUTHORIZATION_DENIED_CLAIM");
    }

    @Test
    void shouldRejectSameResourceRagSentenceWithoutRagDocuments() {
        assertViolation(
                "AuthorizationEffect: ALLOW\nRagRelevance: NO_DOCUMENTS\nRagAuthorizedDocumentCount: 0",
                "Authorization allows access, and authorized RAG is relevant to the same resource.",
                "FALSE_AUTHORIZED_RAG_CLAIM");
    }

    @Test
    void shouldAcceptTheNoRagAllowSentences() {
        String facts = "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW"
                + "\nRagRelevance: NO_DOCUMENTS\nRagAuthorizedDocumentCount: 0";
        assertNoViolation(facts,
                "Authorization allows access with a limited baseline, and no concrete risk or verification requirement is present.");
        assertNoViolation(facts,
                "Authorization allows access, the personal baseline is established, and no concrete risk or verification requirement is present.");
    }

    @Test
    void shouldAcceptFactsThatMatchThePrompt() {
        assertNoViolation(
                "VerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW",
                "Authorization allows the medium-sensitivity request; MFA is not verified.");
    }

    @Test
    void shouldRejectBlockWithoutDecisiveEvidence() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM",
                "BLOCK",
                "Weak MFA and provisional baseline justify blocking.",
                "BLOCK_WITHOUT_DECISIVE_EVIDENCE");
    }

    @Test
    void shouldAcceptBlockWhenIndependentCanonicalAttackCategoriesCorroborate() {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(
                "AuthorizationEffect: ALLOW\nVerificationRequired: true\nMfaVerified: false\nSensitivity: CRITICAL\n"
                        + "FailedLoginAttempts: 1000\nRecentRequestCount: 10000\n"
                        + "DeviceFingerprintMatch: false\nBotUserAgent: true\n"
                        + "ObservedAnomalySignal: CLIENT_SUPPLIED_TEXT\n"
                        + "AnomalySignalTrust: UNTRUSTED_REQUEST_HEADER",
                "BLOCK",
                "Failed logins and request abuse combine with device mismatch and bot intent; final autonomous action is BLOCK.");

        assertThat(result.requiresRetry()).isFalse();
        assertThat(result.semanticViolation()).isNull();
    }

    @Test
    void shouldStillRejectBlockForOnlyOneCanonicalAttackCategory() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: true\nMfaVerified: false\nSensitivity: CRITICAL\n"
                        + "FailedLoginAttempts: 1000\nRecentRequestCount: 10000\n"
                        + "ObservedAnomalySignal: CLIENT_SUPPLIED_TEXT\n"
                        + "AnomalySignalTrust: UNTRUSTED_REQUEST_HEADER",
                "BLOCK",
                "Request activity alone justifies blocking.",
                "BLOCK_WITHOUT_DECISIVE_EVIDENCE");
    }

    @Test
    void shouldRequireBlockForThreeWayCanonicalAttackEvidence() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: CRITICAL\n"
                        + "FailedLoginAttempts: 500\nRecentRequestCount: 800\n"
                        + "DeviceFingerprintMatch: false\nBotUserAgent: true\nTlsFingerprintAltered: true",
                "CHALLENGE",
                "The attack evidence can be resolved by a challenge.",
                "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH");
    }

    @Test
    void shouldNotRequireBlockBelowObservedAbuseMinimum() {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: CRITICAL\n"
                        + "FailedLoginAttempts: 99\nRecentRequestCount: 99\n"
                        + "DeviceFingerprintMatch: false\nBotUserAgent: true\nTlsFingerprintAltered: true",
                "CHALLENGE",
                "The evidence is suspicious but does not meet the required block boundary.");

        assertThat(result.requiresRetry()).isFalse();
    }

    @Test
    void shouldNotTreatAnUntrustedAnomalyClaimAsAdverseEvidence() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\n"
                        + "ObservedAnomalySignal: CLIENT_SUPPLIED_TEXT\n"
                        + "AnomalySignalTrust: UNTRUSTED_REQUEST_HEADER",
                "CHALLENGE",
                "The request header reports an anomaly.",
                "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
    }

    @Test
    void shouldTreatATrustedAnomalySignalAsAdverseEvidence() {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\n"
                        + "ObservedAnomalySignal: SUSPECTED_SESSION_REPLAY\n"
                        + "AnomalySignalTrust: TRUSTED_VERIFICATION_INPUT",
                "CHALLENGE",
                "A server-verified anomaly signal needs fresh verification.");

        assertThat(result.semanticViolation()).isNull();
    }

    @Test
    void shouldTreatAStatedChangeOfDeviceOrNetworkWithinTheSessionAsAdverseEvidence() {
        // W2-14: the changed parts replace the binding-hash mismatch nobody produced.
        String allowedMedium = "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\n"
                + "Sensitivity: MEDIUM\n";
        SecurityDecisionRawOutputContractInspector.Inspection device = inspect(
                allowedMedium + "SessionDeviceChange: Chrome/140 on WINDOWS -> Safari/17 on MAC in the same session",
                "CHALLENGE",
                "The session changed device mid-session.");
        SecurityDecisionRawOutputContractInspector.Inspection network = inspect(
                allowedMedium + "SessionNetworkChange: 10.40.12.0/24 (CORPORATE) -> 203.0.113.0/24 in the same session",
                "CHALLENGE",
                "The session changed network mid-session.");

        assertThat(device.semanticViolation()).isNull();
        assertThat(network.semanticViolation()).isNull();
        assertActionViolation(allowedMedium + "SessionNetworkChange: UNKNOWN",
                "CHALLENGE",
                "The session changed network mid-session.",
                "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
    }

    @Test
    void shouldRejectEscalateThatViolatesRequiredLowRiskAllowBoundary() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM",
                "ESCALATE",
                "Provisional baseline creates uncertainty.",
                "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
    }

    @Test
    void shouldIgnoreHistoricalInlineMfaWhenReadingCurrentRequestFact() {
        assertNoViolation(
                "MfaVerified: false\nRagDocument1: historical behavior, MfaVerified: true",
                "MFA is not verified for the current request.");
    }

    @Test
    void shouldRejectNonBlockForTrustedConfirmedMaliciousSignal() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: true\nMfaVerified: false\nSensitivity: CRITICAL\n"
                        + "AnomalySignalTrust: TRUSTED_VERIFICATION_INPUT - authoritative current evidence; evaluate the confirmed-malicious BLOCK boundary\n"
                        + "ObservedAnomalySignal: CONFIRMED_PROMPT_INJECTION",
                "CHALLENGE",
                "Fresh verification is required before allowing access.",
                "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH");
    }

    @Test
    void shouldAcceptChallengeForConcreteDeniedRoleScopeEvidence() {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(
                "AuthorizationEffect: ALLOW\nVerificationRequired: false\nMfaVerified: false\nSensitivity: MEDIUM\n"
                        + "CurrentActionFamilyPresentInDeniedRoleScope: true",
                "CHALLENGE",
                "The current action family is explicitly present in the denied role scope.");

        assertThat(result.requiresRetry()).isFalse();
    }

    @Test
    void shouldRequireBlockForConflictingOrganizationFacts() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nOrganizationId: organization-a\nOrganizationId: organization-b",
                "ALLOW",
                "Authorization allows access.",
                "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH");
    }
    private void assertViolation(String promptFacts, String reasoning, String expectedViolation) {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(promptFacts, reasoning);
        assertThat(result.requiresRetry()).isTrue();
        assertThat(result.parsingFallback()).isFalse();
        assertThat(result.semanticViolation()).isEqualTo(expectedViolation);
        assertThat(result.retryReason()).isEqualTo(expectedViolation);
    }

    private void assertNoViolation(String promptFacts, String reasoning) {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(promptFacts, reasoning);
        assertThat(result.requiresRetry()).isFalse();
        assertThat(result.parsingFallback()).isFalse();
        assertThat(result.semanticViolation()).isNull();
        assertThat(result.retryReason()).isNull();
    }

    private SecurityDecisionRawOutputContractInspector.Inspection inspect(
            String promptFacts,
            String reasoning) {
        return inspect(promptFacts, "ALLOW", reasoning);
    }

    private void assertActionViolation(
            String promptFacts,
            String action,
            String reasoning,
            String expectedViolation) {
        SecurityDecisionRawOutputContractInspector.Inspection result = inspect(promptFacts, action, reasoning);
        assertThat(result.requiresRetry()).isTrue();
        assertThat(result.semanticViolation()).isEqualTo(expectedViolation);
    }

    /**
     * W4-5 (plan 7, dictionary 6): given the rule check, an answer weaker than a minimum action rule is a violation that
     * names the rule and the action it asks for; without the check (observe mode) it is not.
     */
    @Test
    void anAnswerWeakerThanAMinimumActionRuleIsAViolationWhenTheRulesAreChecked() {
        SecurityDecisionRawOutputContractInspector.MinimumActionCheck check =
                new SecurityDecisionRawOutputContractInspector.MinimumActionCheck(new DecisionFacts(List.of(), List.of(), new PolicySatisfaction(false, PolicyReason.NO_RECORD,
                        List.of(), "no approval for GB-500", List.of("EXPORT_APPROVAL")), List.of()),
                        "CRITICAL", "EXPORT", MinimumActionRules.Settings.DEFAULTS);
        String allow = "{\"action\":\"ALLOW\",\"reasoning\":\"The export looks routine.\"}";
        String challenge = "{\"action\":\"CHALLENGE\",\"reasoning\":\"No approval covers the export.\"}";
        String escalate = "{\"action\":\"ESCALATE\",\"reasoning\":\"No approval covers the export.\"}";

        SecurityDecisionRawOutputContractInspector.Inspection weaker =
                inspector.inspect(allow, new Prompt("facts"), "w45-rule", "initial", check);
        assertThat(weaker.requiresRetry()).isTrue();
        assertThat(weaker.retryReason()).contains("MIN_P3_POLICY_NOT_SATISFIED").contains("requires ESCALATE");
        // Q-87 (N-P3-1): P3 asks for a review, so a challenge is weaker than it.
        assertThat(inspector.inspect(challenge, new Prompt("facts"), "w45-rule", "initial", check).requiresRetry())
                .isTrue();
        assertThat(inspector.inspect(escalate, new Prompt("facts"), "w45-rule", "initial", check).requiresRetry())
                .isFalse();
        assertThat(inspector.inspect(allow, new Prompt("facts"), "w45-rule", "initial", null).requiresRetry()).isFalse();
    }

    /**
     * W4-8 (S-28): a v20 answer is checked on the facts its prompt was drawn from: the low-risk boundary, which the v19
     * label check never saw in a v20 prompt, and a reason code citing an ID the prompt does not give.
     */
    @Test
    void aV20AnswerIsCheckedOnTheFactsItsPromptWasDrawnFrom() {
        String userPrompt = """
            === SESSION (host) ===
            LoginMethod: PASSWORD, MFA not verified

            === REQUEST (host) ===
            ResourceClass: NORMAL

            === DECISION FACTS (computed) ===
            [F1] AuthorizationEffect: ALLOW
            [F2] SameAsBaseline: time, network as usual
            """;
        SecurityDecisionRawOutputContractInspector.V20Check v20 = new SecurityDecisionRawOutputContractInspector.V20Check(
                v20Context(), userPrompt, MinimumActionRules.Settings.DEFAULTS);
        String challenge = "{\"action\":\"CHALLENGE\",\"reasonCodes\":[{\"code\":\"BASELINE_MATCH\",\"fact\":\"F2\"}],"
                + "\"reason\":\"MFA is not verified.\"}";
        String allowCitingNoFact = "{\"action\":\"ALLOW\",\"reasonCodes\":[{\"code\":\"BASELINE_MATCH\",\"fact\":\"F7\"}],"
                + "\"reason\":\"The read is as usual.\"}";
        String allow = "{\"action\":\"ALLOW\",\"reasonCodes\":[{\"code\":\"BASELINE_MATCH\",\"fact\":\"F2\"}],"
                + "\"reason\":\"The read is as usual.\"}";

        assertThat(inspector.inspect(challenge, new Prompt("system\n" + userPrompt), "w48", "initial", null, v20).retryReason())
                .isEqualTo("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH");
        assertThat(inspector.inspect(allowCitingNoFact, new Prompt("system\n" + userPrompt), "w48", "initial", null, v20)
                .retryReason()).startsWith("REASON_CODE_MISMATCH: BASELINE_MATCH F7");
        assertThat(inspector.inspect(allow, new Prompt("system\n" + userPrompt), "w48", "initial", null, v20).requiresRetry())
                .isFalse();
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                "REQUIRED_COVERED_WORK_BOUNDARY_ACTION_MISMATCH")).isEqualTo("ALLOW");
    }

    private static CanonicalSecurityContext v20Context() {
        return CanonicalSecurityContext.builder()
                .session(CanonicalSecurityContext.Session.builder().mfaVerified(false).build())
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("NORMAL").actionFamily("READ").build())
                .authorization(CanonicalSecurityContext.Authorization.builder().authorizationEffect("ALLOW").build())
                .decisionFacts(new DecisionFacts(List.of(new DecisionFact(null, "SameAsBaseline", "time, network as usual",
                        List.of("BASELINE_MATCH"), List.of(), DecisionFact.COMPUTED)), List.of(), PolicySatisfaction.UNKNOWN,
                        List.of()))
                .build();
    }

    private SecurityDecisionRawOutputContractInspector.Inspection inspect(
            String promptFacts,
            String action,
            String reasoning) {
        String response = "{\"action\":\"" + action + "\",\"reasoning\":\"" + reasoning + "\"}";
        return inspector.inspect(response, new Prompt(promptFacts), "contract-test", "initial");
    }

    /**
     * N-OUT-1 (G1-1, decision A): a contract violation left after the retry falls back to ESCALATE (the code does not
     * choose the response), unless the broken rule asks for one action ESCALATE does not give.
     */
    @Test
    void theFallbackOfAViolationLeftAfterTheRetryFollowsTheRuleItBroke() {
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH"))
                .isEqualTo("BLOCK");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH")).isEqualTo("ALLOW");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("BLOCK_WITHOUT_DECISIVE_EVIDENCE"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(
                "MINIMUM_ACTION_VIOLATION: MIN_P1_IDENTITY_DEVIATION requires CHALLENGE or a stronger action"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("FALSE_AUTHORIZED_RAG_CLAIM"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor("PARSER_MALFORMED_JSON"))
                .isEqualTo("ESCALATE");
        assertThat(SecurityDecisionRawOutputContractInspector.fallbackActionFor(null)).isEqualTo("ESCALATE");
    }

    /** N-OUT-1 (G1-4): an answer without a reason still gets the action boundary check. */
    @Test
    void anAnswerWithoutAReasonStillGetsTheActionBoundaryCheck() {
        String facts = "VerificationRequired: false\nMfaVerified: true\nSensitivity: MEDIUM\nAuthorizationEffect: ALLOW";

        SecurityDecisionRawOutputContractInspector.Inspection block = inspector.inspect("{\"action\":\"BLOCK\"}",
                new Prompt(facts), "contract-no-reason-block", "initial");
        SecurityDecisionRawOutputContractInspector.Inspection allow = inspector.inspect("{\"action\":\"ALLOW\"}",
                new Prompt(facts), "contract-no-reason-allow", "initial");

        assertThat(block.retryReason()).isEqualTo("BLOCK_WITHOUT_DECISIVE_EVIDENCE");
        assertThat(allow.retryReason()).isNull();
    }
}
