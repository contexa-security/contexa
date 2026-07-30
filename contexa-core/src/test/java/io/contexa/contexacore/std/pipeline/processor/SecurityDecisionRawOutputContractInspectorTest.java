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

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionRawOutputContractInspectorTest {

    private final SecurityDecisionRawOutputContractInspector inspector =
            new SecurityDecisionRawOutputContractInspector();

    @Test
    void shouldRejectFalseFreshVerificationClaim() {
        assertViolation(
                "VerificationRequired: false",
                "Fresh verification is required before allowing access.",
                "FALSE_VERIFICATION_REQUIRED_CLAIM");
    }

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
    void shouldRejectAllowThatViolatesRequiredVerificationBoundary() {
        assertActionViolation(
                "AuthorizationEffect: ALLOW\nVerificationRequired: true\nMfaVerified: false\nSensitivity: HIGH",
                "ALLOW",
                "Authorization allows access.",
                "REQUIRED_VERIFICATION_BOUNDARY_ACTION_MISMATCH");
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

    private SecurityDecisionRawOutputContractInspector.Inspection inspect(
            String promptFacts,
            String action,
            String reasoning) {
        String response = "{\"action\":\"" + action + "\",\"reasoning\":\"" + reasoning + "\"}";
        return inspector.inspect(response, new Prompt(promptFacts), "contract-test", "initial");
    }
}
