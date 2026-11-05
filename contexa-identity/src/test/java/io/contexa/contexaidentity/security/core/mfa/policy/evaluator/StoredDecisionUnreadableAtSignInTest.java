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
package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-99: the records a store of any kind can hand a password step that the built-in stores do not write together, and a
 * store that fails. Neither may read as a waiver of the second step.
 */
class StoredDecisionUnreadableAtSignInTest {

    private static final String USER = "alice";

    private final ZeroTrustActionRepository store = mock(ZeroTrustActionRepository.class);
    private final SignInPolicyFixture policy = new SignInPolicyFixture(store);

    @Test
    @DisplayName("a pending analysis does not lean on a last verified ALLOW, which has no context and lasts a day")
    void aPendingAnalysisDoesNotLeanOnTheLastVerifiedAllow() {
        when(store.getAnalysisData(USER)).thenReturn(fresh(ZeroTrustAction.PENDING_ANALYSIS));
        when(store.getLastVerifiedAction(USER)).thenReturn(ZeroTrustAction.ALLOW);

        MfaDecision decision = signIn();

        AbstractStoredDecisionSignInContractTest.assertAsksForTheSecondStep(decision);
        assertThat(decision.getMetadata()).containsEntry("pendingAnalysis", true);
    }

    @Test
    @DisplayName("a store that fails asks for the second step, on the evaluator that answers and on the fallback")
    void aStoreThatFailsAsksForTheSecondStep() {
        when(store.getAnalysisData(USER)).thenThrow(new IllegalStateException("store down"));
        when(store.getActionFromHash(USER)).thenThrow(new IllegalStateException("store down"));
        when(store.getLastVerifiedAction(USER)).thenThrow(new IllegalStateException("store down"));

        AbstractStoredDecisionSignInContractTest.assertAsksForTheSecondStep(signIn());
        AbstractStoredDecisionSignInContractTest.assertAsksForTheSecondStep(
                policy.fallback.evaluatePolicy(SignInPolicyFixture.signIn(USER, "198.51.100.77", "curl/8.5.0")));
    }

    @Test
    @DisplayName("a pending analysis with a store that fails on the last verified record asks for the second step")
    void aPendingAnalysisWithAnUnreadableLastVerifiedRecord() {
        when(store.getAnalysisData(USER)).thenReturn(fresh(ZeroTrustAction.PENDING_ANALYSIS));
        when(store.getLastVerifiedAction(USER)).thenThrow(new IllegalStateException("store down"));

        AbstractStoredDecisionSignInContractTest.assertAsksForTheSecondStep(signIn());
    }

    private MfaDecision signIn() {
        return policy.provider.evaluateInitialMfaRequirement(
                SignInPolicyFixture.signIn(USER, "198.51.100.77", "curl/8.5.0"));
    }

    private static ZeroTrustAnalysisData fresh(ZeroTrustAction action) {
        return new ZeroTrustAnalysisData(action.name(), null, null, null, null, Instant.now().toString());
    }
}
