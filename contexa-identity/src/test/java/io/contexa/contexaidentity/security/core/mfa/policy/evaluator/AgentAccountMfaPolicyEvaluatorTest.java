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

import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A1-13: an approved agent's own account signs in by Contexa's zero trust action alone and is never asked for the
 * factors made for people; a person's account keeps the people's policy.
 */
class AgentAccountMfaPolicyEvaluatorTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final AgentAccountMfaPolicyEvaluator evaluator = new AgentAccountMfaPolicyEvaluator(actions,
            provider((tenantId, account) -> "report-bot".equals(account) ? Optional.of("report-bot") : Optional.empty()));

    @Test
    void onlyAnApprovedAgentsAccountIsEvaluatedHere() {
        assertThat(evaluator.supports(context("report-bot"))).isTrue();
        assertThat(evaluator.supports(context("alice"))).isFalse();
        assertThat(evaluator.supports(null)).isFalse();
    }

    @Test
    void allowOrNoAnalysisYetSignsTheAgentInWithoutFactors() {
        when(actions.getAnalysisData("report-bot")).thenReturn(analysis("ALLOW"));
        MfaDecision allowed = evaluator.evaluatePolicy(context("report-bot"));
        when(actions.getAnalysisData("report-bot")).thenReturn(analysis(null));
        MfaDecision pending = evaluator.evaluatePolicy(context("report-bot"));

        assertThat(allowed.getType()).isEqualTo(MfaDecision.DecisionType.NO_MFA_REQUIRED);
        assertThat(allowed.isRequired()).isFalse();
        assertThat(pending.getType()).isEqualTo(MfaDecision.DecisionType.NO_MFA_REQUIRED);
        assertThat(AgentAccountMfaPolicyEvaluator.isAgentAccountDecision(allowed)).isTrue();
        assertThat(allowed.getMetadata()).containsEntry("agentId", "report-bot");
    }

    @Test
    void aChallengeWaitsForTheAccountablePartyInsteadOfFactors() {
        when(actions.getAnalysisData("report-bot")).thenReturn(analysis("CHALLENGE"));

        MfaDecision decision = evaluator.evaluatePolicy(context("report-bot"));

        assertThat(decision.getType()).isEqualTo(MfaDecision.DecisionType.BLOCKED);
        assertThat(decision.getReason()).startsWith("AGENT_CONFIRMATION_REQUIRED");
        assertThat(decision.getRequiredFactors()).isEmpty();
    }

    @Test
    void blockAndEscalateRefuseTheSignInAndAnUnreadableActionToo() {
        when(actions.getAnalysisData("report-bot")).thenReturn(analysis("BLOCK"));
        assertThat(evaluator.evaluatePolicy(context("report-bot")).getType()).isEqualTo(MfaDecision.DecisionType.BLOCKED);
        when(actions.getAnalysisData("report-bot")).thenReturn(analysis("ESCALATE"));
        assertThat(evaluator.evaluatePolicy(context("report-bot")).getType()).isEqualTo(MfaDecision.DecisionType.ESCALATED);
        when(actions.getAnalysisData("report-bot")).thenThrow(new IllegalStateException("store down"));
        assertThat(evaluator.evaluatePolicy(context("report-bot")).getType()).isEqualTo(MfaDecision.DecisionType.BLOCKED);
    }

    @Test
    void theCompositeChoosesItBeforeThePeoplesPolicies() {
        when(actions.getAnalysisData("report-bot")).thenReturn(analysis("CHALLENGE"));
        MfaPolicyEvaluator peoplesPolicy = new MfaPolicyEvaluator() {
            @Override
            public MfaDecision evaluatePolicy(FactorContext context) {
                return MfaDecision.challenged("people's policy");
            }

            @Override
            public int getPriority() {
                return 100;
            }
        };
        CompositeMfaPolicyEvaluator composite = new CompositeMfaPolicyEvaluator(List.of(peoplesPolicy, evaluator));

        assertThat(composite.evaluatePolicy(context("report-bot")).getReason()).startsWith("AGENT_CONFIRMATION_REQUIRED");
        assertThat(composite.evaluatePolicy(context("alice")).getReason()).isEqualTo("people's policy");
    }

    private static FactorContext context(String username) {
        FactorContext context = mock(FactorContext.class);
        when(context.getUsername()).thenReturn(username);
        return context;
    }

    private static ZeroTrustActionRepository.ZeroTrustAnalysisData analysis(String action) {
        return new ZeroTrustActionRepository.ZeroTrustAnalysisData(action, null, null, null, null, null, null, null,
                null, null, null);
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AgentClientDirectory> provider(AgentClientDirectory directory) {
        ObjectProvider<AgentClientDirectory> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(directory);
        return provider;
    }
}
