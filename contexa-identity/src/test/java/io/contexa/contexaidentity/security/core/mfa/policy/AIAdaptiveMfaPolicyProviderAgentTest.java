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
package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.AgentAccountMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A1-13: the AI adaptation keeps an agent account's sign-in away from the factors made for people. */
class AIAdaptiveMfaPolicyProviderAgentTest {

    @Test
    void anAgentAccountsDecisionIsNotTurnedIntoAChallenge() {
        CompositeMfaPolicyEvaluator composite = mock(CompositeMfaPolicyEvaluator.class);
        FactorContext context = mock(FactorContext.class);
        MfaDecision agentDecision = MfaDecision.noMfaRequired().toBuilder()
                .metadata(Map.of(AgentAccountMfaPolicyEvaluator.SUBJECT_METADATA, AgentAccountMfaPolicyEvaluator.AGENT_ACCOUNT))
                .build();
        when(composite.evaluatePolicy(context)).thenReturn(agentDecision);
        when(context.getAttribute(FactorContextAttributes.StateControl.MFA_DECISION_TYPE)).thenReturn("CHALLENGED");
        AIAdaptiveMfaPolicyProvider provider = new AIAdaptiveMfaPolicyProvider(null, null, null, composite, null,
                mock(AICoreOperations.class));

        assertThat(provider.evaluateInitialMfaRequirement(context).getType())
                .isEqualTo(MfaDecision.DecisionType.NO_MFA_REQUIRED);
    }

    @Test
    void aPersonsDecisionIsStillAdapted() {
        CompositeMfaPolicyEvaluator composite = mock(CompositeMfaPolicyEvaluator.class);
        FactorContext context = mock(FactorContext.class);
        when(composite.evaluatePolicy(context)).thenReturn(MfaDecision.noMfaRequired());
        when(context.getAttribute(FactorContextAttributes.StateControl.MFA_DECISION_TYPE)).thenReturn("CHALLENGED");
        AIAdaptiveMfaPolicyProvider provider = new AIAdaptiveMfaPolicyProvider(null, null, null, composite, null,
                mock(AICoreOperations.class));

        assertThat(provider.evaluateInitialMfaRequirement(context).getType())
                .isEqualTo(MfaDecision.DecisionType.CHALLENGED);
    }
}
