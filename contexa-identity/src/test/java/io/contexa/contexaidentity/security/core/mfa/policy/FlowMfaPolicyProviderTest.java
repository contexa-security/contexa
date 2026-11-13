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

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A flow that names a policy provider in its DSL ({@code mfa.policyProvider(...)}) is decided by that provider. */
class FlowMfaPolicyProviderTest {

    private final CompositeMfaPolicyEvaluator evaluator = mock(CompositeMfaPolicyEvaluator.class);

    private static AuthenticationFlowConfig flow(String typeName, MfaPolicyProvider named) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(typeName);
        when(flow.getMfaPolicyProvider()).thenReturn(named);
        return flow;
    }

    private static PlatformConfig platform(AuthenticationFlowConfig... flows) {
        PlatformConfig platform = mock(PlatformConfig.class);
        when(platform.getFlows()).thenReturn(List.of(flows));
        return platform;
    }

    private static FactorContext signIn(String flowTypeName) {
        FactorContext context = mock(FactorContext.class);
        when(context.getFlowTypeName()).thenReturn(flowTypeName);
        when(context.getUsername()).thenReturn("user");
        return context;
    }

    private DefaultMfaPolicyProvider provider(PlatformConfig platform) {
        DefaultMfaPolicyProvider provider = new DefaultMfaPolicyProvider(null, null, null, evaluator, platform);
        provider.initializeMfaFlowConfig();
        return provider;
    }

    @Test
    void everyQuestionOfAFlowThatNamesAProviderIsAnsweredByIt() {
        MfaPolicyProvider named = mock(MfaPolicyProvider.class);
        FactorContext context = signIn("mfa_admin");
        NextFactorDecision next = NextFactorDecision.noMoreFactors();
        when(named.evaluateInitialMfaRequirement(context)).thenReturn(MfaDecision.noMfaRequired());
        when(named.evaluateNextFactor(context)).thenReturn(next);
        when(named.isFactorAvailableForUser("user", AuthType.OTT, context)).thenReturn(true);
        when(named.getRequiredFactorCount("user", "mfa_admin")).thenReturn(3L);
        DefaultMfaPolicyProvider provider = provider(platform(flow("mfa", null), flow("mfa_admin", named)));

        assertThat(provider.evaluateInitialMfaRequirement(context).getType())
                .isEqualTo(MfaDecision.DecisionType.NO_MFA_REQUIRED);
        assertThat(provider.evaluateNextFactor(context)).isSameAs(next);
        assertThat(provider.isFactorAvailableForUser("user", AuthType.OTT, context)).isTrue();
        assertThat(provider.getRequiredFactorCount("user", "mfa_admin")).isEqualTo(3L);
        verify(evaluator, never()).evaluatePolicy(context);
    }

    @Test
    void aFlowThatNamesNoneIsAnsweredAsBefore() {
        MfaPolicyProvider named = mock(MfaPolicyProvider.class);
        FactorContext context = signIn("mfa");
        MfaDecision decision = MfaDecision.noMfaRequired();
        when(evaluator.evaluatePolicy(context)).thenReturn(decision);
        DefaultMfaPolicyProvider provider = provider(platform(flow("mfa", null), flow("mfa_admin", named)));

        assertThat(provider.evaluateInitialMfaRequirement(context)).isSameAs(decision);
        verify(named, never()).evaluateInitialMfaRequirement(context);
    }

    @Test
    void aProviderWrittenAroundTheBeanGetsTheBeansOwnAnswer() {
        FactorContext context = signIn("mfa");
        when(evaluator.evaluatePolicy(context)).thenReturn(MfaDecision.noMfaRequired());
        AuthenticationFlowConfig flow = flow("mfa", null);
        DefaultMfaPolicyProvider bean = provider(platform(flow));
        // Asks the bean, then tightens its answer: the shape an application's own provider commonly has.
        MfaPolicyProvider around = mock(MfaPolicyProvider.class);
        when(around.evaluateInitialMfaRequirement(context)).thenAnswer(question ->
                bean.evaluateInitialMfaRequirement(context).toBuilder()
                        .required(true).type(MfaDecision.DecisionType.CHALLENGED).build());
        when(flow.getMfaPolicyProvider()).thenReturn(around);

        assertThat(bean.evaluateInitialMfaRequirement(context).getType())
                .isEqualTo(MfaDecision.DecisionType.CHALLENGED);
        verify(evaluator).evaluatePolicy(context);

        // The mark of the question in progress is gone with its answer: the next sign-in asks the flow's provider again.
        assertThat(bean.evaluateInitialMfaRequirement(context).getType())
                .isEqualTo(MfaDecision.DecisionType.CHALLENGED);
    }

    @Test
    void theAdaptiveProviderLeavesTheDecisionOfTheFlowsProviderAsItIs() {
        MfaPolicyProvider named = mock(MfaPolicyProvider.class);
        FactorContext context = signIn("mfa");
        when(named.evaluateInitialMfaRequirement(context)).thenReturn(MfaDecision.noMfaRequired());
        when(context.getAttribute(FactorContextAttributes.StateControl.MFA_DECISION_TYPE)).thenReturn("CHALLENGED");
        AIAdaptiveMfaPolicyProvider provider = new AIAdaptiveMfaPolicyProvider(null, null, null, evaluator,
                platform(flow("mfa", named)), mock(AICoreOperations.class));
        provider.initializeMfaFlowConfig();

        assertThat(provider.evaluateInitialMfaRequirement(context).getType())
                .isEqualTo(MfaDecision.DecisionType.NO_MFA_REQUIRED);
    }
}
