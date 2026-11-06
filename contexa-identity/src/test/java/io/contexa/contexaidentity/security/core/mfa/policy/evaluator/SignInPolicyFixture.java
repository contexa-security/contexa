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

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.AIAdaptiveMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The policy a password step meets, wired as {@code IdentityMfaAutoConfiguration} wires it: the three built-in evaluators
 * under the composite, under the AI adaptive provider, all on one decision store. Only the flow, the users and the agent
 * registry are stand-ins.
 */
final class SignInPolicyFixture {

    static final String FLOW = "mfa";
    static final String AGENT_ACCOUNT = "report-bot";

    final MfaPolicyProvider provider;
    /** The evaluator of lowest priority on its own, as a replaced or failing evaluator leaves it to answer. */
    final DefaultMfaPolicyEvaluator fallback;

    SignInPolicyFixture(ZeroTrustActionRepository store) {
        this(store, new SecurityZeroTrustProperties());
    }

    SignInPolicyFixture(ZeroTrustActionRepository store, SecurityZeroTrustProperties zeroTrust) {
        UserRepository users = mock(UserRepository.class);
        when(users.findByUsernameWithGroupsRolesAndPermissions(anyString())).thenAnswer(call ->
                Optional.of(Users.builder().username(call.getArgument(0)).mfaEnabled(true).build()));
        PlatformConfig platform = mock(PlatformConfig.class);
        when(platform.getFlows()).thenReturn(List.of(mfaFlow()));
        ApplicationContext application = mock(ApplicationContext.class);
        when(application.getBean(PlatformConfig.class)).thenReturn(platform);

        fallback = new DefaultMfaPolicyEvaluator(users, application, store);
        CompositeMfaPolicyEvaluator composite = new CompositeMfaPolicyEvaluator(List.of(
                fallback,
                new ZeroTrustPolicyEvaluator(users, application, store, zeroTrust),
                new AgentAccountMfaPolicyEvaluator(store, agents())));
        provider = new AIAdaptiveMfaPolicyProvider(users, application, new AuthContextProperties(), composite, platform,
                mock(AICoreOperations.class));
    }

    /** What the password step of the MFA filters hands the policy: a context of its own, with the address and browser. */
    static FactorContext signIn(String user, String address, String browser) {
        FactorContext context = new FactorContext(UUID.randomUUID().toString(),
                UsernamePasswordAuthenticationToken.authenticated(user, null, List.of()), MfaState.NONE, FLOW);
        context.setAttribute(FactorContextAttributes.DeviceAndSession.CLIENT_IP, address);
        context.setAttribute(FactorContextAttributes.DeviceAndSession.USER_AGENT, browser);
        return context;
    }

    private static AuthenticationFlowConfig mfaFlow() {
        return AuthenticationFlowConfig.builder(FLOW)
                .stepConfigs(List.of(new AuthenticationStepConfig(FLOW, "FORM", 0, true),
                        new AuthenticationStepConfig(FLOW, "OTT", 1, false)))
                .primaryAuthenticationOptions(mock(PrimaryAuthenticationOptions.class))
                .registeredFactorOptions(Map.of(AuthType.OTT, mock(AuthenticationProcessingOptions.class)))
                .build();
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AgentClientDirectory> agents() {
        AgentClientDirectory directory = (tenantId, clientId) ->
                AGENT_ACCOUNT.equals(clientId) ? Optional.of(AGENT_ACCOUNT) : Optional.empty();
        ObjectProvider<AgentClientDirectory> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(directory);
        return provider;
    }
}
