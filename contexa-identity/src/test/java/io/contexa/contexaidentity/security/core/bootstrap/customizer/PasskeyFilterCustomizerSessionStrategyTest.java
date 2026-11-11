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
package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthFailureHandler;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthSuccessHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Spring Security's passkey configurer builds its sign-in filter without the session strategy of the chain. A flow that
 * keeps its sign-in in the session gives the filter that strategy, so a passkey sign-in gets a new session id and is
 * counted by the limit of sessions as the other sign-ins are.
 */
class PasskeyFilterCustomizerSessionStrategyTest {

    private final PasskeyFilterCustomizer customizer = new PasskeyFilterCustomizer();
    private final WebAuthnAuthenticationFilter passkeyFilter = new WebAuthnAuthenticationFilter();
    private final DefaultSecurityFilterChain chain = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, passkeyFilter);
    private final SessionAuthenticationStrategy strategyOfChain = mock(SessionAuthenticationStrategy.class);

    private static AuthenticationFlowConfig flow(StateType stateType) {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn("passkey");
        when(flow.getStateConfig()).thenReturn(new StateConfig(stateType.name().toLowerCase(), stateType));
        return flow;
    }

    @SuppressWarnings("unchecked")
    private static ApplicationContext context() {
        ApplicationContext context = mock(ApplicationContext.class);
        ObjectProvider<UserDetailsService> stores = mock(ObjectProvider.class);
        when(stores.getIfUnique()).thenReturn(mock(UserDetailsService.class));
        when(context.getBeanProvider(UserDetailsService.class)).thenReturn(stores);
        when(context.getBean(AuthContextProperties.class)).thenReturn(new AuthContextProperties());
        when(context.getBean(OAuth2SingleAuthSuccessHandler.class)).thenReturn(mock(OAuth2SingleAuthSuccessHandler.class));
        when(context.getBean(OAuth2SingleAuthFailureHandler.class)).thenReturn(mock(OAuth2SingleAuthFailureHandler.class));
        return context;
    }

    private Object strategyOfFilter() {
        return ReflectionTestUtils.getField(passkeyFilter, "sessionStrategy");
    }

    @Test
    void aFlowThatKeepsItsSignInInTheSessionGivesThePasskeyFilterTheStrategyOfItsChain() {
        customizer.replaceHandlers(chain, flow(StateType.SESSION), context(), false, strategyOfChain);

        assertThat(strategyOfFilter()).isInstanceOf(PasskeySessionAuthenticationStrategy.class);
        assertThat(ReflectionTestUtils.getField(strategyOfFilter(), "delegate")).isSameAs(strategyOfChain);
    }

    @Test
    void aFlowThatKeepsItsSignInInTokensLeavesTheFiltersOwn() {
        customizer.replaceHandlers(chain, flow(StateType.OAUTH2), context(), false, strategyOfChain);

        assertThat(strategyOfFilter()).isInstanceOf(NullAuthenticatedSessionStrategy.class);
    }

    @Test
    void withoutAStrategyOfTheChainTheFilterKeepsItsOwn() {
        customizer.replaceHandlers(chain, flow(StateType.SESSION), context(), false);

        assertThat(strategyOfFilter()).isInstanceOf(NullAuthenticatedSessionStrategy.class);
    }
}
