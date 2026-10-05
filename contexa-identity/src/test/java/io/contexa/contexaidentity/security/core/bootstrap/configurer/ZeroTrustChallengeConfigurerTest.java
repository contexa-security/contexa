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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ZeroTrustChallengeConfigurerTest {

    @Test
    @DisplayName("A session MFA flow keeps the challenge right after the MFA page filter")
    void sessionFlowKeepsPosition() throws Exception {
        ZeroTrustChallengeFilter filter = mock(ZeroTrustChallengeFilter.class);
        HttpSecurity http = mock(HttpSecurity.class);

        new ZeroTrustChallengeConfigurer(filter).configure(flowContext(http, StateType.SESSION));

        verify(http).addFilterAfter(filter, DefaultMfaPageGeneratingFilter.class);
    }

    @Test
    @DisplayName("An OAuth2 MFA flow runs the challenge after the bearer token authentication")
    void oauth2FlowRunsAfterBearerAuthentication() throws Exception {
        ZeroTrustChallengeFilter filter = mock(ZeroTrustChallengeFilter.class);
        HttpSecurity http = mock(HttpSecurity.class);

        new ZeroTrustChallengeConfigurer(filter).configure(flowContext(http, StateType.OAUTH2));

        verify(http).addFilterBefore(filter, BasicAuthenticationFilter.class);
    }

    @Test
    @DisplayName("In a built OAuth2 chain the challenge sits between bearer authentication and authorization")
    void builtOAuth2ChainOrder() throws Exception {
        GenericApplicationContext applicationContext = new GenericApplicationContext();
        applicationContext.refresh();
        HttpSecurity http = new HttpSecurity(
                ObjectPostProcessor.identity(),
                new AuthenticationManagerBuilder(ObjectPostProcessor.identity()),
                Map.of(ApplicationContext.class, applicationContext));
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(mock(JwtDecoder.class))));
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        ZeroTrustChallengeFilter filter = mock(ZeroTrustChallengeFilter.class);

        new ZeroTrustChallengeConfigurer(filter).configure(flowContext(http, StateType.OAUTH2));
        DefaultSecurityFilterChain chain = http.build();
        List<Filter> filters = chain.getFilters();

        int bearerIndex = indexOf(filters, BearerTokenAuthenticationFilter.class);
        int challengeIndex = filters.indexOf(filter);
        int authorizationIndex = indexOf(filters, AuthorizationFilter.class);
        assertThat(bearerIndex).isNotNegative();
        assertThat(challengeIndex).isGreaterThan(bearerIndex);
        assertThat(authorizationIndex).isGreaterThan(challengeIndex);
    }

    private FlowContext flowContext(HttpSecurity http, StateType stateType) {
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        when(flowConfig.getTypeName()).thenReturn("mfa");
        when(flowConfig.getStateConfig()).thenReturn(new StateConfig(stateType.name().toLowerCase(), stateType));
        return new FlowContext(flowConfig, http, mock(PlatformContext.class), PlatformConfig.builder().build());
    }

    private int indexOf(List<Filter> filters, Class<? extends Filter> type) {
        for (int i = 0; i < filters.size(); i++) {
            if (type.isInstance(filters.get(i))) {
                return i;
            }
        }
        return -1;
    }
}
