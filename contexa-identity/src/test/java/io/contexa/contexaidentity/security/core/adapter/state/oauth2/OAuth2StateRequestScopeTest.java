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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A1-10: an OAuth2 flow with the token request scope narrows its chain to token requests and its authentication
 * URLs; without the option the chain is left as it was.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2StateRequestScopeTest {

    @Mock
    private HttpSecurity http;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private ObjectProvider<BearerTokenResolver> resolverProvider;

    private final AuthContextProperties properties = new AuthContextProperties();

    @BeforeEach
    void setUp() throws Exception {
        properties.setOauth2ServerMode(OAuth2ServerMode.RESOURCE_SERVER);
        when(http.getSharedObject(ApplicationContext.class)).thenReturn(applicationContext);
        when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(properties);
        when(applicationContext.getBeanNamesForType(BearerTokenResolver.class)).thenReturn(new String[0]);
        when(applicationContext.getBeanProvider(BearerTokenResolver.class)).thenReturn(resolverProvider);
        when(http.oauth2ResourceServer(any())).thenReturn(http);
    }

    @Test
    void defaultScopeLeavesTheChainTakingEveryRequest() throws Exception {
        OAuth2StateConfigurer configurer = new OAuth2StateConfigurer(OAuth2ServerMode.RESOURCE_SERVER);
        configurer.setBuilder(http);

        configurer.init(http);

        assertThat(configurer.getRequestScope()).isEqualTo(OAuth2RequestScope.ALL_REQUESTS);
        verify(http, never()).securityMatcher(any(RequestMatcher.class));
    }

    @Test
    void tokenScopeNarrowsTheChainToTokenRequestsAndTheFlowLogin() throws Exception {
        AuthenticationFlowConfig flow = restFlow("/api/agent/login");
        when(http.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(flow);
        OAuth2StateConfigurer configurer = new OAuth2StateConfigurer(OAuth2ServerMode.RESOURCE_SERVER)
                .requestScope(OAuth2RequestScope.TOKEN_REQUESTS)
                .tokenScopeRequests(PathPatternRequestMatcher.withDefaults().matcher("/.well-known/oauth-protected-resource"));
        configurer.setBuilder(http);

        configurer.init(http);

        ArgumentCaptor<RequestMatcher> scope = ArgumentCaptor.forClass(RequestMatcher.class);
        verify(http).securityMatcher(scope.capture());
        MockHttpServletRequest bearer = request("GET", "/api/orders");
        bearer.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.c2ln");
        assertThat(scope.getValue().matches(bearer)).isTrue();
        assertThat(scope.getValue().matches(request("POST", "/api/agent/login"))).isTrue();
        assertThat(scope.getValue().matches(request("GET", "/.well-known/oauth-protected-resource"))).isTrue();
        assertThat(scope.getValue().matches(request("GET", "/dashboard"))).isFalse();
        assertThat(scope.getValue().matches(request("POST", "/api/login"))).isFalse();
    }

    @Test
    void adapterAppliesTheFlowsOauth2Customizer() throws Exception {
        PlatformContext platformContext = mock(PlatformContext.class);
        when(platformContext.applicationContext()).thenReturn(applicationContext);
        when(applicationContext.getBean(ObjectMapper.class)).thenReturn(mock(ObjectMapper.class));
        when(applicationContext.getBean(JsonAuthResponseWriter.class)).thenReturn(mock(JsonAuthResponseWriter.class));
        when(applicationContext.getBean(JwtDecoder.class)).thenReturn(mock(JwtDecoder.class));
        Customizer<OAuth2StateConfigurer> customizer = oauth2 -> oauth2.requestScope(OAuth2RequestScope.TOKEN_REQUESTS);
        AuthenticationFlowConfig flow = restFlow("/api/agent/login").withStateConfig(
                new StateConfig("oauth2", StateType.OAUTH2), customizer);

        new OAuth2StateAdapter().apply(http, platformContext, flow);

        verify(http).with(any(OAuth2StateConfigurer.class), same(customizer));
    }

    private static AuthenticationFlowConfig restFlow(String loginProcessingUrl) {
        AuthenticationProcessingOptions rest = mock(AuthenticationProcessingOptions.class);
        when(rest.getLoginProcessingUrl()).thenReturn(loginProcessingUrl);
        AuthenticationStepConfig step = new AuthenticationStepConfig("rest_flow", AuthType.REST.name(), 150, false);
        step.addOption(AuthenticationStepConfig.OPTIONS_KEY, rest);
        return AuthenticationFlowConfig.builder("rest_flow").stepConfigs(List.of(step)).order(150).build();
    }

    private static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        return request;
    }
}
