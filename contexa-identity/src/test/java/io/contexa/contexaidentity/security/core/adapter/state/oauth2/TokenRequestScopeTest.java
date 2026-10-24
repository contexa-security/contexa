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

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A1-10: the OAuth2 chain of a token-scoped flow takes token requests, its authorization server endpoints and its
 * authentication URLs, and leaves every other request to the session flow after it.
 */
class TokenRequestScopeTest {

    private static final RequestMatcher TOKEN_ENDPOINT = PathPatternRequestMatcher.withDefaults().matcher("/oauth2/token");

    private final RequestMatcher headerScope = TokenRequestScope.matcher(new DefaultBearerTokenResolver(),
            TOKEN_ENDPOINT, Set.of("/api/agent/login"), List.of());

    @Test
    void requestWithBearerTokenBelongsToTheTokenFlow() {
        MockHttpServletRequest request = request("GET", "/api/orders");
        request.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.c2ln");

        assertThat(headerScope.matches(request)).isTrue();
    }

    @Test
    void browserPageWithoutTokenPassesToTheSessionFlow() {
        MockHttpServletRequest request = request("GET", "/dashboard");
        request.setCookies(new Cookie("JSESSIONID", "session-1"));

        assertThat(headerScope.matches(request)).isFalse();
    }

    @Test
    void malformedBearerTokenIsAnsweredByTheTokenFlow() {
        MockHttpServletRequest request = request("GET", "/api/orders");
        request.addHeader("Authorization", "Bearer not a token");

        assertThat(headerScope.matches(request)).isTrue();
    }

    @Test
    void corsPreflightAnnouncingAuthorizationBelongsToTheTokenFlow() {
        MockHttpServletRequest preflight = request("OPTIONS", "/api/orders");
        preflight.addHeader("Origin", "https://agent.example");
        preflight.addHeader("Access-Control-Request-Method", "POST");
        preflight.addHeader("Access-Control-Request-Headers", "content-type, Authorization");
        MockHttpServletRequest otherPreflight = request("OPTIONS", "/api/orders");
        otherPreflight.addHeader("Origin", "https://agent.example");
        otherPreflight.addHeader("Access-Control-Request-Method", "POST");
        otherPreflight.addHeader("Access-Control-Request-Headers", "content-type");

        assertThat(headerScope.matches(preflight)).isTrue();
        assertThat(headerScope.matches(otherPreflight)).isFalse();
    }

    @Test
    void authorizationServerEndpointsAndFlowLoginBelongToTheTokenFlow() {
        assertThat(headerScope.matches(request("POST", "/oauth2/token"))).isTrue();
        assertThat(headerScope.matches(request("POST", "/api/agent/login"))).isTrue();
        assertThat(headerScope.matches(request("POST", "/api/login"))).isFalse();
    }

    @Test
    void tokenCookieBelongsToTheTokenFlowWithTheCookieTransport() {
        TokenService tokenService = mock(TokenService.class);
        when(tokenService.resolveAccessToken(any())).thenAnswer(invocation -> {
            MockHttpServletRequest request = invocation.getArgument(0);
            return request.getCookies() != null ? "cookie-token" : null;
        });
        RequestMatcher cookieScope = TokenRequestScope.matcher(new OAuth2AccessTokenResolver(tokenService), null,
                Set.of(), List.of());
        MockHttpServletRequest withCookie = request("GET", "/orders");
        withCookie.setCookies(new Cookie("access_token", "cookie-token"));

        assertThat(cookieScope.matches(withCookie)).isTrue();
        assertThat(cookieScope.matches(request("GET", "/orders"))).isFalse();
    }

    @Test
    void chainWithoutResourceServerDoesNotTakeBearerRequests() {
        RequestMatcher authorizationServerOnly = TokenRequestScope.matcher(null, TOKEN_ENDPOINT, Set.of(), List.of());
        MockHttpServletRequest request = request("GET", "/api/orders");
        request.addHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.c2ln");

        assertThat(authorizationServerOnly.matches(request)).isFalse();
        assertThat(authorizationServerOnly.matches(request("POST", "/oauth2/token"))).isTrue();
    }

    @Test
    void applicationAddedRequestsBelongToTheTokenFlow() {
        RequestMatcher withMetadata = TokenRequestScope.matcher(new DefaultBearerTokenResolver(), null, Set.of(),
                List.of(PathPatternRequestMatcher.withDefaults().matcher("/.well-known/oauth-protected-resource")));

        assertThat(withMetadata.matches(request("GET", "/.well-known/oauth-protected-resource"))).isTrue();
    }

    @Test
    void flowPathsAreTheStepUrlsAndRefreshUri() {
        AuthenticationProcessingOptions rest = mock(AuthenticationProcessingOptions.class);
        when(rest.getLoginProcessingUrl()).thenReturn("/api/agent/login?mode=json");
        AuthenticationStepConfig step = new AuthenticationStepConfig("rest_flow", AuthType.REST.name(), 200, false);
        step.addOption(AuthenticationStepConfig.OPTIONS_KEY, rest);
        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder("rest_flow")
                .stepConfigs(List.of(step))
                .order(150)
                .build();

        Set<String> paths = TokenRequestScope.flowPaths(flow, null, "/oauth2/refresh");

        assertThat(paths).containsExactly("/oauth2/refresh", "/api/agent/login");
    }

    /**
     * An agents' MFA flow under /agent beside the people's flow: its options keep the unprefixed defaults of the
     * people's sign-in (/api/mfa/login, the one-time code URLs), which stay with the people's flow; the agents' flow
     * takes its prefix and the URLs under it (A7-0, found when the people's sign-in answered 404).
     */
    @Test
    void aPrefixedFlowTakesOnlyThePathsUnderItsPrefix() {
        AuthenticationProcessingOptions rest = mock(AuthenticationProcessingOptions.class);
        when(rest.getLoginProcessingUrl()).thenReturn("/api/mfa/login");
        AuthenticationStepConfig step = new AuthenticationStepConfig("mfa_agent", AuthType.REST.name(), 0, true);
        step.addOption(AuthenticationStepConfig.OPTIONS_KEY, rest);
        AuthenticationProcessingOptions ott = mock(AuthenticationProcessingOptions.class);
        when(ott.getLoginProcessingUrl()).thenReturn("/login/mfa-ott");
        AuthenticationStepConfig ottStep = new AuthenticationStepConfig("mfa_agent", AuthType.OTT.name(), 1, false);
        ottStep.addOption(AuthenticationStepConfig.OPTIONS_KEY, ott);
        PrimaryAuthenticationOptions primary = PrimaryAuthenticationOptions.builder()
                .restOptions(mock(RestOptions.class))
                .loginProcessingUrl("/api/mfa/login")
                .build();
        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder("mfa_agent")
                .primaryAuthenticationOptions(primary)
                .stepConfigs(List.of(step, ottStep))
                .urlPrefix("/agent")
                .order(50)
                .build();
        AuthUrlProvider mfaUrls = mock(AuthUrlProvider.class);
        when(mfaUrls.getAllMfaRelatedUrls()).thenReturn(Set.of("/agent/api/mfa/login"));
        when(mfaUrls.getMfaInProgressUrls()).thenReturn(Set.of("/agent/mfa/select-factor"));
        when(mfaUrls.getPasskeyRegistrationUrls()).thenReturn(Set.of("/webauthn/register", "/agentic/x"));

        Set<String> paths = TokenRequestScope.flowPaths(flow, mfaUrls, "/api/refresh");

        assertThat(paths).containsExactly("/api/refresh", "/agent/**", "/agent/api/mfa/login",
                "/agent/mfa/select-factor");
        RequestMatcher scope = TokenRequestScope.matcher(new DefaultBearerTokenResolver(), TOKEN_ENDPOINT, paths,
                List.of());
        assertThat(scope.matches(request("POST", "/api/mfa/login"))).isFalse();
        assertThat(scope.matches(request("POST", "/mfa/ott/generate-code"))).isFalse();
        assertThat(scope.matches(request("POST", "/login/mfa-ott"))).isFalse();
        assertThat(scope.matches(request("POST", "/agent/api/mfa/login"))).isTrue();
        assertThat(scope.matches(request("POST", "/agent/login/mfa-ott"))).isTrue();
    }

    @Test
    void flowPathsOfAnMfaFlowAreItsPagesAndEndpoints() {
        AuthUrlProvider mfaUrls = mock(AuthUrlProvider.class);
        when(mfaUrls.getAllMfaRelatedUrls()).thenReturn(Set.of("/mfa/select-factor"));
        when(mfaUrls.getMfaInProgressUrls()).thenReturn(Set.of("/api/login", "https://idp.example/login"));
        when(mfaUrls.getPasskeyRegistrationUrls()).thenReturn(Set.of("/webauthn/register"));

        Set<String> paths = TokenRequestScope.flowPaths(null, null, null);
        assertThat(paths).isEmpty();

        AuthenticationProcessingOptions rest = mock(AuthenticationProcessingOptions.class);
        AuthenticationStepConfig step = new AuthenticationStepConfig("rest_flow", AuthType.REST.name(), 200, false);
        step.addOption(AuthenticationStepConfig.OPTIONS_KEY, rest);
        AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder("rest_flow").stepConfigs(List.of(step)).build();

        assertThat(TokenRequestScope.flowPaths(flow, mfaUrls, null))
                .containsExactlyInAnyOrder("/mfa/select-factor", "/api/login", "/webauthn/register");
    }

    private static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        return request;
    }
}
