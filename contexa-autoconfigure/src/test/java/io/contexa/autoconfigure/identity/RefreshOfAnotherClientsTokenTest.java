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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The refresh entry point on the real chain, with a token issued to another client than Contexa's own. The entry point
 * has no client authentication: it answers for the internal client. A refresh token of a partner's application is good
 * only with that application's secret, at the token endpoint.
 */
class RefreshOfAnotherClientsTokenTest {

    private static final String REFRESH_URI = "/api/refresh";
    private static final String PARTNER_SECRET = "partner-secret";
    private static final String ACCESS_VALUE = "partner-access-token";
    private static final String REFRESH_VALUE = "partner-refresh-token";

    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private RegisteredClient partner;

    @BeforeEach
    void start() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("internal-secret");
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> beans.registerSingleton("authContextProperties", properties));
        context.register(TokenRightsChainIntegrationTest.RefreshConfig.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        partner = RegisteredClient.withId("partner")
                .clientId("partner-app")
                .clientSecret("{noop}" + PARTNER_SECRET)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://partner.example.test/callback")
                .scope("read")
                .build();
        context.getBean(RegisteredClientRepository.class).save(partner);
    }

    @AfterEach
    void close() {
        context.close();
    }

    private void partnerHoldsTokensIssued(Instant issuedAt) {
        OAuth2AccessToken access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_VALUE, issuedAt,
                issuedAt.plus(Duration.ofHours(1)), Set.of("read"));
        context.getBean(OAuth2AuthorizationService.class).save(OAuth2Authorization.withRegisteredClient(partner)
                .id("partner-sign-in")
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("read"))
                .attribute(Principal.class.getName(),
                        UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()))
                .accessToken(access)
                .refreshToken(new OAuth2RefreshToken(REFRESH_VALUE, issuedAt, issuedAt.plus(Duration.ofDays(7))))
                .build());
    }

    private MvcResult refreshAtTheEntryPoint() throws Exception {
        return mvc.perform(post(REFRESH_URI)
                        .header("X-Requested-With", "XMLHttpRequest")
                        .header("X-Refresh-Token", REFRESH_VALUE))
                .andReturn();
    }

    @Test
    @DisplayName("a still valid access token of another client is not handed to whoever holds its refresh token")
    void aValidAccessTokenStaysWithItsClient() throws Exception {
        partnerHoldsTokensIssued(Instant.now());

        MvcResult refused = refreshAtTheEntryPoint();

        assertThat(refused.getResponse().getContentAsString()).doesNotContain(ACCESS_VALUE);
        assertThat(refused.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("control: an expired access token of another client was refused by the token endpoint already")
    void anExpiredAccessTokenWasRefusedAlready() throws Exception {
        partnerHoldsTokensIssued(Instant.now().minus(Duration.ofHours(2)));

        assertThat(refreshAtTheEntryPoint().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("control: the client renews its own tokens at the token endpoint with its secret")
    void theClientRenewsItsTokensWithItsSecret() throws Exception {
        partnerHoldsTokensIssued(Instant.now().minus(Duration.ofHours(2)));

        MvcResult renewed = mvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + Base64.getEncoder()
                                .encodeToString(("partner-app:" + PARTNER_SECRET).getBytes()))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", REFRESH_VALUE))
                .andReturn();

        assertThat(renewed.getResponse().getStatus()).as(renewed.getResponse().getContentAsString()).isEqualTo(200);
    }
}
