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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * A right taken from a person while a token of theirs is out, on the real chain: Spring's authorization and resource
 * server, Contexa's converter, token customizer and token service, and the refresh entry point. Only the sign-in is
 * stood in for, by the internal grant the login flows use.
 */
class TokenRightsChainIntegrationTest {

    private static final String REFRESH_URI = "/api/refresh";

    private final ObjectMapper json = new ObjectMapper();
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private InMemoryUserDetailsManager accounts;
    private JsonNode tokens;

    @BeforeEach
    void signIn() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("internal-secret");
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> beans.registerSingleton("authContextProperties", properties));
        context.register(RefreshConfig.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        accounts = (InMemoryUserDetailsManager) context.getBean("userDetailsService");
        tokens = signedIn();
    }

    @AfterEach
    void close() {
        context.close();
    }

    @Test
    @DisplayName("control: the token of a sign-in carries the account's rights")
    void aTokenCarriesTheAccountsRights() throws Exception {
        assertThat(rightsOf(accessToken())).contains("ROLE_USER", "SCOPE_read");
    }

    @Test
    @DisplayName("The token that is out loses a right on the next request")
    void theTokenThatIsOutLosesTheRight() throws Exception {
        leaveAliceWith();

        assertThat(rightsOf(accessToken())).containsExactly("SCOPE_read");
    }

    @Test
    @DisplayName("The refresh entry point hands out a new token naming what the account holds, and the old one ends")
    void theRefreshEntryPointHandsOutTheAccountAsItIsNow() throws Exception {
        String stale = accessToken();
        leaveAliceWith();

        MvcResult refreshed = refreshAtTheEntryPoint();

        assertThat(refreshed.getResponse().getStatus()).as(refreshed.getResponse().getContentAsString()).isEqualTo(200);
        String renewed = json.readTree(refreshed.getResponse().getContentAsString()).get("accessToken").asText();
        assertThat(renewed).isNotEqualTo(stale);
        assertThat(decode(renewed).getClaimAsStringList("roles")).containsExactly("SCOPE_read");
        assertThat(rightsOf(renewed)).containsExactly("SCOPE_read");
        assertThat(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + stale))
                .andReturn().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("control: with the account unchanged a good access token is kept, as before")
    void aGoodTokenOfAnUnchangedAccountIsKept() throws Exception {
        MvcResult refreshed = refreshAtTheEntryPoint();

        assertThat(refreshed.getResponse().getStatus()).as(refreshed.getResponse().getContentAsString()).isEqualTo(200);
        assertThat(json.readTree(refreshed.getResponse().getContentAsString()).get("accessToken").asText())
                .isEqualTo(accessToken());
    }

    @Test
    @DisplayName("The token endpoint hands out what the account holds as well")
    void theTokenEndpointHandsOutTheAccountAsItIsNow() throws Exception {
        leaveAliceWith();

        MvcResult refreshed = refreshAtTheTokenEndpoint();

        assertThat(refreshed.getResponse().getStatus()).as(refreshed.getResponse().getContentAsString()).isEqualTo(200);
        String renewed = json.readTree(refreshed.getResponse().getContentAsString()).get("access_token").asText();
        assertThat(decode(renewed).getClaimAsStringList("roles")).containsExactly("SCOPE_read");
    }

    @Test
    @DisplayName("A right given after the sign-in comes with the next request and the next token")
    void aRightGivenAfterTheSignIn() throws Exception {
        leaveAliceWith("ROLE_USER", "ROLE_AUDITOR");

        assertThat(rightsOf(accessToken())).contains("ROLE_AUDITOR");
        MvcResult refreshed = refreshAtTheTokenEndpoint();
        String renewed = json.readTree(refreshed.getResponse().getContentAsString()).get("access_token").asText();
        assertThat(decode(renewed).getClaimAsStringList("roles")).containsExactly("AUDITOR", "USER", "SCOPE_read");
    }

    @Test
    @DisplayName("A disabled account renews nothing, at either door, and its token ends")
    void aDisabledAccount() throws Exception {
        accounts.updateUser(alice().disabled(true).build());

        assertThat(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + accessToken()))
                .andReturn().getResponse().getStatus()).isEqualTo(401);
        assertRefusedAtBothDoors(401);
    }

    @Test
    @DisplayName("A locked account renews nothing, at either door")
    void aLockedAccount() throws Exception {
        accounts.updateUser(alice().accountLocked(true).build());

        assertRefusedAtBothDoors(401);
    }

    @Test
    @DisplayName("A deleted account renews nothing, at either door, and its token ends")
    void aDeletedAccount() throws Exception {
        accounts.deleteUser("alice");

        assertThat(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + accessToken()))
                .andReturn().getResponse().getStatus()).isEqualTo(401);
        assertRefusedAtBothDoors(401);
    }

    @Test
    @DisplayName("A stored BLOCK renews nothing, at either door")
    void aStoredBlock() throws Exception {
        when(context.getBean(ZeroTrustActionRepository.class).getCurrentAction("alice")).thenReturn(ZeroTrustAction.BLOCK);

        assertRefusedAtBothDoors(403);
    }

    private void assertRefusedAtBothDoors(int atTheEntryPoint) throws Exception {
        assertThat(refreshAtTheEntryPoint().getResponse().getStatus()).isEqualTo(atTheEntryPoint);
        assertThat(refreshAtTheTokenEndpoint().getResponse().getStatus()).isEqualTo(400);
    }

    private void leaveAliceWith(String... authorities) {
        accounts.updateUser(User.withUsername("alice").password("{noop}pw").authorities(authorities).build());
    }

    private static User.UserBuilder alice() {
        return User.withUsername("alice").password("{noop}pw").roles("USER");
    }

    private String accessToken() {
        return tokens.get("access_token").asText();
    }

    private JsonNode signedIn() throws Exception {
        MvcResult result = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic())
                        .requestAttr(OAuth2TokenRequestWrapper.INTERNAL_REQUEST_ATTRIBUTE, true)
                        .param("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue())
                        .param("username", "alice"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString());
    }

    private MvcResult refreshAtTheEntryPoint() throws Exception {
        return mvc.perform(post(REFRESH_URI)
                        .header("X-Requested-With", "XMLHttpRequest")
                        .header("X-Refresh-Token", tokens.get("refresh_token").asText()))
                .andReturn();
    }

    private MvcResult refreshAtTheTokenEndpoint() throws Exception {
        return mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic())
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", tokens.get("refresh_token").asText()))
                .andReturn();
    }

    private List<String> rightsOf(String token) throws Exception {
        MvcResult result = mvc.perform(get("/api/orders").header("Authorization", "Bearer " + token)).andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        JsonNode rights = json.readTree(result.getResponse().getContentAsString()).get("authorities");
        return json.convertValue(rights, json.getTypeFactory().constructCollectionType(List.class, String.class));
    }

    private Jwt decode(String token) {
        return context.getBean("contexaJwtDecoder", JwtDecoder.class).decode(token);
    }

    private static String basic() {
        return "Basic " + Base64.getEncoder().encodeToString("default-client:internal-secret".getBytes());
    }

    @Configuration
    @Import(OAuth2TokenChainIntegrationTest.ChainConfig.class)
    static class RefreshConfig {

        @Bean
        ZeroTrustActionRepository zeroTrustActionRepository() {
            return mock(ZeroTrustActionRepository.class);
        }

        /** The in-process token endpoint reads the issued tokens from what this handler leaves in the context. */
        @Bean
        AuthenticationSuccessHandler contexaOauth2TokenSuccessHandler(IdentityOAuth2AutoConfiguration contexaOAuth2) {
            return contexaOAuth2.oauth2TokenSuccessHandler();
        }

        @Bean
        AccountTokenGuard accountTokenGuard(IdentityOAuth2AutoConfiguration contexaOAuth2, BeanFactory beans,
                                            ObjectProvider<ZeroTrustActionRepository> actions) {
            return contexaOAuth2.accountTokenGuard(beans, actions);
        }

        @Bean
        ClientRegistrationRepository contexaClientRegistrationRepository(IdentityOAuth2AutoConfiguration contexaOAuth2,
                                                                         RegisteredClientRepository clients) {
            return contexaOAuth2.clientRegistrationRepository(clients);
        }

        @Bean
        OAuth2AuthorizedClientManager contexaAuthorizedClientManager(IdentityOAuth2AutoConfiguration contexaOAuth2,
                                                                     ClientRegistrationRepository registrations,
                                                                     ObjectProvider<FilterChainProxy> chain,
                                                                     RegisteredClientRepository clients,
                                                                     OAuth2AuthorizationService authorizations) {
            return contexaOAuth2.authorizedClientManager(registrations, chain, clients, authorizations);
        }

        @Bean
        TokenValidator contexaOauth2TokenValidator(IdentityOAuth2AutoConfiguration contexaOAuth2, BeanFactory beans,
                                                   OAuth2AuthorizationService authorizations) {
            return contexaOAuth2.oauth2TokenValidator(beans.getBean("contexaJwtDecoder", JwtDecoder.class), authorizations);
        }

        @Bean
        OAuth2TokenService contexaOauth2TokenService(IdentityOAuth2AutoConfiguration contexaOAuth2,
                                                     OAuth2AuthorizedClientManager manager,
                                                     ClientRegistrationRepository registrations,
                                                     OAuth2AuthorizationService authorizations,
                                                     TokenValidator validator, ObjectMapper objectMapper,
                                                     ObjectProvider<ZeroTrustActionRepository> actions,
                                                     ObjectProvider<AccountTokenGuard> accountGuard) {
            TokenService service = contexaOAuth2.oauth2TokenService(manager, registrations, authorizations, validator,
                    objectMapper, actions, accountGuard);
            return (OAuth2TokenService) service;
        }
    }
}
