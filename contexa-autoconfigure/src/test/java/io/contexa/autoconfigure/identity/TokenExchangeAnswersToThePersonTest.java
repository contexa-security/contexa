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
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * An agent's exchange of a person's token answers to the person as a renewal of it does, on the real chain (Spring's token
 * endpoint and exchange provider, Contexa's token customizer): no token while a decision in force stops the person or
 * while the account is locked or disabled, and no scope the person's token does not hold.
 */
class TokenExchangeAnswersToThePersonTest {

    private static final String AGENT = "report-bot-client:agent-secret";
    private static final String INTERNAL = "default-client:internal-secret";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final ObjectMapper json = new ObjectMapper();
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private InMemoryUserDetailsManager accounts;
    private ZeroTrustActionRepository decisions;

    @BeforeEach
    void start() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("internal-secret");
        properties.getOauth2().setTokenExchangeEnabled(true);
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> beans.registerSingleton("authContextProperties", properties));
        context.register(ExchangeConfig.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        accounts = (InMemoryUserDetailsManager) context.getBean("userDetailsService");
        decisions = context.getBean(ZeroTrustActionRepository.class);
    }

    @AfterEach
    void close() {
        context.close();
    }

    @Test
    void controlAnOpenAccountWithNoDecisionIsExchanged() throws Exception {
        MvcResult exchanged = exchange(personToken(), "reports.read");

        assertThat(exchanged.getResponse().getStatus()).as(body(exchanged)).isEqualTo(200);
    }

    @ParameterizedTest
    @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "CHALLENGE", "ESCALATE"})
    void aDecisionInForceOnThePersonRefusesTheExchange(ZeroTrustAction action) throws Exception {
        String personToken = personToken();
        when(decisions.getCurrentAction("alice")).thenReturn(action);

        MvcResult exchanged = exchange(personToken, "reports.read");

        assertThat(exchanged.getResponse().getStatus()).as(body(exchanged)).isEqualTo(400);
        assertThat(body(exchanged)).contains("access_denied");
    }

    @Test
    void aLockedAccountIsNotExchanged() throws Exception {
        String personToken = personToken();
        accounts.updateUser(User.withUsername("alice").password("{noop}pw").roles("USER").accountLocked(true).build());

        MvcResult exchanged = exchange(personToken, "reports.read");

        assertThat(exchanged.getResponse().getStatus()).as(body(exchanged)).isEqualTo(400);
        assertThat(body(exchanged)).contains("invalid_grant");
    }

    @Test
    void aDisabledAccountIsNotExchanged() throws Exception {
        String personToken = personToken();
        accounts.updateUser(User.withUsername("alice").password("{noop}pw").roles("USER").disabled(true).build());

        MvcResult exchanged = exchange(personToken, "reports.read");

        assertThat(exchanged.getResponse().getStatus()).as(body(exchanged)).isEqualTo(400);
        assertThat(body(exchanged)).contains("invalid_grant");
    }

    @Test
    void anExchangeGetsTheScopesThePersonsTokenAndTheClientShare() throws Exception {
        MvcResult exchanged = exchange(personToken(), "reports.read");

        assertThat(exchanged.getResponse().getStatus()).as(body(exchanged)).isEqualTo(200);
        String token = json.readTree(body(exchanged)).get("access_token").asText();
        assertThat(context.getBean("contexaJwtDecoder", JwtDecoder.class).decode(token).getClaimAsStringList("scope"))
                .containsExactly("reports.read");
    }

    @Test
    void aScopeTheClientHoldsAndThePersonsTokenDoesNotIsRefused() throws Exception {
        MvcResult wider = exchange(personToken(), "reports.write");
        MvcResult mixed = exchange(personToken(), "reports.read reports.write");

        assertThat(wider.getResponse().getStatus()).as(body(wider)).isEqualTo(400);
        assertThat(body(wider)).contains("invalid_scope");
        assertThat(mixed.getResponse().getStatus()).as(body(mixed)).isEqualTo(400);
        assertThat(body(mixed)).contains("invalid_scope");
    }

    @Test
    void controlAScopeThePersonsTokenHoldsAndTheClientDoesNotIsRefusedAsBefore() throws Exception {
        MvcResult exchanged = exchange(personToken(), "read");

        assertThat(exchanged.getResponse().getStatus()).as(body(exchanged)).isEqualTo(400);
        assertThat(body(exchanged)).contains("invalid_scope");
    }

    /** The person's token as the login flows issue it, with the scopes the internal client is configured with. */
    private String personToken() throws Exception {
        MvcResult result = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(INTERNAL))
                        .requestAttr(OAuth2TokenRequestWrapper.INTERNAL_REQUEST_ATTRIBUTE, true)
                        .param("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue())
                        .param("username", "alice")
                        .param("scope", "read reports.read"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).as(body(result)).isEqualTo(200);
        JsonNode issued = json.readTree(body(result));
        return issued.get("access_token").asText();
    }

    private MvcResult exchange(String subjectToken, String scope) throws Exception {
        return mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT))
                        .param("grant_type", TOKEN_EXCHANGE)
                        .param("subject_token", subjectToken)
                        .param("subject_token_type", ACCESS_TOKEN_TYPE)
                        .param("scope", scope))
                .andReturn();
    }

    private static String body(MvcResult result) throws Exception {
        return result.getResponse().getContentAsString();
    }

    private static String basic(String credentials) {
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());
    }

    @Configuration
    @Import(OAuth2TokenChainIntegrationTest.ChainConfig.class)
    static class ExchangeConfig {

        @Bean
        ZeroTrustActionRepository zeroTrustActionRepository() {
            return mock(ZeroTrustActionRepository.class);
        }

        @Bean
        AccountTokenGuard accountTokenGuard(IdentityOAuth2AutoConfiguration contexaOAuth2, BeanFactory beans,
                                            ObjectProvider<ZeroTrustActionRepository> actions) {
            return contexaOAuth2.accountTokenGuard(beans, actions);
        }
    }
}
