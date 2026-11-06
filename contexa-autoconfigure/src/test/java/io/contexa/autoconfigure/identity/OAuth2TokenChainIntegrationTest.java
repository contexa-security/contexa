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
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.security.bridge.AgentTokenClaims;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.resolver.TokenDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.subject.AgentClientStatusUnavailableException;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationBody;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2RequestScope;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The OAuth2 state on a real Spring Security chain (A1-2, A1-10, A1-12, CF-06): Contexa's state adapter and
 * configurer, Contexa's keys, decoder and token customizer, Spring's authorization and resource server, and a session
 * chain ordered after the token-scoped OAuth2 chain.
 */
class OAuth2TokenChainIntegrationTest {

    private static final String AGENT_CLIENT = "report-bot-client";
    private static final String AGENT_SECRET = "agent-secret";
    private static final String INTERNAL_CLIENT = "default-client";
    private static final String INTERNAL_SECRET = "internal-secret";
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final ObjectMapper json = new ObjectMapper();
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;

    @AfterEach
    void close() {
        if (context != null) {
            context.close();
        }
    }

    @Test
    void anApprovedAgentsOwnTokenCallsTheApiThroughTheTokenChain() throws Exception {
        start(true);

        String agentToken = clientCredentials(null).get("access_token").asText();
        Jwt claims = decode(agentToken);

        assertThat(claims.getSubject()).isEqualTo(AGENT_CLIENT);
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);
        JsonNode caller = json.readTree(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + agentToken))
                .andReturn().getResponse().getContentAsString());
        assertThat(caller.get("name").asText()).isEqualTo(AGENT_CLIENT);
        assertThat(caller.get("authorities").toString()).isEqualTo("[\"SCOPE_reports.read\"]");
    }

    @Test
    void requestsWithoutATokenAreLeftToTheSessionChain() throws Exception {
        start(true);

        MvcResult page = mvc.perform(get("/page")).andReturn();
        MvcResult apiWithoutToken = mvc.perform(get("/api/orders")).andReturn();

        assertThat(page.getResponse().getStatus()).isEqualTo(302);
        assertThat(page.getResponse().getRedirectedUrl()).endsWith("/login");
        assertThat(apiWithoutToken.getResponse().getRedirectedUrl()).endsWith("/login");
        assertThat(mvc.perform(get("/login")).andReturn().getResponse().getContentAsString()).contains("<form");
    }

    @Test
    void tokenExchangeIssuesTheAgentADelegatedTokenNamingThePersonAndTheActor() throws Exception {
        start(true);
        String userToken = userToken();
        String agentToken = clientCredentials(null).get("access_token").asText();

        MvcResult exchanged = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                        .param("grant_type", TOKEN_EXCHANGE)
                        .param("subject_token", userToken)
                        .param("subject_token_type", ACCESS_TOKEN_TYPE)
                        .param("actor_token", agentToken)
                        .param("actor_token_type", ACCESS_TOKEN_TYPE)
                        .param("scope", "reports.read"))
                .andReturn();

        assertThat(exchanged.getResponse().getStatus()).as(exchanged.getResponse().getContentAsString()).isEqualTo(200);
        String delegatedToken = json.readTree(exchanged.getResponse().getContentAsString()).get("access_token").asText();
        Jwt claims = decode(delegatedToken);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getClaimAsMap("act")).containsEntry("sub", AGENT_CLIENT);
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);

        AgentTokenClaims.Agent agent = AgentTokenClaims.agent(claims.getClaims(), null,
                new BridgeProperties().getDelegation().getToken(), directory()).orElseThrow();
        assertThat(agent.delegated()).isTrue();
        assertThat(agent.agentId()).isEqualTo("report-bot");
        assertThat(agent.subject()).isEqualTo("alice");
        assertThat(agent.form()).isEqualTo(AgentTokenClaims.FORM_ACTOR_CLAIM);

        JsonNode caller = json.readTree(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + delegatedToken))
                .andReturn().getResponse().getContentAsString());
        assertThat(caller.get("name").asText()).isEqualTo("alice");
    }

    /**
     * An exchange without an actor token is issued in the person's name: no {@code act}, and the client it went to is
     * all that tells the agent. The bridge reads it so, and the delegation API takes it for the agent it is.
     */
    @Test
    void anExchangeWithoutAnActorTokenIsStillTheAgentsAndRecordsNoDelegationForThePerson() throws Exception {
        start(true);

        MvcResult exchanged = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                        .param("grant_type", TOKEN_EXCHANGE)
                        .param("subject_token", userToken())
                        .param("subject_token_type", ACCESS_TOKEN_TYPE)
                        .param("scope", "reports.read"))
                .andReturn();

        assertThat(exchanged.getResponse().getStatus()).as(exchanged.getResponse().getContentAsString()).isEqualTo(200);
        Jwt claims = decode(json.readTree(exchanged.getResponse().getContentAsString()).get("access_token").asText());
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.hasClaim("act")).isFalse();
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);

        Authentication token = new JwtAuthenticationToken(claims, List.of(), "alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContextHolder.getContext().setAuthentication(token);
        DelegationStamp stamp;
        try {
            stamp = new TokenDelegationStampResolver(directory()).resolve(request, null, new BridgeProperties())
                    .orElseThrow();
        } finally {
            SecurityContextHolder.clearContext();
        }
        assertThat(stamp.agentId()).isEqualTo("report-bot");
        assertThat(stamp.subjectId()).isEqualTo("alice");
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, stamp);

        InMemoryDelegationRegistry delegations = new InMemoryDelegationRegistry();
        AgentDelegationApiController api = new AgentDelegationApiController(
                new AgentDelegationService(delegations, directory(), null));
        Instant now = Instant.now();
        ResponseEntity<?> answer = api.record(new DelegationBody(null, null, "report-bot", null, "REPORTING",
                "Weekly report", List.of("READ"), List.of("HX-310"), false, null, null, now.minusSeconds(60),
                now.plusSeconds(3600), null, null), token, request);

        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(delegations.list(null, "alice", null, 10)).isEmpty();
    }

    @Test
    void tokenExchangeIsRefusedWhenTurnedOff() throws Exception {
        start(false);
        String userToken = userToken();

        MvcResult refused = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                        .param("grant_type", TOKEN_EXCHANGE)
                        .param("subject_token", userToken)
                        .param("subject_token_type", ACCESS_TOKEN_TYPE))
                .andReturn();

        assertThat(refused.getResponse().getStatus()).isEqualTo(400);
        assertThat(refused.getResponse().getContentAsString()).contains("unsupported_grant_type");
    }

    @Test
    void aDpopProofGetsASenderConstrainedToken() throws Exception {
        start(true);
        ECKey proofKey = new ECKeyGenerator(Curve.P_256).generate();

        JsonNode response = clientCredentials(dpopProof(proofKey, "POST", "http://localhost/oauth2/token"));

        assertThat(response.get("token_type").asText()).isEqualTo("DPoP");
        Jwt claims = decode(response.get("access_token").asText());
        assertThat(claims.getClaimAsMap("cnf")).containsEntry("jkt", proofKey.computeThumbprint().toString());
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);
    }

    @Test
    void aTokenRefusedByTheTokenChecksNeverReachesContexa() throws Exception {
        // A1-7: this application serves tokens issued to the internal client only.
        start(true, List.of(INTERNAL_CLIENT));
        AfterBearerRecorder recorder = context.getBean(AfterBearerRecorder.class);
        String agentToken = clientCredentials(null).get("access_token").asText();
        String userToken = userToken();
        int before = recorder.reached;

        MvcResult otherAudience = mvc.perform(get("/api/orders").header("Authorization", "Bearer " + agentToken)).andReturn();
        MvcResult forged = mvc.perform(get("/api/orders").header("Authorization", "Bearer " + agentToken + "x")).andReturn();

        assertThat(otherAudience.getResponse().getStatus()).isEqualTo(401);
        assertThat(forged.getResponse().getStatus()).isEqualTo(401);
        assertThat(recorder.reached).isEqualTo(before);
        assertThat(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + userToken))
                .andReturn().getResponse().getStatus()).isEqualTo(200);
        assertThat(recorder.reached).isEqualTo(before + 1);
    }

    @Test
    void contexaCannotWidenWhatTheTokensScopeGrants() throws Exception {
        start(true);
        String agentToken = clientCredentials(null).get("access_token").asText();

        assertThat(mvc.perform(get("/api/reports/write").header("Authorization", "Bearer " + agentToken))
                .andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mvc.perform(get("/api/orders").header("Authorization", "Bearer " + agentToken))
                .andReturn().getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void theUserTokenKeepsContexasClaims() throws Exception {
        start(true);

        Jwt claims = decode(userToken());

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(INTERNAL_CLIENT);
        assertThat(claims.getClaimAsStringList("roles")).contains("USER");
        assertThat(claims.hasClaim("act")).isFalse();
        assertThat(claims.hasClaim("cnf")).isFalse();
    }

    /**
     * The application's own token customizers beside Contexa's: the authorization server, which takes one customizer bean,
     * still finds exactly one, runs Contexa's checks first and keeps what the application adds.
     */
    @Test
    void anApplicationsTokenCustomizersRunAfterContexasOnTheRealTokenEndpoint() throws Exception {
        start(true, List.of(), ApplicationTokenCustomizers.class);

        Jwt claims = decode(clientCredentials(null).get("access_token").asText());

        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);
        assertThat(claims.getClaimAsString("tenant")).isEqualTo("acme");
        assertThat(claims.getClaimAsString("saw_client_id")).as("Contexa's claims were there when the application's ran")
                .isEqualTo(AGENT_CLIENT);
        assertThat(claims.getClaimAsStringList("trail")).containsExactly("first", "second");
    }

    @Test
    void anExchangeBeyondTheScopeOfTheTokenExchangedIsRefusedAlsoWhenTheApplicationCustomizesTokens() throws Exception {
        start(true, List.of(), ApplicationTokenCustomizers.class);

        MvcResult exchanged = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                        .param("grant_type", TOKEN_EXCHANGE)
                        .param("subject_token", userToken())
                        .param("subject_token_type", ACCESS_TOKEN_TYPE)
                        .param("scope", "reports.write"))
                .andReturn();

        assertThat(exchanged.getResponse().getStatus()).isEqualTo(400);
        assertThat(exchanged.getResponse().getContentAsString()).contains("invalid_scope");
    }

    /**
     * A suspended agent gets no token whatever the application customizes, and an agent whose suspension cannot be read is
     * stopped for the time being, at the token endpoint and at the resource server alike, while a person's sign-in and
     * token go on. The agent is served again once the status can be read.
     */
    @Test
    void anAgentWhoseSuspensionIsKnownOrCannotBeReadIsStoppedAndAPersonIsNot() throws Exception {
        start(true, List.of(), ApplicationTokenCustomizers.class, SwitchableDirectory.class);
        DirectoryState state = context.getBean(DirectoryState.class);
        String agentToken = clientCredentials(null).get("access_token").asText();
        String userToken = userToken();

        state.suspended = true;
        MvcResult suspended = agentTokenRequest();
        assertThat(suspended.getResponse().getStatus()).isEqualTo(400);
        assertThat(suspended.getResponse().getContentAsString()).contains("unauthorized_client");
        assertThat(callApi(agentToken)).isEqualTo(401);

        state.suspended = false;
        state.unreadable = true;
        MvcResult unreadable = agentTokenRequest();
        assertThat(unreadable.getResponse().getStatus()).isEqualTo(400);
        assertThat(unreadable.getResponse().getContentAsString()).contains("temporarily_unavailable")
                .doesNotContain("secret-host");
        assertThat(callApi(agentToken)).isEqualTo(401);
        assertThat(callApi(userToken)).as("a person's token never asks the agent registry").isEqualTo(200);
        assertThat(decode(userToken()).getClaimAsString("client_id")).as("nor does a person's sign-in")
                .isEqualTo(INTERNAL_CLIENT);

        state.unreadable = false;
        assertThat(callApi(agentToken)).isEqualTo(200);
        assertThat(agentTokenRequest().getResponse().getStatus()).isEqualTo(200);
    }

    /**
     * An application's customizer that lengthens a token cannot lengthen an exchanged token beyond the token it exchanges:
     * Contexa's limit is put on again after the application's customizers ran. A token of any other grant keeps what the
     * application made of it.
     */
    @Test
    void anApplicationCustomizerCannotLengthenAnExchangedTokenBeyondTheTokenItExchanges() throws Exception {
        start(true, List.of(), ApplicationLifetimeCustomizer.class);
        String userToken = userToken();
        Instant personEnds = decode(userToken).getExpiresAt();

        MvcResult exchanged = exchange(userToken, "reports.read");

        assertThat(exchanged.getResponse().getStatus()).as(exchanged.getResponse().getContentAsString()).isEqualTo(200);
        Jwt claims = decode(json.readTree(exchanged.getResponse().getContentAsString()).get("access_token").asText());
        assertThat(claims.getExpiresAt()).as("the exchanged token ends no later than the token it exchanges")
                .isBeforeOrEqualTo(personEnds);
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);

        Instant agentTokenEnds = decode(clientCredentials(null).get("access_token").asText()).getExpiresAt();
        assertThat(agentTokenEnds).as("the agent's own token keeps the lifetime the application gave it")
                .isAfter(Instant.now().plus(Duration.ofDays(29)));
    }

    /**
     * An application that declares its own token generator builds its tokens itself, and the authorization server then
     * never offers a token to the customizer. Contexa's checks and claims still apply to what the generator issues.
     */
    @Test
    void aSuspendedAgentGetsNoTokenAlsoWhenTheApplicationHasATokenGeneratorOfItsOwn() throws Exception {
        start(true, List.of(), ApplicationTokenGenerator.class, SwitchableDirectory.class);
        DirectoryState state = context.getBean(DirectoryState.class);

        MvcResult served = agentTokenRequest();
        assertThat(served.getResponse().getStatus()).as(served.getResponse().getContentAsString()).isEqualTo(200);
        assertThat(decode(json.readTree(served.getResponse().getContentAsString()).get("access_token").asText())
                .getClaimAsString("tenant")).as("the application's generator issued it").isEqualTo("acme");

        state.suspended = true;
        MvcResult suspended = agentTokenRequest();
        assertThat(suspended.getResponse().getStatus()).as(suspended.getResponse().getContentAsString()).isEqualTo(400);
        assertThat(suspended.getResponse().getContentAsString()).contains("unauthorized_client");

        state.suspended = false;
        state.unreadable = true;
        MvcResult unreadable = agentTokenRequest();
        assertThat(unreadable.getResponse().getStatus()).isEqualTo(400);
        assertThat(unreadable.getResponse().getContentAsString()).contains("temporarily_unavailable")
                .doesNotContain("secret-host");
        assertThat(decode(userToken()).getClaimAsString("client_id")).as("a person's sign-in never asks the agent registry")
                .isEqualTo(INTERNAL_CLIENT);

        state.unreadable = false;
        assertThat(agentTokenRequest().getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void theTokensOfAnApplicationsGeneratorCarryContexasClaimsSoTheResourceServerReadsThemAsBefore() throws Exception {
        start(true, List.of(), ApplicationTokenGenerator.class);

        String agentToken = clientCredentials(null).get("access_token").asText();
        Jwt agent = decode(agentToken);
        assertThat(agent.getClaimAsString("tenant")).isEqualTo("acme");
        assertThat(agent.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);
        assertThat(callApi(agentToken)).isEqualTo(200);

        Jwt person = decode(userToken());
        assertThat(person.getClaimAsString("tenant")).isEqualTo("acme");
        assertThat(person.getClaimAsString("client_id")).isEqualTo(INTERNAL_CLIENT);
        assertThat(person.getClaimAsStringList("roles")).contains("USER");
    }

    @Test
    void anExchangeThroughTheApplicationsGeneratorKeepsContexasRules() throws Exception {
        start(true, List.of(), ApplicationTokenGenerator.class);
        String userToken = userToken();
        Instant personEnds = decode(userToken).getExpiresAt();

        MvcResult exchanged = exchange(userToken, "reports.read");
        assertThat(exchanged.getResponse().getStatus()).as(exchanged.getResponse().getContentAsString()).isEqualTo(200);
        String delegated = json.readTree(exchanged.getResponse().getContentAsString()).get("access_token").asText();
        Jwt claims = decode(delegated);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(AGENT_CLIENT);
        assertThat(claims.getExpiresAt()).as("ends no later than the token it exchanges").isBeforeOrEqualTo(personEnds);

        MvcResult beyondScope = exchange(userToken, "reports.write");
        assertThat(beyondScope.getResponse().getStatus()).isEqualTo(400);
        assertThat(beyondScope.getResponse().getContentAsString()).contains("invalid_scope");

        MvcResult again = exchange(delegated, "reports.read");
        assertThat(again.getResponse().getStatus()).isEqualTo(400);
        assertThat(again.getResponse().getContentAsString()).contains("invalid_grant");
    }

    /**
     * An application whose own generator signs with a key the authorization server does not hold. Its tokens are the
     * application's: Contexa's checks still decide whether they are issued, but Contexa cannot sign such a token again
     * (it has not the key) and its resource server cannot verify one, so the application keeps working with them as before.
     */
    @Test
    void aGeneratorThatSignsWithAKeyOfItsOwnStillIssuesTheLoginAndTheAgentsTokenAndIsStillChecked() throws Exception {
        start(true, List.of(), ApplicationOwnKeyTokenGenerator.class, SwitchableDirectory.class);
        DirectoryState state = context.getBean(DirectoryState.class);
        IssuedTokens issued = context.getBean(IssuedTokens.class);

        String login = userToken();
        MvcResult served = agentTokenRequest();
        assertThat(served.getResponse().getStatus()).as(served.getResponse().getContentAsString()).isEqualTo(200);
        String agentToken = json.readTree(served.getResponse().getContentAsString()).get("access_token").asText();
        assertThat(issued.values).as("the tokens are the application's, byte for byte").contains(login, agentToken);
        assertThat(callApi(agentToken)).as("Contexa's resource server does not take a token it cannot verify").isEqualTo(401);

        int issuedBefore = issued.values.size();
        state.suspended = true;
        MvcResult suspended = agentTokenRequest();
        assertThat(suspended.getResponse().getStatus()).as(suspended.getResponse().getContentAsString()).isEqualTo(400);
        assertThat(suspended.getResponse().getContentAsString()).contains("unauthorized_client");

        state.suspended = false;
        state.unreadable = true;
        MvcResult unreadable = agentTokenRequest();
        assertThat(unreadable.getResponse().getStatus()).isEqualTo(400);
        assertThat(unreadable.getResponse().getContentAsString()).contains("temporarily_unavailable")
                .doesNotContain("secret-host");
        assertThat(issued.values).as("a refusal ends the issuance before the application's generator runs")
                .hasSize(issuedBefore);
        assertThat(userToken()).as("a person's sign-in never asks the agent registry").isNotBlank();

        state.unreadable = false;
        assertThat(agentTokenRequest().getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void anExchangeThroughAGeneratorWithAKeyOfItsOwnIsIssuedAsItWasAndIsRefusedBeyondTheScope() throws Exception {
        start(true, List.of(), ApplicationOwnKeyTokenGenerator.class);
        IssuedTokens issued = context.getBean(IssuedTokens.class);
        String userToken = userToken();

        MvcResult exchanged = exchange(userToken, "reports.read");
        assertThat(exchanged.getResponse().getStatus()).as(exchanged.getResponse().getContentAsString()).isEqualTo(200);
        assertThat(issued.values).contains(json.readTree(exchanged.getResponse().getContentAsString()).get("access_token").asText());

        MvcResult beyondScope = exchange(userToken, "reports.write");
        assertThat(beyondScope.getResponse().getStatus()).isEqualTo(400);
        assertThat(beyondScope.getResponse().getContentAsString()).contains("invalid_scope");
    }

    private MvcResult exchange(String subjectToken, String scope) throws Exception {
        return mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                        .param("grant_type", TOKEN_EXCHANGE)
                        .param("subject_token", subjectToken)
                        .param("subject_token_type", ACCESS_TOKEN_TYPE)
                        .param("scope", scope))
                .andReturn();
    }

    private MvcResult agentTokenRequest() throws Exception {
        return mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                        .param("grant_type", "client_credentials")
                        .param("scope", "reports.read"))
                .andReturn();
    }

    private int callApi(String token) throws Exception {
        return mvc.perform(get("/api/orders").header("Authorization", "Bearer " + token)).andReturn().getResponse().getStatus();
    }

    private void start(boolean tokenExchange) {
        start(tokenExchange, List.of());
    }

    private void start(boolean tokenExchange, List<String> audiences, Class<?>... moreConfiguration) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret(INTERNAL_SECRET);
        properties.getOauth2().setTokenExchangeEnabled(tokenExchange);
        properties.getOauth2().setAudiences(audiences);
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> beans.registerSingleton("authContextProperties", properties));
        context.register(ChainConfig.class);
        if (moreConfiguration.length > 0) {
            context.register(moreConfiguration);
        }
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private JsonNode clientCredentials(String dpopProof) throws Exception {
        var request = post("/oauth2/token")
                .header("Authorization", basic(AGENT_CLIENT, AGENT_SECRET))
                .param("grant_type", "client_credentials")
                .param("scope", "reports.read");
        if (dpopProof != null) {
            request.header("DPoP", dpopProof);
        }
        MvcResult result = mvc.perform(request).andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString());
    }

    /**
     * A person's token as the login flows issue it: the internal authenticated-user grant, with the scopes the internal
     * client is configured with (an agent's exchange gets no scope the person's token does not hold).
     */
    private String userToken() throws Exception {
        MvcResult result = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(INTERNAL_CLIENT, INTERNAL_SECRET))
                        .requestAttr(OAuth2TokenRequestWrapper.INTERNAL_REQUEST_ATTRIBUTE, true)
                        .param("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue())
                        .param("username", "alice")
                        .param("scope", "read reports.read"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString()).get("access_token").asText();
    }

    private Jwt decode(String token) {
        return context.getBean("contexaJwtDecoder", JwtDecoder.class).decode(token);
    }

    private static String dpopProof(ECKey key, String method, String uri) throws Exception {
        SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
                        .jwk(key.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().claim("htm", method).claim("htu", uri)
                        .issueTime(new Date()).jwtID(UUID.randomUUID().toString()).build());
        proof.sign(new ECDSASigner(key));
        return proof.serialize();
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
    }

    private static AgentClientDirectory directory() {
        return (tenantId, clientId) -> AGENT_CLIENT.equals(clientId) ? Optional.of("report-bot") : Optional.empty();
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    static class ChainConfig {

        private final TransactionTemplate transactionTemplate = new TransactionTemplate(mock(PlatformTransactionManager.class));

        @Bean
        IdentityOAuth2AutoConfiguration contexaOAuth2(AuthContextProperties properties) {
            return new IdentityOAuth2AutoConfiguration(transactionTemplate, properties);
        }

        @Bean
        JWKSource<SecurityContext> jwkSource(IdentityOAuth2AutoConfiguration contexaOAuth2) {
            return contexaOAuth2.jwkSource();
        }

        @Bean
        JwtEncoder jwtEncoder(IdentityOAuth2AutoConfiguration contexaOAuth2, JWKSource<SecurityContext> keys) {
            return contexaOAuth2.jwtEncoder(keys);
        }

        @Bean(name = "contexaJwtDecoder", defaultCandidate = false)
        JwtDecoder contexaJwtDecoder(IdentityOAuth2AutoConfiguration contexaOAuth2, JWKSource<SecurityContext> keys) {
            return contexaOAuth2.jwtDecoder(keys);
        }

        /** P-8: decoders of the application for purposes of its own, which neither check Contexa's tokens nor stop the chain. */
        @Bean
        JwtDecoder applicationDecoderOne() {
            return token -> {
                throw new JwtException("the application's decoder must not see Contexa's tokens");
            };
        }

        @Bean
        JwtDecoder applicationDecoderTwo() {
            return token -> {
                throw new JwtException("the application's decoder must not see Contexa's tokens");
            };
        }

        /** Contexa's token customizer as the auto-configuration builds it: its checks, then the application's customizers. */
        @Bean(name = "contexaTokenCustomizer")
        ComposedTokenCustomizer contexaTokenCustomizer(IdentityOAuth2AutoConfiguration contexaOAuth2,
                                                       ObjectProvider<DelegationRegistry> delegations,
                                                       ObjectProvider<AgentClientDirectory> agents,
                                                       ObjectProvider<AccountTokenGuard> accountGuard,
                                                       ObjectProvider<HostTokenCustomizer> applicationCustomizers) {
            return contexaOAuth2.composedTokenCustomizer(delegations, agents, accountGuard, applicationCustomizers);
        }

        @Bean
        static BeanFactoryPostProcessor contexaTokenCustomizerComposition() {
            return IdentityOAuth2AutoConfiguration.tokenCustomizerComposition();
        }

        @Bean
        AuthorizationServerSettings authorizationServerSettings(IdentityOAuth2AutoConfiguration contexaOAuth2) {
            return contexaOAuth2.authorizationServerSettings();
        }

        @Bean
        TransactionTemplate contexaTransactionTemplate() {
            return transactionTemplate;
        }

        @Bean
        RegisteredClientRepository registeredClientRepository() {
            RegisteredClient internal = RegisteredClient.withId("internal")
                    .clientId(INTERNAL_CLIENT)
                    .clientSecret("{noop}" + INTERNAL_SECRET)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("read")
                    .scope("reports.read")
                    .build();
            RegisteredClient agent = RegisteredClient.withId("agent")
                    .clientId(AGENT_CLIENT)
                    .clientSecret("{noop}" + AGENT_SECRET)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .scope("reports.read")
                    .scope("reports.write")
                    // longer than a person's token (5 minutes): an exchange never outlives the token it exchanges
                    .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
                    .build();
            return new InMemoryRegisteredClientRepository(internal, agent);
        }

        @Bean
        OAuth2AuthorizationService authorizationService() {
            return new InMemoryOAuth2AuthorizationService();
        }

        @Bean
        UserRepository userRepository() {
            UserRepository users = mock(UserRepository.class);
            Users alice = mock(Users.class);
            when(alice.getUsername()).thenReturn("alice");
            when(alice.getRoleNames()).thenReturn(List.of("ROLE_USER"));
            when(users.findByUsernameWithGroupsRolesAndPermissions("alice")).thenReturn(Optional.of(alice));
            return users;
        }

        @Bean
        UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(User.withUsername("alice").password("{noop}pw").roles("USER").build());
        }

        @Bean
        AgentClientDirectory agentClientDirectory() {
            return directory();
        }

        @Bean(name = "contexaObjectMapper")
        ObjectMapper objectMapper() {
            return new ObjectMapper().findAndRegisterModules();
        }

        @Bean
        JsonAuthResponseWriter jsonAuthResponseWriter(ObjectMapper objectMapper) {
            return new JsonAuthResponseWriter(objectMapper);
        }

        /** The agents' flow: OAuth2 state with the token request scope, ordered first. */
        @Bean
        @Order(1)
        SecurityFilterChain agentTokenChain(HttpSecurity http, ApplicationContext context) throws Exception {
            AuthenticationProcessingOptions rest = mock(AuthenticationProcessingOptions.class);
            when(rest.getLoginProcessingUrl()).thenReturn("/api/agent/login");
            AuthenticationStepConfig step = new AuthenticationStepConfig("rest_flow", AuthType.REST.name(), 50, false);
            step.addOption(AuthenticationStepConfig.OPTIONS_KEY, rest);
            Customizer<OAuth2StateConfigurer> tokenScope = oauth2 -> oauth2.requestScope(OAuth2RequestScope.TOKEN_REQUESTS);
            AuthenticationFlowConfig flow = AuthenticationFlowConfig.builder("rest_flow")
                    .stepConfigs(List.of(step))
                    .order(50)
                    .build()
                    .withStateConfig(new StateConfig("oauth2", StateType.OAUTH2), tokenScope);
            http.setSharedObject(AuthenticationFlowConfig.class, flow);
            PlatformContext platform = mock(PlatformContext.class);
            when(platform.applicationContext()).thenReturn(context);

            new OAuth2StateAdapter().apply(http, platform, flow);
            // Stands for every Contexa filter that reads the authentication (bridge, zero trust): they come after it.
            http.addFilterAfter(context.getBean(AfterBearerRecorder.class), BearerTokenAuthenticationFilter.class);
            http.authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/api/reports/write").hasAuthority("SCOPE_reports.write")
                    .anyRequest().authenticated());
            return http.build();
        }

        /** The people's flow: a session chain that takes every other request. */
        @Bean
        @Order(2)
        SecurityFilterChain sessionChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                    .formLogin(Customizer.withDefaults());
            return http.build();
        }

        @Bean
        Endpoints endpoints() {
            return new Endpoints();
        }

        @Bean
        AfterBearerRecorder afterBearerRecorder() {
            return new AfterBearerRecorder();
        }
    }

    /** Two customizers of an application: they add claims and note what Contexa's checks had written when they ran. */
    @Configuration
    static class ApplicationTokenCustomizers {

        @Bean
        @Order(2)
        OAuth2TokenCustomizer<JwtEncodingContext> second() {
            return context -> {
                context.getClaims().claim("tenant", "acme");
                context.getClaims().claim("trail", List.of("first", "second"));
            };
        }

        @Bean
        @Order(1)
        OAuth2TokenCustomizer<JwtEncodingContext> first() {
            return context -> context.getClaims().claim("saw_client_id",
                    context.getClaims().build().getClaims().get("client_id"));
        }
    }

    /** An application's customizer that lengthens every token but a person's sign-in to a month. */
    @Configuration
    static class ApplicationLifetimeCustomizer {

        @Bean
        OAuth2TokenCustomizer<JwtEncodingContext> longerLife() {
            return context -> {
                if (!AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.equals(context.getAuthorizationGrantType())) {
                    context.getClaims().expiresAt(Instant.now().plus(Duration.ofDays(30)));
                }
            };
        }
    }

    /** The tokens the application's own generator issued, in the order it issued them. */
    static class IssuedTokens {
        final List<String> values = new CopyOnWriteArrayList<>();
    }

    /** An application's own generator that signs with an RSA key of its own, which the authorization server does not hold. */
    @Configuration
    static class ApplicationOwnKeyTokenGenerator {

        @Bean
        IssuedTokens issuedTokens() {
            return new IssuedTokens();
        }

        @Bean
        OAuth2TokenGenerator<OAuth2Token> applicationTokenGenerator(IssuedTokens issued) throws Exception {
            RSAKey own = new RSAKeyGenerator(2048).keyID("host-own-" + UUID.randomUUID()).generate();
            JwtGenerator jwt = new JwtGenerator(new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(own))));
            jwt.setJwtCustomizer(context -> context.getClaims().claim("tenant", "acme"));
            OAuth2TokenGenerator<OAuth2Token> inner = new DelegatingOAuth2TokenGenerator(jwt,
                    new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
            return context -> {
                OAuth2Token token = inner.generate(context);
                if (token instanceof Jwt issuedJwt) {
                    issued.values.add(issuedJwt.getTokenValue());
                }
                return token;
            };
        }
    }

    /** An application's own token generator: it builds its tokens itself and knows nothing of Contexa's customizer. */
    @Configuration
    static class ApplicationTokenGenerator {

        @Bean
        OAuth2TokenGenerator<OAuth2Token> applicationTokenGenerator(JwtEncoder encoder) {
            JwtGenerator jwt = new JwtGenerator(encoder);
            jwt.setJwtCustomizer(context -> context.getClaims().claim("tenant", "acme"));
            return new DelegatingOAuth2TokenGenerator(jwt, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
        }
    }

    /** What the registry of agents says now. */
    static class DirectoryState {
        volatile boolean suspended;
        volatile boolean unreadable;
    }

    /** The agent registry of the chain, which can be made to say suspended or to fail. */
    @Configuration
    static class SwitchableDirectory {

        @Bean
        DirectoryState directoryState() {
            return new DirectoryState();
        }

        @Bean
        AgentClientDirectory agentClientDirectory(DirectoryState state) {
            return new AgentClientDirectory() {
                @Override
                public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                    return AGENT_CLIENT.equals(clientId) ? Optional.of("report-bot") : Optional.empty();
                }

                @Override
                public boolean suspendedAgentClient(String tenantId, String clientId) {
                    if (state.unreadable && AGENT_CLIENT.equals(clientId)) {
                        throw new AgentClientStatusUnavailableException("cannot read jdbc:postgresql://secret-host/contexa");
                    }
                    return state.suspended && AGENT_CLIENT.equals(clientId);
                }
            };
        }
    }

    /** Counts the requests that pass the bearer token filter. */
    static class AfterBearerRecorder extends OncePerRequestFilter {

        volatile int reached;

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            reached++;
            chain.doFilter(request, response);
        }
    }

    @RestController
    static class Endpoints {

        @GetMapping("/api/orders")
        Map<String, Object> orders(Authentication authentication) {
            return Map.of("name", authentication.getName(), "authorities", authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).sorted().toList());
        }

        @GetMapping("/page")
        String page() {
            return "page";
        }

        @GetMapping("/api/reports/write")
        String write() {
            return "written";
        }
    }
}
