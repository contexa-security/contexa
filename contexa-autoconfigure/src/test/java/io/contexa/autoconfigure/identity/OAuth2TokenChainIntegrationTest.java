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
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
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
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2RequestScope;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateConfigurer;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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

    private void start(boolean tokenExchange) {
        start(tokenExchange, List.of());
    }

    private void start(boolean tokenExchange, List<String> audiences) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret(INTERNAL_SECRET);
        properties.getOauth2().setTokenExchangeEnabled(tokenExchange);
        properties.getOauth2().setAudiences(audiences);
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> beans.registerSingleton("authContextProperties", properties));
        context.register(ChainConfig.class);
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

    /** A person's token as the login flows issue it: the internal authenticated-user grant. */
    private String userToken() throws Exception {
        MvcResult result = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(INTERNAL_CLIENT, INTERNAL_SECRET))
                        .requestAttr(OAuth2TokenRequestWrapper.INTERNAL_REQUEST_ATTRIBUTE, true)
                        .param("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue())
                        .param("username", "alice"))
                .andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString()).get("access_token").asText();
    }

    private Jwt decode(String token) {
        return context.getBean(JwtDecoder.class).decode(token);
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

        @Bean
        JwtDecoder jwtDecoder(IdentityOAuth2AutoConfiguration contexaOAuth2, JWKSource<SecurityContext> keys) {
            return contexaOAuth2.jwtDecoder(keys);
        }

        @Bean
        OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(IdentityOAuth2AutoConfiguration contexaOAuth2,
                                                                  ObjectProvider<DelegationRegistry> delegations,
                                                                  ObjectProvider<AgentClientDirectory> agents) {
            return contexaOAuth2.tokenCustomizer(delegations, agents);
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
                    .build();
            RegisteredClient agent = RegisteredClient.withId("agent")
                    .clientId(AGENT_CLIENT)
                    .clientSecret("{noop}" + AGENT_SECRET)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                    .scope("reports.read")
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
            return new ObjectMapper();
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
