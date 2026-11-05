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

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.OAuth2TokenSettings;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.AuthorizationServerIssuer;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.client.InProcessOAuth2TokenEndpoint;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * RC PR-45. A login issues the token inside the request of the login, so with no issuer in the settings the chain runs
 * under, Spring's filter takes the issuer from that request, and the token said {@code http://host/api/login}. Spring Boot
 * makes a settings bean of its own, with no issuer, as soon as the authorization server library is on the class path, and
 * Contexa's bean, conditional on there being none, then never came to be: {@code contexa.auth.oauth2.issuer-uri} reached the
 * decoder and not the chain, and the server refused its own tokens. The form and the REST flow share this path, the state
 * adapter; the sign-in below stands for either and goes through the real in-process token endpoint on the real chain.
 */
class OAuth2IssuerAgreementTest {

    private static final String SIGN_IN = "/api/login";
    private static final String INTERNAL_CLIENT = "default-client";
    private static final String INTERNAL_SECRET = "internal-secret";
    private static final String CONFIGURED_ISSUER = "https://auth.example.test";

    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;

    @AfterEach
    void close() {
        if (context != null) {
            context.close();
        }
    }

    // IS-01: the cause, and a guard on the premise of the other cases
    @Test
    void springBootMakesASettingsBeanThatNamesNoIssuer() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(OAuth2AuthorizationServerAutoConfiguration.class))
                .run(started -> assertThat(started.getBean(AuthorizationServerSettings.class).getIssuer()).isNull());
    }

    // IS-02: the measurement
    @Test
    void theConfiguredIssuerIssuesAndChecksOverSpringBootsSettings() throws Exception {
        start(AuthorizationServerSettings.builder().build(), CONFIGURED_ISSUER);

        String token = signIn();

        assertThat(issuerOf(token)).isEqualTo(CONFIGURED_ISSUER);
        assertThat(callWith(token)).isEqualTo(200);
    }

    // IS-03: the default the documentation names
    @Test
    void withoutAConfiguredIssuerTheDocumentedDefaultIssuesAndChecks() throws Exception {
        start(AuthorizationServerSettings.builder().build(), new AuthContextProperties().getOauth2().getIssuerUri());

        String token = signIn();

        assertThat(issuerOf(token)).isEqualTo("http://localhost:9000");
        assertThat(callWith(token)).isEqualTo(200);
    }

    // IS-04: an issuer the application gives in the settings stays the application's
    @Test
    void theIssuerOfTheApplicationsSettingsIssuesAndChecks() throws Exception {
        start(AuthorizationServerSettings.builder().issuer("https://application.example.test").build(), CONFIGURED_ISSUER);

        String token = signIn();

        assertThat(issuerOf(token)).isEqualTo("https://application.example.test");
        assertThat(callWith(token)).isEqualTo(200);
    }

    // IS-05: Contexa's own settings, where nothing made a settings bean first
    @Test
    void contexasOwnSettingsIssueAndCheckTheSame() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri(CONFIGURED_ISSUER);
        start(new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties).authorizationServerSettings(), CONFIGURED_ISSUER);

        String token = signIn();

        assertThat(issuerOf(token)).isEqualTo(CONFIGURED_ISSUER);
        assertThat(callWith(token)).isEqualTo(200);
    }

    // IS-06: an empty key is a choice the settings allow: the request names the issuer and nothing checks it
    @Test
    void anEmptyIssuerLeavesTheTokenAcceptable() throws Exception {
        start(AuthorizationServerSettings.builder().build(), "");

        assertThat(callWith(signIn())).isEqualTo(200);
    }

    // IS-07: the bean belongs to whoever made it: an authorization server of the application keeps what it has
    @Test
    void theSettingsBeanItselfStaysAsItWasMade() throws Exception {
        AuthorizationServerSettings shared = AuthorizationServerSettings.builder().build();
        start(shared, CONFIGURED_ISSUER);

        assertThat(issuerOf(signIn())).isEqualTo(CONFIGURED_ISSUER);

        assertThat(context.getBean(AuthorizationServerSettings.class)).isSameAs(shared);
        assertThat(shared.getIssuer()).isNull();
    }

    // IS-09: several issuers on one host are the application's choice: no single issuer can be set or expected
    @Test
    void settingsWithSeveralIssuersStayAsTheyAre() {
        AuthorizationServerSettings several = AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
        OAuth2TokenSettings oauth2 = new AuthContextProperties().getOauth2();

        assertThat(AuthorizationServerIssuer.applyTo(several, oauth2)).isSameAs(several);
        assertThat(AuthorizationServerIssuer.of(several, oauth2)).isNull();
    }

    // IS-08: the key the message names is the key the settings are read from
    @Test
    void theMessageOfAMissingIssuerNamesTheKeyContexaReads() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("");
        Logger logger = (Logger) LoggerFactory.getLogger(IdentityOAuth2AutoConfiguration.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties).authorizationServerSettings();
        } finally {
            logger.detachAppender(appender);
        }

        assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message).contains("contexa.auth.oauth2.issuer-uri").doesNotContain("spring.auth"));
    }

    private void start(AuthorizationServerSettings settings, String issuerUri) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret(INTERNAL_SECRET);
        properties.getOauth2().setIssuerUri(issuerUri);
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> {
            beans.registerSingleton("authContextProperties", properties);
            beans.registerSingleton("authorizationServerSettings", settings);
        });
        context.register(ChainConfig.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private String signIn() throws Exception {
        MvcResult result = mvc.perform(post(SIGN_IN)).andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return result.getResponse().getContentAsString();
    }

    private int callWith(String token) throws Exception {
        return mvc.perform(get("/api/orders").header("Authorization", "Bearer " + token)).andReturn().getResponse().getStatus();
    }

    private static String issuerOf(String token) throws Exception {
        return SignedJWT.parse(token).getJWTClaimsSet().getIssuer();
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

        @Bean(name = OAuth2StateAdapter.CONTEXA_JWT_DECODER)
        JwtDecoder contexaJwtDecoder(IdentityOAuth2AutoConfiguration contexaOAuth2, JWKSource<SecurityContext> keys,
                                     ObjectProvider<AuthorizationServerSettings> settings) {
            return contexaOAuth2.jwtDecoder(keys, settings);
        }

        @Bean
        OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(IdentityOAuth2AutoConfiguration contexaOAuth2,
                                                                  ObjectProvider<DelegationRegistry> delegations,
                                                                  ObjectProvider<AgentClientDirectory> agents,
                                                                  ObjectProvider<AccountTokenGuard> accountGuard) {
            return contexaOAuth2.tokenCustomizer(delegations, agents, accountGuard);
        }

        @Bean("contexaOauth2TokenSuccessHandler")
        AuthenticationSuccessHandler tokenSuccessHandler(IdentityOAuth2AutoConfiguration contexaOAuth2) {
            return contexaOAuth2.oauth2TokenSuccessHandler();
        }

        @Bean
        TransactionTemplate contexaTransactionTemplate() {
            return transactionTemplate;
        }

        @Bean
        RegisteredClientRepository registeredClientRepository() {
            return new InMemoryRegisteredClientRepository(RegisteredClient.withId("internal")
                    .clientId(INTERNAL_CLIENT)
                    .clientSecret("{noop}" + INTERNAL_SECRET)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("read")
                    .build());
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

        @Bean(name = "contexaObjectMapper")
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        JsonAuthResponseWriter jsonAuthResponseWriter(ObjectMapper objectMapper) {
            return new JsonAuthResponseWriter(objectMapper);
        }

        @Bean
        Endpoints endpoints() {
            return new Endpoints();
        }

        @Bean
        SecurityFilterChain tokenChain(HttpSecurity http, ApplicationContext context, RegisteredClientRepository clients,
                                       OAuth2AuthorizationService authorizations) throws Exception {
            PlatformContext platform = mock(PlatformContext.class);
            when(platform.applicationContext()).thenReturn(context);

            new OAuth2StateAdapter().apply(http, platform);
            http.addFilterBefore(new SignIn(new InProcessOAuth2TokenEndpoint(context.getBeanProvider(FilterChainProxy.class),
                    new ClientSecretBasicAuthenticationConverter(), new ClientSecretAuthenticationProvider(clients, authorizations))),
                    BearerTokenAuthenticationFilter.class);
            http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
            return http.build();
        }
    }

    /** Stands for a login filter whose success handler asks the token engine for the user's token. */
    static final class SignIn extends OncePerRequestFilter {

        private final InProcessOAuth2TokenEndpoint endpoint;

        SignIn(InProcessOAuth2TokenEndpoint endpoint) {
            this.endpoint = endpoint;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            if (!SIGN_IN.equals(request.getRequestURI())) {
                chain.doFilter(request, response);
                return;
            }
            OAuth2AccessTokenResponse issued = endpoint.exchange(request, response, current -> OAuth2TokenRequestWrapper
                    .authenticatedUser(current, "alice", null, INTERNAL_CLIENT, INTERNAL_SECRET, Set.of("read")));
            response.getWriter().write(issued.getAccessToken().getTokenValue());
        }
    }

    @RestController
    static class Endpoints {

        @GetMapping("/api/orders")
        String orders(Authentication authentication) {
            return authentication.getName();
        }
    }
}
