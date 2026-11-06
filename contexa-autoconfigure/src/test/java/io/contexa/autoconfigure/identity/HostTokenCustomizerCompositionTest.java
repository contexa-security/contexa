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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * The application's own token customizers beside Contexa's checks, on the real auto-configuration. The authorization
 * server takes one {@code OAuth2TokenCustomizer<JwtEncodingContext>} bean; an application that declared its own used to
 * replace Contexa's, and with it the refusal of a suspended agent. Whether the application has none, one or several,
 * Contexa's checks run first and the application's customizers after them.
 */
class HostTokenCustomizerCompositionTest {

    /** How the authorization server looks for its customizer: by type, and several beans are an error there. */
    private static final ResolvableType WHAT_THE_SERVER_LOOKS_FOR =
            ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED")
            .withConfiguration(AutoConfigurations.of(IdentityOAuth2AutoConfiguration.class))
            .withUserConfiguration(RecordingBeans.class, OtherPartsOfTheAuthorizationServer.class);

    @Test
    void withoutAnApplicationCustomizerContexasChecksAreTheOnlyOnes() {
        runner.run(context -> {
            assertThat(context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR)).containsExactly("contexaTokenCustomizer");
            JwtEncodingContext token = accessToken("report-client");

            theServersCustomizer(context).customize(token);

            assertThat(claims(token)).containsEntry("client_id", "report-client");
        });
    }

    @Test
    void oneApplicationCustomizerRunsAfterContexasChecksAndKeepsItsClaims() {
        runner.withUserConfiguration(OneApplicationCustomizer.class).run(context -> {
            assertThat(context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR)).containsExactly("contexaTokenCustomizer");
            JwtEncodingContext token = accessToken("report-client");

            theServersCustomizer(context).customize(token);

            assertThat(claims(token)).containsEntry("client_id", "report-client").containsEntry("tenant", "acme");
            assertThat(context.getBean(Calls.class).seen).containsExactly("tenantClaim saw client_id=report-client");
        });
    }

    @Test
    void severalApplicationCustomizersRunInTheirOrderAfterContexasChecks() {
        runner.withUserConfiguration(SeveralApplicationCustomizers.class).run(context -> {
            assertThat(context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR)).containsExactly("contexaTokenCustomizer");
            JwtEncodingContext token = accessToken("report-client");

            theServersCustomizer(context).customize(token);

            assertThat(context.getBean(Calls.class).seen).containsExactly(
                    "ordered saw client_id=report-client",
                    "first saw client_id=report-client",
                    "second saw client_id=report-client",
                    "unordered saw client_id=report-client");
            assertThat(claims(token)).containsEntry("client_id", "report-client").containsEntry("first", true)
                    .containsEntry("second", true);
        });
    }

    /** Whatever the application has, a refusal of Contexa's ends the issuance before any customizer of the application runs. */
    @Test
    void aRefusalOfContexaEndsTheIssuanceWhetherTheApplicationHasNoneOneOrSeveral() {
        for (Class<?> shape : List.of(NoApplicationCustomizer.class, OneApplicationCustomizer.class,
                SeveralApplicationCustomizers.class)) {
            runner.withUserConfiguration(shape).run(context -> {
                assertThat(context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR)).as(shape.getSimpleName())
                        .containsExactly("contexaTokenCustomizer");

                assertThatThrownBy(() -> theServersCustomizer(context).customize(accessToken("sync-client")))
                        .as(shape.getSimpleName())
                        .isInstanceOfSatisfying(OAuth2AuthenticationException.class, refused ->
                                assertThat(refused.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
                assertThat(context.getBean(Calls.class).seen).as(shape.getSimpleName()).isEmpty();
            });
        }
    }

    /** A customizer of another token type is not touched, and the application's keeps its bean name. */
    @Test
    void aCustomizerOfTheApplicationKeepsItsNameAndAClaimsCustomizerIsLeftAlone() {
        runner.withUserConfiguration(OneApplicationCustomizer.class, ClaimsContextCustomizer.class).run(context -> {
            assertThat(context.containsBean("tenantClaim")).isTrue();
            assertThat(context.getBeanNamesForType(ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class,
                    OAuth2TokenClaimsContext.class))).containsExactly("opaqueClaims");
            assertThat(context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR)).containsExactly("contexaTokenCustomizer");
        });
    }

    /** An application that declared the bean of Contexa's name itself took the place on purpose; nothing of its is taken away. */
    @Test
    void anApplicationThatTookTheBeanNameItselfLosesNoCustomizer() {
        runner.withUserConfiguration(ApplicationTookTheName.class).run(context -> {
            assertThat(context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR))
                    .containsExactlyInAnyOrder("contexaTokenCustomizer", "extraCustomizer");
            assertThat(context.getBean("contexaTokenCustomizer")).isNotInstanceOf(ComposedTokenCustomizer.class);
        });
    }

    @Test
    void theCompositionIsSaidOnceAtStartAndNotWhenThereIsNothingToCompose() {
        ListAppender<ILoggingEvent> logged = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(HostTokenCustomizerDemotion.class);
        logged.start();
        logger.addAppender(logged);
        try {
            runner.withUserConfiguration(NoApplicationCustomizer.class).run(context -> { });
            assertThat(infos(logged)).isEmpty();

            runner.withUserConfiguration(SeveralApplicationCustomizers.class).run(context -> { });
            assertThat(infos(logged)).hasSize(1);
            assertThat(infos(logged).get(0).getFormattedMessage()).contains("first", "second", "ordered", "unordered");
        } finally {
            logger.detachAppender(logged);
        }
    }

    /** The bean the server finds, whatever its name: the one customizer of the context. */
    private static OAuth2TokenCustomizer<JwtEncodingContext> theServersCustomizer(ApplicationContext context) {
        String[] names = context.getBeanNamesForType(WHAT_THE_SERVER_LOOKS_FOR);
        assertThat(names).hasSize(1);
        @SuppressWarnings("unchecked")
        OAuth2TokenCustomizer<JwtEncodingContext> customizer =
                (OAuth2TokenCustomizer<JwtEncodingContext>) context.getBean(names[0]);
        return customizer;
    }

    private static Map<String, Object> claims(JwtEncodingContext context) {
        return context.getClaims().build().getClaims();
    }

    private static List<ILoggingEvent> infos(ListAppender<ILoggingEvent> logged) {
        return logged.list.stream().filter(event -> event.getLevel() == Level.INFO).toList();
    }

    private static JwtEncodingContext accessToken(String clientId) {
        RegisteredClient client = RegisteredClient.withId(clientId)
                .clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        return JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder().subject("alice"))
                .registeredClient(client)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    /** What the customizers of the application did, in order. */
    static final class Calls {
        final List<String> seen = new CopyOnWriteArrayList<>();

        void saw(String who, JwtEncodingContext context) {
            seen.add(who + " saw client_id=" + context.getClaims().build().getClaims().get("client_id"));
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class RecordingBeans {

        @Bean
        Calls calls() {
            return new Calls();
        }
    }

    /**
     * What the auto-configuration needs around the customizer, so that it starts as it does in an application: the beans it
     * is conditional on, and the ones whose own creation would reach for a database. The agent client named sync-client
     * is suspended.
     */
    @Configuration(proxyBeanMethods = false)
    static class OtherPartsOfTheAuthorizationServer {

        @Bean
        AuthContextProperties authContextProperties() {
            return new AuthContextProperties();
        }

        @Bean
        PlatformConfig platformConfig() {
            return mock(PlatformConfig.class);
        }

        @Bean(name = "contexaJdbcTemplate")
        JdbcTemplate contexaJdbcTemplate() {
            return mock(JdbcTemplate.class);
        }

        @Bean(name = "contexaTransactionTemplate")
        TransactionTemplate contexaTransactionTemplate() {
            return mock(TransactionTemplate.class);
        }

        @Bean
        OAuth2StateAdapter oauth2StateAdapter() {
            return new OAuth2StateAdapter();
        }

        @Bean(name = "contexaJwtDecoder")
        JwtDecoder jwtDecoder() {
            return mock(JwtDecoder.class);
        }

        @Bean
        JwtEncoder jwtEncoder() {
            return mock(JwtEncoder.class);
        }

        @Bean
        @SuppressWarnings("unchecked")
        JWKSource<SecurityContext> jwkSource() {
            return mock(JWKSource.class);
        }

        @Bean
        OAuth2AuthorizationService authorizationService() {
            return mock(OAuth2AuthorizationService.class);
        }

        @Bean
        RegisteredClientRepository registeredClientRepository() {
            return mock(RegisteredClientRepository.class);
        }

        @Bean
        AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
        }

        @Bean
        AccountTokenGuard accountTokenGuard() {
            return mock(AccountTokenGuard.class);
        }

        @Bean
        TokenValidator tokenValidator() {
            return mock(TokenValidator.class);
        }

        @Bean
        TokenService tokenService() {
            return mock(TokenService.class);
        }

        @Bean(name = "contexaCompositeLogoutHandler")
        CompositeLogoutHandler compositeLogoutHandler() {
            return mock(CompositeLogoutHandler.class);
        }

        @Bean(name = "contexaOauth2LogoutSuccessHandler")
        LogoutSuccessHandler logoutSuccessHandler() {
            return mock(LogoutSuccessHandler.class);
        }

        @Bean(name = "contexaClientRegistrationRepository")
        ClientRegistrationRepository clientRegistrationRepository() {
            return mock(ClientRegistrationRepository.class);
        }

        @Bean(name = "contexaAuthorizedClientRepository")
        OAuth2AuthorizedClientRepository authorizedClientRepository() {
            return mock(OAuth2AuthorizedClientRepository.class);
        }

        @Bean(name = "contexaAuthorizedClientManager")
        OAuth2AuthorizedClientManager authorizedClientManager() {
            return mock(OAuth2AuthorizedClientManager.class);
        }

        @Bean
        AgentClientDirectory agentClientDirectory() {
            return new AgentClientDirectory() {
                @Override
                public Optional<String> activeAgentForClient(String tenantId, String clientId) {
                    return Optional.empty();
                }

                @Override
                public boolean suspendedAgentClient(String tenantId, String clientId) {
                    return "sync-client".equals(clientId);
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class NoApplicationCustomizer {
    }

    @Configuration(proxyBeanMethods = false)
    static class OneApplicationCustomizer {

        /** Takes a bean of the application, as an application customizer does. */
        @Bean
        OAuth2TokenCustomizer<JwtEncodingContext> tenantClaim(Calls calls) {
            return context -> {
                calls.saw("tenantClaim", context);
                context.getClaims().claim("tenant", "acme");
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class SeveralApplicationCustomizers {

        @Bean
        OAuth2TokenCustomizer<JwtEncodingContext> unordered(Calls calls) {
            return context -> calls.saw("unordered", context);
        }

        @Bean
        @Order(2)
        OAuth2TokenCustomizer<JwtEncodingContext> second(Calls calls) {
            return context -> {
                calls.saw("second", context);
                context.getClaims().claim("second", true);
            };
        }

        @Bean
        @Order(1)
        OAuth2TokenCustomizer<JwtEncodingContext> first(Calls calls) {
            return context -> {
                calls.saw("first", context);
                context.getClaims().claim("first", true);
            };
        }

        @Bean
        OrderedByItself ordered(Calls calls) {
            return new OrderedByItself(calls);
        }
    }

    /** A customizer that carries its own order. */
    static final class OrderedByItself implements OAuth2TokenCustomizer<JwtEncodingContext>, Ordered {

        private final Calls calls;

        OrderedByItself(Calls calls) {
            this.calls = calls;
        }

        @Override
        public void customize(JwtEncodingContext context) {
            calls.saw("ordered", context);
        }

        @Override
        public int getOrder() {
            return -5;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ClaimsContextCustomizer {

        @Bean
        OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueClaims() {
            return context -> context.getClaims().claim("opaque", true);
        }
    }

    /** An application that declared the bean of Contexa's name itself, and another customizer. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationTookTheName {

        @Bean(name = "contexaTokenCustomizer")
        OAuth2TokenCustomizer<JwtEncodingContext> theApplicationsOwn() {
            return context -> { };
        }

        @Bean
        OAuth2TokenCustomizer<JwtEncodingContext> extraCustomizer() {
            return context -> { };
        }
    }
}
