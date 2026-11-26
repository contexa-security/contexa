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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2StateAdapter;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * M3 of docs/agent/운영모드-정상화-구현계획.md on the real auto-configuration: Contexa's OAuth2 plane is there in every way of
 * running Contexa, and its components of the types Spring Boot and Spring Security pick by type for the application are beans
 * of their type only in mode FULL where the application has none (R-17); elsewhere they are held under the same names, and
 * Contexa's code takes them by those names.
 */
@DisplayName("OAuth2 평면: 네 조합 모두에 있고, 앱이 타입으로 찾는 구성요소는 R-17을 따른다")
class OAuth2PlaneInEveryCombinationTest {

    /** The components of the plane of the types Spring picks by type for the application, by Contexa's names. */
    private static final Map<String, Class<?>> SHARED = shared();

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdentityOAuth2AutoConfiguration.class))
            .withUserConfiguration(Surroundings.class);

    private static Map<String, Class<?>> shared() {
        Map<String, Class<?>> shared = new LinkedHashMap<>();
        shared.put(OAuth2StateAdapter.CONTEXA_JWT_DECODER, JwtDecoder.class);
        shared.put(OAuth2StateAdapter.CONTEXA_JWT_ENCODER, JwtEncoder.class);
        shared.put(OAuth2StateAdapter.CONTEXA_JWK_SOURCE, JWKSource.class);
        shared.put(OAuth2StateAdapter.CONTEXA_AUTHORIZATION_SERVICE, OAuth2AuthorizationService.class);
        shared.put(OAuth2StateAdapter.CONTEXA_SERVER_SETTINGS, AuthorizationServerSettings.class);
        shared.put("contexaClientRegistrationRepository", ClientRegistrationRepository.class);
        shared.put("contexaAuthorizedClientRepository", OAuth2AuthorizedClientRepository.class);
        shared.put("contexaAuthorizedClientManager", OAuth2AuthorizedClientManager.class);
        return shared;
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({"SANDBOX,HOST_OWNED", "SANDBOX,CONTEXA_OWNED", "FULL,HOST_OWNED", "FULL,CONTEXA_OWNED"})
    @DisplayName("네 조합 모두에서 Contexa의 인가 서버 구성요소와 토큰 서비스가 만들어지고 이름으로 쓸 수 있다")
    void thePlaneIsThereInEveryCombination(String mode, String ownership) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=" + mode,
                ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership).run(context -> {
            assertThat(context).hasNotFailed();
            for (Map.Entry<String, Class<?>> component : SHARED.entrySet()) {
                assertThat(ContexaOwnBeans.own(context, component.getKey(), component.getValue())).as(component.getKey())
                        .isInstanceOf(component.getValue());
            }
            assertThat(context.getBean("contexaOauth2TokenService")).isInstanceOf(OAuth2TokenService.class);
            assertThat(context).hasBean("contexaCompositeLogoutHandler").hasBean("contexaOauth2StateAdapter");
        });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"HOST_OWNED", "CONTEXA_OWNED"})
    @DisplayName("SANDBOX에서는 앱이 타입으로 찾을 때 Contexa의 OAuth2 구성요소가 하나도 보이지 않는다")
    void inSandboxTheApplicationsLookupsFindNoneOfContexas(String ownership) {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=SANDBOX",
                ContexaOperatingProfile.PROP_OWNERSHIP + "=" + ownership).run(context -> {
            for (Map.Entry<String, Class<?>> component : SHARED.entrySet()) {
                assertThat(context.getBean(component.getKey())).as(component.getKey()).isInstanceOf(HeldBean.class);
                assertThat(context.getBeanNamesForType(component.getValue())).as(component.getValue().getSimpleName()).isEmpty();
            }
        });
    }

    @Test
    @DisplayName("FULL에서 앱에 같은 타입이 없으면 Contexa의 구성요소가 그 타입의 빈이다")
    void inFullWithoutTheApplicationsOwnContexasAreOfferedByType() {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=FULL").run(context -> {
            for (Map.Entry<String, Class<?>> component : SHARED.entrySet()) {
                assertThat(context.getBeanNamesForType(component.getValue())).as(component.getValue().getSimpleName())
                        .containsExactly(component.getKey());
            }
        });
    }

    @Test
    @DisplayName("FULL에서도 앱에 같은 타입이 있으면 Contexa의 것은 보유 객체이고 앱의 것이 그 타입의 유일한 빈이다")
    void inFullBesideTheApplicationsOwnContexasAreHeld() {
        runner.withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=FULL").withUserConfiguration(ApplicationsOwn.class)
                .run(context -> {
                    assertThat(context.getBean(OAuth2StateAdapter.CONTEXA_JWT_DECODER)).isInstanceOf(HeldBean.class);
                    assertThat(context.getBean("contexaClientRegistrationRepository")).isInstanceOf(HeldBean.class);
                    assertThat(context.getBeanNamesForType(JwtDecoder.class)).containsExactly("applicationDecoder");
                    assertThat(context.getBeanNamesForType(ClientRegistrationRepository.class))
                            .containsExactly("applicationRegistrations");
                    assertThat(context.getBean(JwtDecoder.class)).isSameAs(context.getBean("applicationDecoder"));
                    assertThat(ContexaOwnBeans.own(context, OAuth2StateAdapter.CONTEXA_JWT_DECODER, JwtDecoder.class))
                            .isNotSameAs(context.getBean("applicationDecoder"));
                });
    }

    @Test
    @DisplayName("SANDBOX에서 앱 설정의 리소스 서버 해독기를 Spring Boot가 그대로 만든다")
    void inSandboxSpringBootMakesTheDecoderOfTheApplicationsProperties() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(IdentityOAuth2AutoConfiguration.class,
                        OAuth2ResourceServerAutoConfiguration.class))
                .withUserConfiguration(Surroundings.class, ApplicationsChain.class)
                .withPropertyValues(ContexaOperatingProfile.PROP_MODE + "=SANDBOX",
                        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://issuer.example.test/jwks")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanNamesForType(JwtDecoder.class)).hasSize(1)
                            .doesNotContain(OAuth2StateAdapter.CONTEXA_JWT_DECODER);
                    assertThat(context.getBean(OAuth2StateAdapter.CONTEXA_JWT_DECODER)).isInstanceOf(HeldBean.class);
                });
    }

    /**
     * What the plane is conditional on, and Contexa's client repository under its name: its own creation stores the internal
     * client in the database, which these contexts have not.
     */
    @Configuration(proxyBeanMethods = false)
    static class Surroundings {

        @Bean
        AuthContextProperties authContextProperties() {
            AuthContextProperties properties = new AuthContextProperties();
            properties.getOauth2().setClientSecret("plane-test-secret");
            return properties;
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

        @Bean(name = OAuth2StateAdapter.CONTEXA_REGISTERED_CLIENTS)
        RegisteredClientRepository contexaRegisteredClientRepository() {
            return mock(RegisteredClientRepository.class);
        }

        @Bean(name = "contexaObjectMapper")
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }

        @Bean
        SessionIdResolver sessionIdResolver() {
            return mock(SessionIdResolver.class);
        }

        @Bean
        AuthResponseWriter authResponseWriter() {
            return mock(AuthResponseWriter.class);
        }
    }

    /** An application with a decoder and client registrations of its own. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationsOwn {

        @Bean
        JwtDecoder applicationDecoder() {
            return mock(JwtDecoder.class);
        }

        @Bean
        ClientRegistrationRepository applicationRegistrations() {
            return mock(ClientRegistrationRepository.class);
        }
    }

    /** A chain of the application's, so that Spring Boot's resource server adds no chain of its own. */
    @Configuration(proxyBeanMethods = false)
    static class ApplicationsChain {

        @Bean
        SecurityFilterChain applicationChain() {
            return new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE);
        }
    }
}
