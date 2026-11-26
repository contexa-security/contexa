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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contexa's password sign-in for a flow that signs Contexa's accounts in: Contexa's provider decides, once, and no other
 * provider or manager is asked; for a flow of the application's users whose components win nothing changes. The flow of
 * Contexa's administrators always signs Contexa's accounts in (R-13, R-17 of docs/agent/운영모드-정상화-구현계획.md).
 */
class ContexaPasswordSignInTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(SignInBeans.class);

    @Test
    void whereContexaOwnsTheSignInContexasProviderDecidesOnceAndNoOtherProviderIsAsked() {
        runner.withPropertyValues("contexa.ai.security.mode=FULL").run(context -> {
            AuthenticationManager signIn = ContexaPasswordSignIn.manager(null, context);
            CountingProvider provider = context.getBean(ContexaPasswordSignIn.PROVIDER_BEAN, CountingProvider.class);
            CountingProvider applicationProvider = context.getBean("applicationProvider", CountingProvider.class);
            CountingPublisher events = context.getBean(CountingPublisher.class);

            assertThat(signIn).isNotNull();
            assertThatThrownBy(() -> signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "wrong")))
                    .isInstanceOf(BadCredentialsException.class);
            assertThat(provider.calls.get()).as("a refused password is checked once").isEqualTo(1);
            assertThat(events.failures.get()).isEqualTo(1);

            Authentication signedIn = signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "right"));
            assertThat(signedIn.isAuthenticated()).isTrue();
            assertThat(signedIn.getName()).isEqualTo("admin");
            assertThat(provider.calls.get()).isEqualTo(2);
            assertThat(events.successes.get()).isEqualTo(1);

            assertThatThrownBy(() -> signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("locked", "right")))
                    .isInstanceOf(LockedException.class);
            assertThat(events.failures.get()).isEqualTo(2);
            assertThat(applicationProvider.calls.get()).as("the application's provider is never asked").isZero();
        });
    }

    @Test
    void whereTheApplicationOwnsTheSignInTheChainsManagerStays() {
        runner.withPropertyValues("contexa.ai.security.mode=SANDBOX")
                .run(context -> assertThat(ContexaPasswordSignIn.manager(null, context)).isNull());
    }

    @Test
    void withoutContexasProviderTheChainsManagerStays() {
        new ApplicationContextRunner().withPropertyValues("contexa.ai.security.mode=FULL")
                .run(context -> assertThat(ContexaPasswordSignIn.manager(null, context)).isNull());
    }

    @Test
    void theSignInIsObservedAsTheChainsManagerIs() {
        runner.withUserConfiguration(Observation.class).withPropertyValues("contexa.ai.security.mode=FULL").run(context -> {
            AuthenticationManager signIn = ContexaPasswordSignIn.manager(null, context);

            assertThat(signIn).isInstanceOf(ObservedManager.class);
            assertThat(signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "right"))
                    .isAuthenticated()).isTrue();
            assertThat(context.getBean(ContexaPasswordSignIn.PROVIDER_BEAN, CountingProvider.class).calls.get()).isEqualTo(1);
        });
    }

    @Test
    @DisplayName("관리자 흐름은 SANDBOX + HOST_OWNED에서도 Contexa 제공자 하나로 판단한다")
    void theFlowOfContexasAdministratorsSignsContexasAccountsInWhateverTheMode() {
        runner.withPropertyValues("contexa.ai.security.mode=SANDBOX").run(context -> {
            AuthenticationManager signIn = ContexaPasswordSignIn.manager(adminFlow(), context);

            assertThat(signIn).isNotNull();
            assertThat(signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "right")).isAuthenticated()).isTrue();
            assertThat(context.getBean("applicationProvider", CountingProvider.class).calls.get()).isZero();
        });
    }

    @Test
    @DisplayName("보유 객체로 둔 Contexa 제공자를 풀어 쓴다")
    void aHeldProviderIsTakenOutOfItsHolder() {
        new ApplicationContextRunner().withUserConfiguration(HeldProvider.class).withPropertyValues("contexa.ai.security.mode=SANDBOX")
                .run(context -> {
                    AuthenticationManager signIn = ContexaPasswordSignIn.manager(adminFlow(), context);

                    assertThat(signIn).isNotNull();
                    assertThat(signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "right")).isAuthenticated()).isTrue();
                });
    }

    @Test
    @DisplayName("관리자 흐름은 주소 제한을 먼저 묻고 로그인 정책 이벤트를 보낸다")
    void theAdministratorsSignInAsksTheAddressGateFirstAndReportsToThePolicy() {
        runner.withUserConfiguration(AdminPolicy.class).withPropertyValues("contexa.ai.security.mode=SANDBOX").run(context -> {
            AuthenticationManager signIn = ContexaPasswordSignIn.manager(adminFlow(), context);
            CountingPublisher adminEvents = context.getBean("adminEventsInside", CountingPublisher.class);
            CountingPublisher applicationEvents = context.getBean("publisher", CountingPublisher.class);

            assertThatThrownBy(() -> signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("throttled", "right")))
                    .isInstanceOf(LockedException.class);
            assertThat(context.getBean(ContexaPasswordSignIn.PROVIDER_BEAN, CountingProvider.class).calls.get())
                    .as("a throttled address never reaches the password").isZero();
            signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "right"));
            assertThat(adminEvents.successes.get()).isEqualTo(1);
            assertThat(applicationEvents.successes.get()).as("the application's publisher hears nothing of it").isZero();
        });
    }

    private static HttpSecurityBuilder<?> adminFlow() {
        AuthenticationFlowConfig flow = mock(AuthenticationFlowConfig.class);
        when(flow.getTypeName()).thenReturn(ContexaSignInRealm.adminFlowTypeName());
        HttpSecurityBuilder<?> http = mock(HttpSecurityBuilder.class);
        when(http.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(flow);
        return http;
    }

    @Configuration(proxyBeanMethods = false)
    static class HeldProvider {

        @Bean(ContexaPasswordSignIn.PROVIDER_BEAN)
        HeldBean<AuthenticationProvider> contexaProvider() {
            return new HeldBean<>(new CountingProvider());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class AdminPolicy {

        @Bean
        CountingPublisher adminEventsInside() {
            return new CountingPublisher();
        }

        @Bean(ContexaAdminRealm.SIGN_IN_EVENTS_BEAN)
        HeldBean<AuthenticationEventPublisher> adminEvents(CountingPublisher adminEventsInside) {
            return new HeldBean<>(adminEventsInside);
        }

        @Bean(ContexaAdminRealm.ADDRESS_GATE_BEAN)
        HeldBean<AuthenticationProvider> addressGate() {
            return new HeldBean<>(new AuthenticationProvider() {
                @Override
                public Authentication authenticate(Authentication authentication) {
                    if ("throttled".equals(authentication.getName())) {
                        throw new LockedException("Too many attempts from this address");
                    }
                    return null;
                }

                @Override
                public boolean supports(Class<?> authentication) {
                    return true;
                }
            });
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class SignInBeans {

        @Bean(ContexaPasswordSignIn.PROVIDER_BEAN)
        CountingProvider contexaProvider() {
            return new CountingProvider();
        }

        @Bean
        CountingProvider applicationProvider() {
            return new CountingProvider();
        }

        @Bean
        CountingPublisher publisher() {
            return new CountingPublisher();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Observation {

        @Bean
        ObjectPostProcessor<AuthenticationManager> observation() {
            return new ObjectPostProcessor<>() {
                @Override
                @SuppressWarnings("unchecked")
                public <O extends AuthenticationManager> O postProcess(O manager) {
                    return (O) new ObservedManager(manager);
                }
            };
        }
    }

    record ObservedManager(AuthenticationManager delegate) implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) {
            return delegate.authenticate(authentication);
        }
    }

    /** Signs 'admin' in with "right", refuses any other password, and says 'locked' is locked. */
    static final class CountingProvider implements AuthenticationProvider {

        final AtomicInteger calls = new AtomicInteger();

        @Override
        public Authentication authenticate(Authentication authentication) {
            calls.incrementAndGet();
            if ("locked".equals(authentication.getName())) {
                throw new LockedException("Account is locked");
            }
            if (!"right".equals(authentication.getCredentials())) {
                throw new BadCredentialsException("Invalid username or password.");
            }
            return UsernamePasswordAuthenticationToken.authenticated(authentication.getName(), null, List.of());
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }

    static final class CountingPublisher implements AuthenticationEventPublisher {

        final AtomicInteger successes = new AtomicInteger();
        final AtomicInteger failures = new AtomicInteger();

        @Override
        public void publishAuthenticationSuccess(Authentication authentication) {
            successes.incrementAndGet();
        }

        @Override
        public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
            failures.incrementAndGet();
        }
    }
}
