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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Contexa's password sign-in where Contexa owns the sign-in: Contexa's provider decides, once, and no other provider or
 * manager is asked; where the application owns the sign-in nothing changes.
 */
class ContexaPasswordSignInTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(SignInBeans.class);

    @Test
    void whereContexaOwnsTheSignInContexasProviderDecidesOnceAndNoOtherProviderIsAsked() {
        runner.withPropertyValues("contexa.ai.security.mode=FULL").run(context -> {
            AuthenticationManager signIn = ContexaPasswordSignIn.manager(context);
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
                .run(context -> assertThat(ContexaPasswordSignIn.manager(context)).isNull());
    }

    @Test
    void withoutContexasProviderTheChainsManagerStays() {
        new ApplicationContextRunner().withPropertyValues("contexa.ai.security.mode=FULL")
                .run(context -> assertThat(ContexaPasswordSignIn.manager(context)).isNull());
    }

    @Test
    void theSignInIsObservedAsTheChainsManagerIs() {
        runner.withUserConfiguration(Observation.class).withPropertyValues("contexa.ai.security.mode=FULL").run(context -> {
            AuthenticationManager signIn = ContexaPasswordSignIn.manager(context);

            assertThat(signIn).isInstanceOf(ObservedManager.class);
            assertThat(signIn.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("admin", "right"))
                    .isAuthenticated()).isTrue();
            assertThat(context.getBean(ContexaPasswordSignIn.PROVIDER_BEAN, CountingProvider.class).calls.get()).isEqualTo(1);
        });
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
