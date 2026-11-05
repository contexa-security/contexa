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
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.RedisStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * The mail of a one-time code is claimed in this store, and Contexa's own sign-in mails codes too: the store stands under
 * either ownership, not only beside the step-up of an application that owns its sign-in.
 */
class StepUpOptionsStoreAutoConfigurationTest {

    private final ApplicationContextRunner contexts = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(StepUpOptionsStoreAutoConfiguration.class,
                    IdentityServiceAutoConfiguration.class))
            .withUserConfiguration(Collaborators.class);

    @Configuration(proxyBeanMethods = false)
    static class Collaborators {

        @Bean
        PlatformConfig platformConfig() {
            return mock(PlatformConfig.class);
        }

        @Bean
        AuthContextProperties authContextProperties() {
            return new AuthContextProperties();
        }

        @Bean
        MfaStateMachineIntegrator mfaStateMachineIntegrator() {
            return mock(MfaStateMachineIntegrator.class);
        }

        @Bean("contexaJdbcTemplate")
        JdbcTemplate contexaJdbcTemplate() {
            return mock(JdbcTemplate.class);
        }

        @Bean("contexaTransactionTemplate")
        TransactionTemplate contexaTransactionTemplate() {
            return new TransactionTemplate(mock(PlatformTransactionManager.class));
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class TheApplicationsOwnStore {

        @Bean
        StepUpOptionsStore applicationsStore() {
            return mock(StepUpOptionsStore.class);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"CONTEXA_OWNED", "HOST_OWNED"})
    @DisplayName("a standalone application keeps it in memory under either ownership, where the sweep reaches it")
    void inMemoryUnderEitherOwnership(String ownership) {
        contexts.withPropertyValues("contexa.bridge.ownership=" + ownership).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(StepUpOptionsStore.class);
            assertThat(context.getBean(StepUpOptionsStore.class)).isInstanceOf(InMemoryStepUpOptionsStore.class);
            assertThat(context.getBeanProvider(ExpiringStateStore.class).stream().toList())
                    .containsExactly((ExpiringStateStore) context.getBean(StepUpOptionsStore.class));
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"CONTEXA_OWNED", "HOST_OWNED"})
    @DisplayName("a distributed deployment shares it in Redis under either ownership")
    void inRedisUnderEitherOwnership(String ownership) {
        contexts.withPropertyValues("contexa.bridge.ownership=" + ownership, "contexa.infrastructure.mode=distributed")
                .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(StepUpOptionsStore.class);
                    assertThat(context.getBean(StepUpOptionsStore.class)).isInstanceOf(RedisStepUpOptionsStore.class);
                });
    }

    @Test
    @DisplayName("Contexa's mail of a code claims in the store of the context, the application's own when it has one")
    void theMailOfACodeClaimsInTheStoreOfTheContext() {
        contexts.withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED")
                .withUserConfiguration(TheApplicationsOwnStore.class)
                .withBean(UserDetailsService.class, () -> new InMemoryUserDetailsManager(
                        User.withUsername("alice@contexa.io").password("{noop}x").build()))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(StepUpOptionsStore.class);

                    context.getBean(ContexaOneTimeTokens.BEAN_NAME, ContexaOneTimeTokens.class).service()
                            .generate(new GenerateOneTimeTokenRequest("alice@contexa.io"));

                    verify(context.getBean(StepUpOptionsStore.class)).claim(anyString(), any(Duration.class));
                });
    }
}
