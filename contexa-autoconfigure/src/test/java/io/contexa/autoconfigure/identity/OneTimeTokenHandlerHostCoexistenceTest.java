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
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Spring Security's one-time token login takes the application's {@link OneTimeTokenGenerationSuccessHandler} by type
 * ({@code getBeanProvider(OneTimeTokenGenerationSuccessHandler.class).getIfUnique()}) and does not start without one. A handler of
 * Contexa's of that type beside the application's made two, so the login found none and the application did not start (found by the
 * magic-link sample: it starts alone and failed with Contexa, enforcing or not); with none of the application's, its login would have
 * taken Contexa's. Contexa keeps its handler for the sign-in it owns.
 */
class OneTimeTokenHandlerHostCoexistenceTest {

    private static final String FULL = "contexa.ai.security.mode=FULL";
    private static final String SANDBOX = "contexa.ai.security.mode=SANDBOX";
    private static final String HOST_OWNED = "contexa.bridge.ownership=HOST_OWNED";
    private static final String CONTEXA_OWNED = "contexa.bridge.ownership=CONTEXA_OWNED";

    /** What @EnableAISecurity publishes for an application that signs its own users in (the mode with its ownership), and less than that. */
    private static final List<String[]> APPLICATION_SIGNS_IN =
            List.of(new String[] {SANDBOX, HOST_OWNED}, new String[] {HOST_OWNED}, new String[] {SANDBOX}, new String[] {});

    /** What it publishes where Contexa signs the users in, and the ownership alone. */
    private static final List<String[]> CONTEXA_SIGNS_IN = List.of(new String[] {FULL, CONTEXA_OWNED}, new String[] {CONTEXA_OWNED});

    private final ApplicationContextRunner contexts = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdentityServiceAutoConfiguration.class))
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

        /** What the MFA endpoint of an application whose sign-in Contexa owns is built on. */
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
    static class TheApplicationsOwnHandler {

        @Bean
        OneTimeTokenGenerationSuccessHandler applicationsMagicLink() {
            return (request, response, token) -> response.setStatus(204);
        }
    }

    @Test
    @DisplayName("an application that signs its own users in finds its own handler by type, as its one-time token login does")
    void theApplicationsOwnHandlerIsTheOneItsLoginFinds() {
        for (String[] mode : APPLICATION_SIGNS_IN) {
            contexts.withUserConfiguration(TheApplicationsOwnHandler.class).withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBeanProvider(OneTimeTokenGenerationSuccessHandler.class).getIfUnique())
                        .as("what Spring Security's one-time token login finds by type (%s)", String.join(", ", mode))
                        .isSameAs(context.getBean("applicationsMagicLink"));
            });
        }
    }

    @Test
    @DisplayName("an application that signs its own users in and declares no handler is not given Contexa's by type")
    void theApplicationIsNotGivenContexasHandler() {
        for (String[] mode : APPLICATION_SIGNS_IN) {
            contexts.withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBeanNamesForType(OneTimeTokenGenerationSuccessHandler.class))
                        .as("the handlers a one-time token login of the application could be given (%s)", String.join(", ", mode)).isEmpty();
            });
        }
    }

    @Test
    @DisplayName("where Contexa signs the users in, its handler of the magic link is there")
    void whereContexaSignsTheUsersInItsHandlerStays() {
        for (String[] mode : CONTEXA_SIGNS_IN) {
            contexts.withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBean("contexaMagicLinkHandler")).as(String.join(", ", mode)).isInstanceOf(MagicLinkHandler.class);
            });
        }
    }
}
