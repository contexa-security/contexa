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
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Spring Security's one-time token login takes the application's {@link OneTimeTokenService} by type
 * ({@code getBeanProvider(OneTimeTokenService.class).getIfUnique(...)}). Contexa's e-mail service writes to Contexa's table and sends mail
 * through Contexa's sender: if the application's login picked it, the code of the application would be generated and mailed by Contexa
 * (found by the hostile host: 200 alone, 500 with Contexa). Contexa keeps its service under its own name for its own flows only.
 */
class OneTimeTokenServiceHostCoexistenceTest {

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
    static class TheApplicationsOwnService {

        @Bean
        OneTimeTokenService applicationsOneTimeTokenService() {
            return new InMemoryOneTimeTokenService();
        }
    }

    @Test
    @DisplayName("an application without a one-time token service of its own is not given Contexa's by type")
    void theApplicationIsNotGivenContexasServiceByType() {
        contexts.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(ContexaOneTimeTokens.BEAN_NAME, ContexaOneTimeTokens.class).service())
                    .as("Contexa's flows reach it by name").isNotNull();
            OneTimeTokenService sentinel = new InMemoryOneTimeTokenService();
            assertThat(context.getBeanProvider(OneTimeTokenService.class).getIfUnique(() -> sentinel))
                    .as("what Spring Security's one-time token login finds by type")
                    .isSameAs(sentinel);
            assertThat(context.getBeanProvider(OneTimeTokenService.class).getIfAvailable())
                    .as("what an injection point of the application finds by type").isNull();
        });
    }

    @Test
    @DisplayName("a code goes to a name of the store the sign-in reads, and to no name that store does not know")
    void theStoreOfTheSignInDecidesWhoIsMailed() {
        EmailService mail = mock(EmailService.class);
        when(mail.isMailSenderConfigured()).thenReturn(true);
        contexts.withBean("contexaEmailService", EmailService.class, () -> mail)
                .withBean(UserDetailsService.class, () -> new InMemoryUserDetailsManager(
                        User.withUsername("alice@app.example").password("{noop}x").build()))
                .run(context -> {
                    EmailOneTimeTokenService service = context.getBean(ContexaOneTimeTokens.BEAN_NAME,
                            ContexaOneTimeTokens.class).service();

                    service.generate(new GenerateOneTimeTokenRequest("alice@app.example"));
                    service.generate(new GenerateOneTimeTokenRequest("victim@example.test"));

                    verify(mail).sendHtmlMessage(eq("alice@app.example"), anyString(), anyString());
                    verify(mail, never()).sendHtmlMessage(eq("victim@example.test"), anyString(), anyString());
                });
    }

    @Test
    @DisplayName("an application with a one-time token service of its own keeps it, and Contexa keeps its own beside it")
    void theApplicationsOwnServiceIsTheOneItFinds() {
        contexts.withUserConfiguration(TheApplicationsOwnService.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeanProvider(OneTimeTokenService.class).getIfUnique())
                    .isSameAs(context.getBean("applicationsOneTimeTokenService"));
            assertThat(context.getBean(ContexaOneTimeTokens.BEAN_NAME, ContexaOneTimeTokens.class).service()).isNotNull();
        });
    }
}
