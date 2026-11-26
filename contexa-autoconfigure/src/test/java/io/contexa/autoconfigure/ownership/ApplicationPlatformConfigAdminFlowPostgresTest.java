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
package io.contexa.autoconfigure.ownership;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-13 of docs/agent/운영모드-정상화-구현계획.md for an application that declares its own {@link PlatformConfig}, as an
 * application does that defines its sign-in with Contexa's DSL: wherever Contexa's administrators sign in apart from the
 * application's users, the flow of the administrators is part of that configuration too, so that they can still reach the
 * console. Before, it was added only to Contexa's default configuration, and such an application had no way for Contexa's
 * administrators to sign in. Where the two are one (FULL with CONTEXA_OWNED), nothing is added.
 */
@Timeout(1200)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@DisplayName("앱이 흐름 설정을 직접 둔 경우의 Contexa 관리자 흐름(R-13, 실제 기동)")
class ApplicationPlatformConfigAdminFlowPostgresTest {

    @BeforeAll
    static void driver() throws Exception {
        Class.forName("org.postgresql.Driver");
    }

    @Test
    @DisplayName("FULL + HOST_OWNED: 앱 흐름 설정에도 관리 흐름 체인이 하나 생기고, 관리자가 그 흐름으로 MFA 로그인해 콘솔을 연다")
    void theAdministratorsFlowJoinsTheApplicationsConfiguration() throws Exception {
        try (GridRun run = GridRun.start(SandboxWithItsPlatform.class, FullWithItsPlatform.class,
                OperatingCombination.FULL_HOST_OWNED)) {
            assertThat(run.startOutcome()).isEqualTo(GridRun.STARTED);
            ConfigurableApplicationContext context = run.context();

            assertThat(adminFlowChains(context)).hasSize(1);
            assertThat(flowTypeNames(context)).containsExactly("mfa", ContexaSignInRealm.adminFlowTypeName());
            GridRun.Browser administrator = run.browser();
            assertThat(run.contexaSignIn(administrator)).isEqualTo("200 MFA_COMPLETED");
            assertThat(administrator.get("/contexa/admin/api/blacklist", "application/json").statusCode()).isEqualTo(200);
        }
    }

    @Test
    @DisplayName("FULL + CONTEXA_OWNED: 관리 흐름을 더하지 않고, 관리자는 앱 흐름(주 체인)으로 로그인한다")
    void nothingJoinsWhereTheAdministratorsAndTheUsersAreOne() throws Exception {
        try (GridRun run = GridRun.start(SandboxWithItsPlatform.class, FullWithItsPlatform.class,
                OperatingCombination.FULL_CONTEXA_OWNED)) {
            assertThat(run.startOutcome()).isEqualTo(GridRun.STARTED);
            ConfigurableApplicationContext context = run.context();

            assertThat(adminFlowChains(context)).isEmpty();
            assertThat(flowTypeNames(context)).containsExactly("mfa");
            GridRun.Browser administrator = run.browser();
            assertThat(run.contexaSignIn(administrator)).isEqualTo("200 MFA_COMPLETED");
            assertThat(administrator.get("/contexa/admin/api/blacklist", "application/json").statusCode()).isEqualTo(200);
        }
    }

    /** The chains the flow of Contexa's administrators was built into, by the names the chain registrar gives them. */
    private static List<String> adminFlowChains(ConfigurableApplicationContext context) {
        String prefix = "contexa" + ContexaSignInRealm.adminFlowTypeName() + "SecurityFilterChain";
        return context.getBeansOfType(SecurityFilterChain.class).keySet().stream()
                .filter(name -> name.startsWith(prefix))
                .toList();
    }

    private static List<String> flowTypeNames(ConfigurableApplicationContext context) {
        return context.getBean(PlatformConfig.class).getFlows().stream()
                .map(AuthenticationFlowConfig::getTypeName)
                .toList();
    }

    /**
     * An application that defines its own sign-in with Contexa's DSL, as the examples do: a flow of its users with the
     * password and a code by mail, the URL policies for every request, and users of its own.
     */
    abstract static class ApplicationWithItsPlatform extends GridModels {

        @Bean
        PlatformConfig applicationPlatform(ApplicationContext applicationContext,
                                           @Lazy CustomDynamicAuthorizationManager contexaCustomDynamicAuthorizationManager)
                throws Exception {
            return new IdentityDslRegistry<HttpSecurity>(applicationContext)
                    .global(http -> http.authorizeHttpRequests(requests -> requests
                            .anyRequest().access(contexaCustomDynamicAuthorizationManager)))
                    .mfa(mfa -> mfa.requiredFactors(1)
                            .primaryAuthentication(auth -> auth.formLogin(form -> form.defaultSuccessUrl("/")))
                            .ott(Customizer.withDefaults())
                            .order(100))
                    .session(Customizer.withDefaults())
                    .build();
        }

        @Bean
        UserDetailsService hostUsers() {
            return new InMemoryUserDetailsManager(User.withUsername(GridRun.HOST_USER)
                    .password("{noop}" + GridRun.HOST_PASSWORD).roles("USER").build());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class SandboxWithItsPlatform extends ApplicationWithItsPlatform {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullWithItsPlatform extends ApplicationWithItsPlatform {
    }
}
