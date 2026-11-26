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
package io.contexa.autoconfigure.ai;

import io.contexa.autoconfigure.iam.IamSecurityCoreAutoConfiguration;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SessionSecurityContextRepositoryConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AiSecurityConfigurationTest {

    /** The repository as IamSecurityCoreAutoConfiguration declares it: no default candidate, so only its name finds it. */
    @Configuration(proxyBeanMethods = false)
    static class DeclaredRepository {

        @Bean(name = IamSecurityCoreAutoConfiguration.SESSION_CONTEXT_REPOSITORY, defaultCandidate = false)
        AISessionSecurityContextRepository repository() {
            return mock(AISessionSecurityContextRepository.class);
        }
    }

    /**
     * Q-14: with a plain type lookup the chains got nothing and fell back to Spring's repository, so no open session was
     * ever checked: neither the forced logout nor the change of an account reached it, whatever the code around them did.
     */
    @Test
    void q14_theChainsGetTheRepositoryAsItIsDeclared() {
        new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class, ContexaAdminFlowBeans.class, DeclaredRepository.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .run(context -> {
                    SessionSecurityContextRepositoryConfigurer configurer =
                            context.getBean(SessionSecurityContextRepositoryConfigurer.class);

                    assertThat(ReflectionTestUtils.getField(configurer, "aiSessionSecurityContextRepository"))
                            .as("what the chains install").isNotNull();
                    assertThat(context.getBeanProvider(AISessionSecurityContextRepository.class).getIfAvailable())
                            .as("what the MFA success handler saves through").isNotNull();
                });
    }

    @Test
    void shouldRegisterSessionSecurityContextRepositoryConfigurerWhenUserProvidesPlatformConfig() {
        new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class, ContexaAdminFlowBeans.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .withBean(AISessionSecurityContextRepository.class,
                        () -> mock(AISessionSecurityContextRepository.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(PlatformConfig.class);
                    assertThat(context).hasSingleBean(AISessionSecurityContextRepository.class);
                    assertThat(context).hasSingleBean(SessionSecurityContextRepositoryConfigurer.class);
                });
    }

    @Test
    void shouldStillRegisterSessionSecurityContextRepositoryConfigurerWhenRepositoryBeanIsNotYetPresent() {
        new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class, ContexaAdminFlowBeans.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .run(context -> {
                    assertThat(context).hasSingleBean(PlatformConfig.class);
                    assertThat(context).doesNotHaveBean(AISessionSecurityContextRepository.class);
                    assertThat(context).hasSingleBean(SessionSecurityContextRepositoryConfigurer.class);
                });
    }

    /**
     * The diagnostics speak of the application's own chain, which stays the main one in SANDBOX whatever the ownership (R-1,
     * R-15): the mode decides, an ownership set alone stands for the mode that goes with it, and nothing set is SANDBOX.
     */
    @Test
    @DisplayName("체인 진단은 SANDBOX에서만 있다: 소유권과 무관하게 모드가 정하고, 아무것도 적지 않으면 SANDBOX로 본다")
    void shouldRegisterSandboxChainDiagnosticsOnlyInSandboxMode() {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class, ContexaAdminFlowBeans.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build());
        for (String[] sandbox : List.of(
                new String[] {"contexa.ai.security.mode=SANDBOX", "contexa.bridge.ownership=HOST_OWNED"},
                new String[] {"contexa.ai.security.mode=SANDBOX", "contexa.bridge.ownership=CONTEXA_OWNED"},
                new String[] {"contexa.bridge.ownership=HOST_OWNED"},
                new String[] {})) {
            runner.withPropertyValues(sandbox).run(context -> assertThat(context.getBeanNamesForType(SandboxSecurityChainDiagnostics.class))
                    .as(String.join(", ", sandbox)).hasSize(1));
        }
        for (String[] full : List.of(
                new String[] {"contexa.ai.security.mode=FULL", "contexa.bridge.ownership=CONTEXA_OWNED"},
                new String[] {"contexa.ai.security.mode=FULL", "contexa.bridge.ownership=HOST_OWNED"},
                new String[] {"contexa.bridge.ownership=CONTEXA_OWNED"})) {
            runner.withPropertyValues(full).run(context -> assertThat(context.getBeanNamesForType(SandboxSecurityChainDiagnostics.class))
                    .as(String.join(", ", full)).isEmpty());
        }
    }
}
