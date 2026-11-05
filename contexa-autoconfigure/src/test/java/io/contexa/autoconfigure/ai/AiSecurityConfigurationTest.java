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
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.util.ReflectionTestUtils;

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
                .withUserConfiguration(AiSecurityConfiguration.class, DeclaredRepository.class)
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
                .withUserConfiguration(AiSecurityConfiguration.class)
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
                .withUserConfiguration(AiSecurityConfiguration.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .run(context -> {
                    assertThat(context).hasSingleBean(PlatformConfig.class);
                    assertThat(context).doesNotHaveBean(AISessionSecurityContextRepository.class);
                    assertThat(context).hasSingleBean(SessionSecurityContextRepositoryConfigurer.class);
                });
    }

    @Test
    void shouldRegisterHostOwnedChainDiagnosticsOnlyInHostOwnedMode() {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build());
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED")
                .run(context -> assertThat(context).hasSingleBean(HostOwnedSecurityChainDiagnostics.class));
        runner.run(context -> assertThat(context).hasSingleBean(HostOwnedSecurityChainDiagnostics.class));
        runner.withPropertyValues("contexa.bridge.ownership=CONTEXA_OWNED")
                .run(context -> assertThat(context).doesNotHaveBean(HostOwnedSecurityChainDiagnostics.class));
    }
}
