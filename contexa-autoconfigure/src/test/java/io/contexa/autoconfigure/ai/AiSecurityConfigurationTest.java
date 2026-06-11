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

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SessionSecurityContextRepositoryConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AiSecurityConfigurationTest {

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
}
