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
package io.contexa.contexaiam.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SecurityStepUpProperties binding")
class SecurityStepUpPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(Config.class);

    @Test
    @DisplayName("maxAttempts and lockoutDuration default to 3 and 300 when no property is provided")
    void stepUpDefaults_bindsCorrectly() {
        contextRunner.run(context -> {
            SecurityStepUpProperties properties = context.getBean(SecurityStepUpProperties.class);

            assertThat(properties.getMaxAttempts()).isEqualTo(3);
            assertThat(properties.getLockoutDuration()).isEqualTo(300);
        });
    }

    @Test
    @DisplayName("maxAttempts=5 binds via kebab-case property")
    void maxAttempts_bindsCorrectly() {
        contextRunner
                .withPropertyValues("contexa.security.stepup.max-attempts=5")
                .run(context -> {
                    SecurityStepUpProperties properties = context.getBean(SecurityStepUpProperties.class);
                    assertThat(properties.getMaxAttempts()).isEqualTo(5);
                });
    }

    @Test
    @DisplayName("lockoutDuration=600 binds via kebab-case property")
    void lockoutDuration_bindsCorrectly() {
        contextRunner
                .withPropertyValues("contexa.security.stepup.lockout-duration=600")
                .run(context -> {
                    SecurityStepUpProperties properties = context.getBean(SecurityStepUpProperties.class);
                    assertThat(properties.getLockoutDuration()).isEqualTo(600);
                });
    }

    @EnableConfigurationProperties(SecurityStepUpProperties.class)
    static class Config {
    }
}
