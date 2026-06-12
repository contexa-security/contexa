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

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Tests the conditional activation gates of IdentityStateMachineAutoConfiguration.
 * Verifies @ConditionalOnBean(PlatformConfig) and @ConditionalOnProperty gates.
 */
@DisplayName("IdentityStateMachineAutoConfiguration")
class IdentityStateMachineAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdentityStateMachineAutoConfiguration.class));

    @Nested
    @DisplayName("Activation gates")
    class ActivationGates {

        @Test
        @DisplayName("Should not activate without PlatformConfig bean")
        void shouldNotActivateWithoutPlatformConfig() {
            contextRunner
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentityStateMachineAutoConfiguration.class);
                    });
        }

        @Test
        @DisplayName("Should not activate when contexa.identity.statemachine.enabled=false")
        void shouldNotActivateWhenDisabled() {
            contextRunner
                    .withBean(PlatformConfig.class, () -> Mockito.mock(PlatformConfig.class))
                    .withPropertyValues("contexa.identity.statemachine.enabled=false")
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentityStateMachineAutoConfiguration.class);
                    });
        }
    }
}
