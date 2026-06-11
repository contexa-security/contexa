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
package io.contexa.autoconfigure.core.session;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.HttpSessionIdGenerator;
import io.contexa.contexacore.infra.session.impl.HttpSessionMfaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CoreSessionAutoConfiguration")
class CoreSessionAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreSessionAutoConfiguration.class));

    @Nested
    @DisplayName("SessionIdGenerator")
    class SessionIdGeneratorTest {

        @Test
        @DisplayName("Should create HttpSessionIdGenerator by default")
        void shouldCreateHttpSessionIdGenerator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(SessionIdGenerator.class);
                assertThat(context.getBean(SessionIdGenerator.class))
                        .isInstanceOf(HttpSessionIdGenerator.class);
            });
        }
    }

    @Nested
    @DisplayName("MfaSessionRepository fallback")
    class MfaSessionRepositoryTest {

        @Test
        @DisplayName("Should fallback to HttpSession when no Redis available")
        void shouldFallbackToHttpSession() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(MfaSessionRepository.class);
                assertThat(context.getBean(MfaSessionRepository.class))
                        .isInstanceOf(HttpSessionMfaRepository.class);
            });
        }
    }
}
