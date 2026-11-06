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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.infra.StandaloneEnforcementStateWarning;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * PR-52 (Q-6): in standalone a restart ends the decisions in force that live in memory, a CHALLENGE among them. A BLOCK
 * that ctxa_blocked_user holds in force is written again when the server starts, and one it does not hold is not; the
 * start says exactly that, as standalone is for development.
 */
@ExtendWith(OutputCaptureExtension.class)
class StandaloneEnforcementStateWarningTest {

    private static final String WARNING = "decisions in force are kept in memory and lost on restart";

    @Test
    @DisplayName("the in-memory decisions make one warning that a restart ends a re-authentication, and that a block comes back from the record only")
    void theStartSaysThatARestartEndsTheDecisionsInForce(CapturedOutput output) {
        new StandaloneEnforcementStateWarning(() -> new InMemoryZeroTrustActionRepository(0)).afterSingletonsInstantiated();

        assertThat(output).containsOnlyOnce(WARNING);
        assertThat(output).contains("BLOCK").contains("CHALLENGE").contains("contexa.infrastructure.mode=distributed");
        assertThat(output).as("a BLOCK the record holds in force is written again at start")
                .contains("ctxa_blocked_user").contains("written again");
        assertThat(output).as("not the statement that a restart ends every BLOCK")
                .doesNotContain("a BLOCK and a CHALLENGE end with the server");
    }

    @Test
    @DisplayName("a repository the application gives keeps the start silent")
    void aRepositoryTheApplicationGivesKeepsTheStartSilent(CapturedOutput output) {
        new StandaloneEnforcementStateWarning(() -> mock(ZeroTrustActionRepository.class)).afterSingletonsInstantiated();

        assertThat(output).doesNotContain(WARNING);
    }

    @Test
    @DisplayName("no repository at all keeps the start silent")
    void noRepositoryKeepsTheStartSilent(CapturedOutput output) {
        new StandaloneEnforcementStateWarning(() -> null).afterSingletonsInstantiated();

        assertThat(output).doesNotContain(WARNING);
    }

    @Test
    @DisplayName("the warning belongs to the standalone mode only")
    void theWarningBelongsToTheStandaloneMode() {
        ConditionalOnProperty condition = Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("standaloneEnforcementStateWarning")).findFirst().orElseThrow()
                .getAnnotation(ConditionalOnProperty.class);

        assertThat(condition.name()).containsExactly("contexa.infrastructure.mode");
        assertThat(condition.havingValue()).isEqualTo("standalone");
        assertThat(condition.matchIfMissing()).isTrue();
    }
}
