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
package io.contexa.contexacore.verification.runtime.longhorizon;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 2.3 B13: the long-horizon evidence reads a dictionary prompt (v20, v21, v1.0) in its own form: the learned
 * requests and the baseline context are on its BaselineStatus line, read past the line's fact id.
 */
class OfficialVerificationRpiDictionaryPromptTest {

    @Test
    void theBaselineStatusLineOfADictionaryPromptGivesTheObservationsAndTheBaselineContext() {
        String userPrompt = String.join("\n",
                "=== USER BASELINE (learned; time zone UTC) ===",
                "[B1] BaselineStatus: ESTABLISHED (42 learned requests, personal baseline AVAILABLE)",
                "=== SESSION ===",
                "[S1] LoginMethod: PASSWORD, MFA verified");

        var round = new OfficialVerificationRpiEvidenceFactory().createRoundSnapshot(null, 1, "req-1", Map.of(),
                List.of(), null, null, Map.of(), Map.of("userPrompt", userPrompt));

        assertThat(round.observationCount()).isEqualTo(42);
        assertThat(round.baselineContextPresent()).isTrue();
    }
}
