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
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.10 (2): the finished system prompt the version screen shows is the one a decision draws from the version,
 * as the golden render draws a person's first pass with the host's defaults.
 */
class SecurityDecisionSystemPreviewTest {

    @Test
    void thePreviewOfTheProductVersionIsTheSystemTextOfAPersonsDecision() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptDocument.product().release());
        JsonNode first = golden.cases().get(0);
        String drawn = golden.render(first, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties).systemText();

        String preview = SecurityDecisionPromptDocument.systemPreview(SecurityDecisionPromptDocument.product());

        assertThat(drawn.strip()).startsWith(preview.strip());
        assertThat(drawn + "\n").contains(SecurityDecisionPromptDocument.outputFormatPreview().strip());
    }
}
