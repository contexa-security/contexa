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
package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.std.llm.client.AnthropicThinkingCapability.Budget;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingCapability.DefaultThinking;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingCapability.Off;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The default capability table against the Claude model ids the Contexa repositories use (application settings,
 * benchmark runners and tests, collected 2026-10-30) and the Claude API's ids with their date suffixes: each id reads
 * the row of the Claude API's thinking table its model has, and an id the table does not name reads none.
 */
class AnthropicThinkingCapabilityTest {

    @AfterEach
    void restoreTheTable() {
        AnthropicThinkingRules.configureCapabilities(null);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("modelIds")
    void eachModelIdReadsTheRowOfItsModel(String modelId, Off off, Budget budget, DefaultThinking defaultThinking,
                                          boolean adaptive) {
        AnthropicThinkingCapability capability = AnthropicThinkingRules.capabilityOf(modelId);

        assertThat(capability).as(modelId).isNotNull();
        assertThat(capability.getOff()).isEqualTo(off);
        assertThat(capability.getBudget()).isEqualTo(budget);
        assertThat(capability.getDefaultThinking()).isEqualTo(defaultThinking);
        assertThat(capability.isAdaptive()).isEqualTo(adaptive);
    }

    static Stream<Arguments> modelIds() {
        return Stream.of(
                Arguments.of("claude-fable-5-1", Off.NOT_POSSIBLE, Budget.REFUSED, DefaultThinking.ALWAYS_ON, true),
                Arguments.of("claude-mythos-5-1", Off.NOT_POSSIBLE, Budget.REFUSED, DefaultThinking.ALWAYS_ON, true),
                Arguments.of("claude-fable-5", Off.NOT_POSSIBLE, Budget.REFUSED, DefaultThinking.ALWAYS_ON, true),
                Arguments.of("claude-mythos-5", Off.NOT_POSSIBLE, Budget.REFUSED, DefaultThinking.ALWAYS_ON, true),
                Arguments.of("claude-opus-5-5", Off.NOT_POSSIBLE, Budget.REFUSED, DefaultThinking.ALWAYS_ON, true),
                Arguments.of("claude-mythos-preview", Off.NOT_POSSIBLE, Budget.ACCEPTED, DefaultThinking.ALWAYS_ON, true),
                Arguments.of("claude-opus-5", Off.DISABLED, Budget.REFUSED, DefaultThinking.ON, true),
                Arguments.of("claude-sonnet-5-5", Off.BETWEEN_TOOLS, Budget.REFUSED, DefaultThinking.ON, true),
                Arguments.of("claude-sonnet-5", Off.DISABLED, Budget.REFUSED, DefaultThinking.ON, true),
                Arguments.of("claude-haiku-5-5", Off.DISABLED, Budget.REFUSED, DefaultThinking.ON, true),
                Arguments.of("claude-opus-4-8", Off.DISABLED, Budget.REFUSED, DefaultThinking.OFF, true),
                Arguments.of("claude-opus-4-7", Off.DISABLED, Budget.REFUSED, DefaultThinking.OFF, true),
                Arguments.of("claude-opus-4-6", Off.DISABLED, Budget.DEPRECATED, DefaultThinking.OFF, true),
                Arguments.of("claude-sonnet-4-6", Off.DISABLED, Budget.DEPRECATED, DefaultThinking.OFF, true),
                Arguments.of("claude-opus-4-5", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-opus-4-5-20251101", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-opus-4-5@20251101", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-haiku-4-5", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-haiku-4-5-20251001", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-sonnet-4-5", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-sonnet-4-5-20250929", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-opus-4-1", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-opus-4-1-20250805", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-opus-4-0", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-sonnet-4-0", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-sonnet-4-20250514", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false),
                Arguments.of("claude-opus-4-20250514", Off.DISABLED, Budget.ACCEPTED, DefaultThinking.OFF, false));
    }

    /** The rows that would match a newer model's id by its prefix do not: the table names no future model. */
    @Test
    void anIdTheTableDoesNotNameReadsNoRow() {
        for (String modelId : List.of("claude-opus-5-7", "claude-sonnet-5-6", "claude-fable-5-2", "claude-haiku-6",
                "claude-3-7-sonnet-20250219", "claude-3-5-haiku-latest", "gpt-6-luna", "claude-nova-1", "")) {
            assertThat(AnthropicThinkingRules.capabilityOf(modelId)).as(modelId).isNull();
        }
    }

    /** The effort levels each row lists (Claude API effort documentation). */
    @Test
    void theEffortLevelsAreTheClaudeApisList() {
        assertThat(AnthropicThinkingRules.capabilityOf("claude-mythos-preview").getEffortLevels())
                .doesNotContain(AnthropicEffort.XHIGH).contains(AnthropicEffort.MAX);
        assertThat(AnthropicThinkingRules.capabilityOf("claude-sonnet-4-6").getEffortLevels())
                .doesNotContain(AnthropicEffort.XHIGH).contains(AnthropicEffort.MAX);
        assertThat(AnthropicThinkingRules.capabilityOf("claude-opus-4-5").getEffortLevels())
                .containsExactly(AnthropicEffort.LOW, AnthropicEffort.MEDIUM, AnthropicEffort.HIGH);
        assertThat(AnthropicThinkingRules.capabilityOf("claude-haiku-4-5").getEffortLevels()).isEmpty();
        assertThat(AnthropicThinkingRules.capabilityOf("claude-haiku-5-5").getOffMaxEffort())
                .isEqualTo(AnthropicEffort.HIGH);
        assertThat(AnthropicThinkingRules.capabilityOf("claude-sonnet-5").getOffMaxEffort()).isNull();
    }

    /** A host's table replaces the default one; the first matching row applies. */
    @Test
    void aConfiguredTableReplacesTheDefaultOne() {
        AnthropicThinkingCapability custom = new AnthropicThinkingCapability("claude-haiku-5-5", false,
                Off.NOT_POSSIBLE, null, Budget.ACCEPTED, List.of(), DefaultThinking.ALWAYS_ON);
        AnthropicThinkingRules.configureCapabilities(List.of(custom));

        assertThat(AnthropicThinkingRules.capabilityOf("claude-haiku-5-5")).isSameAs(custom);
        assertThat(AnthropicThinkingRules.capabilityOf("claude-opus-5-5")).isNull();
    }

    /** Spring AI 1.1.8 sends thinking enabled and disabled only; adaptive, between_tools and effort it cannot. */
    @Test
    void springAi11SendsEnabledAndDisabledOnly() {
        assertThat(AnthropicThinkingRules.thinkingTypeExpressible("enabled")).isTrue();
        assertThat(AnthropicThinkingRules.thinkingTypeExpressible("disabled")).isTrue();
        assertThat(AnthropicThinkingRules.thinkingTypeExpressible("adaptive")).isFalse();
        assertThat(AnthropicThinkingRules.thinkingTypeExpressible("between_tools")).isFalse();
        assertThat(AnthropicThinkingRules.effortExpressible()).isFalse();
    }
}
