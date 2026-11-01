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
package io.contexa.autoconfigure.core.llm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T3, T4 (design 4.5-A, D-1): the application start refuses the Anthropic thinking settings a known layer model
 * contradicts and the ones Spring AI 1.1 cannot send, naming the setting and the Claude API rule (or the Spring AI
 * version that would be needed); it warns about the ones the call adjusts. The layer model is the one
 * {@code contexa.security.tiered.llm.layerN.model} names.
 */
@ExtendWith(OutputCaptureExtension.class)
class AnthropicThinkingStartupCheckTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AnthropicChatModelOptionsAutoConfiguration.class));

    @Test
    void theDefaultSettingsStart() {
        runner.withPropertyValues("contexa.security.tiered.llm.layer1.model=claude-opus-5-5")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void thinkingOffWithAnEffortAboveHighOnClaudeHaiku55IsRefused() {
        runner.withPropertyValues(
                        "contexa.security.tiered.llm.layer1.model=claude-haiku-5-5",
                        "contexa.security.tiered.layer1.anthropic-thinking=OFF",
                        "contexa.security.tiered.layer1.anthropic-effort=XHIGH")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("contexa.security.tiered.layer1.anthropic-effort=XHIGH cannot be sent")
                        .hasMessageContaining("Spring AI 2.0.x")
                        .hasMessageContaining("claude-haiku-5-5 takes thinking off only at effort high or below"));
    }

    @Test
    void thinkingOffOnAModelThatAlwaysThinksIsRefused() {
        runner.withPropertyValues(
                        "contexa.security.tiered.llm.layer2.model=claude-opus-5-5",
                        "contexa.security.tiered.layer2.anthropic-thinking=OFF")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("contexa.security.tiered.layer2.anthropic-thinking=OFF")
                        .hasMessageContaining("claude-opus-5-5 cannot turn thinking off"));
    }

    @Test
    void aThinkingBudgetOnAModelThatRefusesItIsRefused() {
        runner.withPropertyValues(
                        "contexa.security.tiered.llm.layer1.model=claude-haiku-5-5",
                        "contexa.security.tiered.layer1.anthropic-thinking=BUDGET",
                        "contexa.security.tiered.layer1.anthropic-thinking-budget-tokens=2048")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("claude-haiku-5-5 refuses thinking.type enabled with budget_tokens")
                        .hasMessageContaining("thinking.type adaptive and output_config.effort"));
    }

    @Test
    void adaptiveThinkingIsRefusedWithSpringAi11AndOnAModelThatRefusesIt() {
        runner.withPropertyValues(
                        "contexa.security.tiered.llm.layer1.model=claude-haiku-4-5",
                        "contexa.security.tiered.layer1.anthropic-thinking=ADAPTIVE")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("anthropic-thinking=ADAPTIVE cannot be sent")
                        .hasMessageContaining("Adaptive thinking needs Spring AI 2.0.x")
                        .hasMessageContaining("claude-haiku-4-5 refuses adaptive thinking"));
    }

    @Test
    void anEffortIsRefusedWithSpringAi11WhateverTheModel() {
        runner.withPropertyValues("contexa.security.tiered.layer2.anthropic-effort=LOW")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("contexa.security.tiered.layer2.anthropic-effort=LOW cannot be sent")
                        .hasMessageContaining("Spring AI 2.0.x"));
    }

    @Test
    void aBudgetSettingWithoutAValidBudgetIsRefused() {
        runner.withPropertyValues(
                        "contexa.security.tiered.layer1.anthropic-thinking=BUDGET",
                        "contexa.security.tiered.layer1.anthropic-thinking-budget-tokens=512")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("anthropic-thinking=BUDGET needs")
                        .hasMessageContaining("of at least 1024")
                        .hasMessageContaining("it is 512"));
    }

    @Test
    void aBudgetWithoutAPositiveAnswerLimitIsRefused() {
        runner.withPropertyValues(
                        "contexa.security.tiered.layer2.anthropic-thinking=BUDGET",
                        "contexa.security.tiered.layer2.anthropic-thinking-budget-tokens=2048",
                        "contexa.security.tiered.layer2.max-output-tokens=0")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasMessageContaining("needs a positive contexa.security.tiered.layer2.max-output-tokens")
                        .hasMessageContaining("it is 0"));
    }

    @Test
    void thinkingOffOnClaudeSonnet55StartsWithAWarning(CapturedOutput output) {
        runner.withPropertyValues(
                        "contexa.security.tiered.llm.layer2.model=claude-sonnet-5-5",
                        "contexa.security.tiered.layer2.anthropic-thinking=OFF")
                .run(context -> assertThat(context).hasNotFailed());

        assertThat(output).contains("claude-sonnet-5-5 turns thinking off with thinking.type between_tools")
                .contains("NOT_EXPRESSIBLE_SPRING_AI_1_1");
    }

    @Test
    void aModelTheTableDoesNotNameStartsWithWhatTheLayerAsks() {
        runner.withPropertyValues(
                        "contexa.security.tiered.llm.layer1.model=claude-nova-1",
                        "contexa.security.tiered.layer1.anthropic-thinking=OFF")
                .run(context -> assertThat(context).hasNotFailed());
    }
}
