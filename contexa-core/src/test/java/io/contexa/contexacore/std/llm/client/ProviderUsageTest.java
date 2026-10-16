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

import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.metadata.DefaultUsage;
import org.springframework.ai.openai.api.OpenAiApi;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Token counts that mean the same for every provider: Anthropic counts its prompt cache reads and writes apart from
 * its input tokens (Spring AI's prompt tokens), OpenAI includes its cached tokens and reports its reasoning tokens
 * inside the completion tokens.
 */
class ProviderUsageTest {

    @Test
    void anAnthropicUsageCountsItsCacheReadsAndWritesAsPromptTokens() {
        DefaultUsage usage = new DefaultUsage(3329, 838, 4167, new AnthropicApi.Usage(3329, 838, 12, 4372));

        assertThat(ProviderUsage.promptTokens(usage)).isEqualTo(7713);
        assertThat(ProviderUsage.totalTokens(usage)).isEqualTo(8551);
        assertThat(ProviderUsage.cacheReadTokens(usage)).isEqualTo(4372);
        assertThat(ProviderUsage.cacheWriteTokens(usage)).isEqualTo(12);
    }

    @Test
    void anOpenAiUsageKeepsItsCountsAndNamesItsReasoningTokens() {
        DefaultUsage usage = new DefaultUsage(4337, 212, 4549, new OpenAiApi.Usage(212, 4337, 4549, null,
                new OpenAiApi.Usage.CompletionTokenDetails(157, null, null, null)));

        assertThat(ProviderUsage.promptTokens(usage)).isEqualTo(4337);
        assertThat(ProviderUsage.totalTokens(usage)).isEqualTo(4549);
        assertThat(ProviderUsage.cacheWriteTokens(usage)).isNull();
        assertThat(ProviderUsage.reasoningTokens(usage)).isEqualTo(157);
    }
}
