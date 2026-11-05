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

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.model.TieredLayerModelVerifier;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Q-22 (PR-78): the layer model verifier is there when the application starts. Its condition on the primary chat model
 * was read before that bean's own declaration further down the class, so it was never registered: measured with
 * {@code /actuator/beans}, no such bean.
 */
class TieredLayerModelVerifierWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreLLMTieredAutoConfiguration.class))
            .withBean(ContexaProperties.class)
            .withBean(AdvisorRegistry.class, () -> mock(AdvisorRegistry.class))
            .withBean(JsonStreamingProcessor.class, () -> mock(JsonStreamingProcessor.class))
            .withBean("anthropicChatModel", ChatModel.class, () -> AnthropicChatModel.builder()
                    .anthropicApi(AnthropicApi.builder().apiKey("test").build())
                    .defaultOptions(AnthropicChatOptions.builder().model("claude-haiku-5-5").build())
                    .build());

    @Test
    void theVerifierIsRegisteredAndTheStartGoesOnWhateverTheLayersAreSetTo() {
        runner.withPropertyValues("contexa.security.tiered.llm.layer1.model=claude-haiku-5-5",
                        "contexa.security.tiered.llm.layer2.model=gpt-6.1-sol")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(TieredLayerModelVerifier.class);
                });
    }
}
