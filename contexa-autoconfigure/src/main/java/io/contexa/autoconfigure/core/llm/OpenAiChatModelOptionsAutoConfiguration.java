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

import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

@AutoConfiguration(beforeName = "org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration")
@ConditionalOnClass(name = "org.springframework.ai.openai.OpenAiChatModel")
public class OpenAiChatModelOptionsAutoConfiguration {

    @Bean
    public static BeanFactoryPostProcessor providerAwareChatOptionsEnvironmentBridge(Environment environment) {
        return beanFactory -> ProviderAwareChatOptionsFactory.configureModelCapabilities(
                environment.getProperty("spring.ai.openai.chat.options.model"),
                environment.getProperty("contexa.llm.model-capabilities.openai.max-completion-token-patterns"),
                environment.getProperty("contexa.llm.model-capabilities.openai.default-sampling-only-patterns"),
                environment.getProperty("contexa.llm.model-capabilities.ollama.disable-thinking-patterns"));
    }

    @Bean
    public static OpenAiChatModelPostProcessor openAiChatModelPostProcessor() {
        return new OpenAiChatModelPostProcessor();
    }
}
