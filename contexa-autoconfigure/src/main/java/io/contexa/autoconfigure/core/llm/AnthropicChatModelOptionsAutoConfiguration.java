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

import io.contexa.autoconfigure.properties.AnthropicModelCapabilitiesProperties;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingRules;
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * The Anthropic chat model options for the Claude models Contexa runs. Its post-processors take nothing and read the
 * environment through EnvironmentAware: a post-processor bean method that takes a bean by type makes Spring create
 * FactoryBeans and what they need while post-processors are being registered, and those beans then miss the
 * post-processors (the chat model among them).
 */
@AutoConfiguration(beforeName = "org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration")
@ConditionalOnClass(name = "org.springframework.ai.anthropic.AnthropicChatModel")
public class AnthropicChatModelOptionsAutoConfiguration {

    @Bean(name = "contexaAnthropicModelCapabilitiesEnvironmentBridge")
    public static CapabilitiesBridge anthropicModelCapabilitiesEnvironmentBridge() {
        return new CapabilitiesBridge();
    }

    @Bean(name = "contexaAnthropicChatModelPostProcessor")
    public static AnthropicChatModelPostProcessor anthropicChatModelPostProcessor() {
        return new AnthropicChatModelPostProcessor();
    }

    /** Design 4.5-A: the start refuses the Anthropic thinking settings a layer model or Spring AI 1.1 contradicts. */
    @Bean(name = "contexaAnthropicThinkingSettingsVerifier")
    public static AnthropicThinkingSettingsVerifier anthropicThinkingSettingsVerifier() {
        return new AnthropicThinkingSettingsVerifier();
    }

    static AnthropicModelCapabilitiesProperties capabilities(Environment environment) {
        return Binder.get(environment)
                .bind(AnthropicModelCapabilitiesProperties.PREFIX, Bindable.of(AnthropicModelCapabilitiesProperties.class))
                .orElseGet(AnthropicModelCapabilitiesProperties::new);
    }

    /**
     * Hands the configured Claude models that take only the default sampling and the thinking capability table to the
     * options factory, and takes every sampling value out when the Anthropic API version refuses them all.
     */
    @Slf4j
    public static final class CapabilitiesBridge implements BeanFactoryPostProcessor, EnvironmentAware {

        /** The first Anthropic API version that refuses every sampling value (Claude API migration guide). */
        static final String SAMPLING_FREE_API_VERSION = "2026-10-21";

        private Environment environment;

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
            if (environment != null) {
                AnthropicModelCapabilitiesProperties capabilities = capabilities(environment);
                ProviderAwareChatOptionsFactory.configureAnthropicModelCapabilities(
                        capabilities.getDefaultSamplingOnlyPatterns());
                AnthropicThinkingRules.configureCapabilities(capabilities.getThinking());
                String version = environment.getProperty("spring.ai.anthropic.version", "").trim();
                boolean samplingFree = version.matches("\\d{4}-\\d{2}-\\d{2}")
                        && version.compareTo(SAMPLING_FREE_API_VERSION) >= 0;
                ProviderAwareChatOptionsFactory.configureAnthropicSamplingNeverSent(samplingFree);
                if (samplingFree) {
                    log.warn("[AnthropicThinking] spring.ai.anthropic.version {} refuses every temperature, top_p and"
                            + " top_k value on every model (Claude API migration guide 2026-10-21); Anthropic requests"
                            + " carry none, and the platform's determinism temperature is recorded as not applied.",
                            version);
                }
            }
        }
    }
}
