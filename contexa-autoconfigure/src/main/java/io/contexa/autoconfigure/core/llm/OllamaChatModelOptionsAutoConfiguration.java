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
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * The Ollama chat options Contexa applies: the application configuration's models whose thinking is turned off
 * (contexa.llm.model-capabilities.ollama.disable-thinking-patterns) reach the options factory on an application that
 * runs Ollama without OpenAI. The bridge takes nothing and reads the environment through EnvironmentAware.
 */
@AutoConfiguration(beforeName = "org.springframework.ai.model.ollama.autoconfigure.OllamaChatAutoConfiguration")
@ConditionalOnClass(name = "org.springframework.ai.ollama.OllamaChatModel")
public class OllamaChatModelOptionsAutoConfiguration {

    static final String DISABLE_THINKING_PATTERNS = "contexa.llm.model-capabilities.ollama.disable-thinking-patterns";

    @Bean
    public static CapabilitiesBridge ollamaModelCapabilitiesEnvironmentBridge() {
        return new CapabilitiesBridge();
    }

    /** Hands the configured Ollama models whose thinking is turned off to the options factory. */
    public static final class CapabilitiesBridge implements BeanFactoryPostProcessor, EnvironmentAware {

        private Environment environment;

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
            if (environment != null) {
                ProviderAwareChatOptionsFactory.configureOllamaModelCapabilities(
                        environment.getProperty(DISABLE_THINKING_PATTERNS));
            }
        }
    }
}
