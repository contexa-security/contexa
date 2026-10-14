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
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import java.lang.reflect.Field;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.util.ReflectionUtils;

/**
 * Adjusts the default options of an Anthropic chat model for the Claude model it runs. Spring AI sets a default
 * temperature of 0.8 and sends it on every request, which the newest Claude models refuse with a 400 error, so it is
 * taken out with the other sampling values for them. Anthropic caches only the prompt a request marks, so the system
 * prompt is marked when no cache strategy is configured. The model keeps its defaults in a field it only hands out as
 * copies, so they are adjusted in place.
 */
@Slf4j
public class AnthropicChatModelPostProcessor
        implements BeanPostProcessor, BeanFactoryAware, EnvironmentAware, SmartInitializingSingleton {

    private AnthropicModelCapabilitiesProperties capabilities = new AnthropicModelCapabilitiesProperties();
    private BeanFactory beanFactory;

    public AnthropicChatModelPostProcessor() {
    }

    public AnthropicChatModelPostProcessor(AnthropicModelCapabilitiesProperties capabilities) {
        this.capabilities = capabilities;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.capabilities = AnthropicChatModelOptionsAutoConfiguration.capabilities(environment);
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    /**
     * A chat model bean created before the post-processors (another post-processor's dependency pulled it in early)
     * never passes postProcessAfterInitialization; once every singleton exists its defaults are adjusted in place.
     */
    @Override
    public void afterSingletonsInstantiated() {
        if (beanFactory instanceof ListableBeanFactory listable) {
            listable.getBeansOfType(AnthropicChatModel.class, false, false)
                    .forEach((name, model) -> postProcessAfterInitialization(model, name));
        }
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (!(bean instanceof AnthropicChatModel)) {
            return bean;
        }
        Field field = ReflectionUtils.findField(AnthropicChatModel.class, "defaultOptions");
        if (field == null) {
            return bean;
        }
        try {
            ReflectionUtils.makeAccessible(field);
            if (field.get(bean) instanceof AnthropicChatOptions defaults) {
                adjust(defaults);
            }
        } catch (IllegalAccessException | RuntimeException e) {
            log.error("Failed to adjust the Anthropic chat model default options of bean '{}'", beanName, e);
        }
        return bean;
    }

    private void adjust(AnthropicChatOptions defaults) {
        if (ProviderAwareChatOptionsFactory.anthropicUsesDefaultSamplingOnly(defaults.getModel())) {
            defaults.setTemperature(null);
            defaults.setTopP(null);
            defaults.setTopK(null);
        }
        AnthropicCacheOptions cache = defaults.getCacheOptions();
        if (capabilities.isSystemPromptCache()
                && (cache == null || cache.getStrategy() == AnthropicCacheStrategy.NONE)) {
            defaults.setCacheOptions(AnthropicCacheOptions.builder().strategy(AnthropicCacheStrategy.SYSTEM_ONLY).build());
        }
    }
}
