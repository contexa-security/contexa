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
import java.lang.reflect.Field;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

@Slf4j
public class OpenAiChatModelPostProcessor implements BeanPostProcessor {

    private static final String OPENAI_CHAT_MODEL_CLASS = "org.springframework.ai.openai.OpenAiChatModel";

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean == null || !OPENAI_CHAT_MODEL_CLASS.equals(bean.getClass().getName())) {
            return bean;
        }
        Field defaultOptionsField = findField(bean.getClass(), "defaultOptions");
        if (defaultOptionsField == null) {
            return bean;
        }
        try {
            defaultOptionsField.setAccessible(true);
            Object defaultOptions = defaultOptionsField.get(bean);
            if (!(defaultOptions instanceof ChatOptions chatOptions)) {
                return bean;
            }
            if (bean instanceof ChatModel chatModel) {
                ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(chatModel);
                log.info("Normalized OpenAI chat model default options for bean '{}'.", beanName);
                return bean;
            }
            ChatOptions normalized = ProviderAwareChatOptionsFactory.normalizeModelDefaultOptions(chatOptions);
            if (normalized != chatOptions) {
                defaultOptionsField.set(bean, normalized);
                log.info("Normalized OpenAI chat model default options for bean '{}'.", beanName);
            }
        } catch (ReflectiveOperationException | RuntimeException ex) {
            log.error("Failed to normalize OpenAI chat model default options for bean '{}'.", beanName, ex);
        }
        return bean;
    }

    private Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null && current != Object.class) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                current = current.getSuperclass();
            }
        }
        return null;
    }
}
