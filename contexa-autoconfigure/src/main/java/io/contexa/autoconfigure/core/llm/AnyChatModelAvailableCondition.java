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

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

public class AnyChatModelAvailableCondition implements Condition {

    private static final String CONTEXA_PRIMARY_CHAT_MODEL_BEAN = "primaryChatModel";
    private static final String CONTEXA_OLLAMA_CHAT_BASE_URL_PROPERTY = "contexa.llm.chat.ollama.base-url";
    private static final String OLLAMA_CHAT_MODEL_CLASS = "org.springframework.ai.ollama.OllamaChatModel";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        ListableBeanFactory beanFactory = context.getBeanFactory();
        if (beanFactory == null) {
            return hasConfiguredContexaChatRuntime(context);
        }
        String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beanFactory, ChatModel.class, false, false);
        for (String beanName : beanNames) {
            if (!CONTEXA_PRIMARY_CHAT_MODEL_BEAN.equals(beanName)) {
                return true;
            }
        }
        return hasConfiguredContexaChatRuntime(context);
    }

    private boolean hasConfiguredContexaChatRuntime(ConditionContext context) {
        if (!ClassUtils.isPresent(OLLAMA_CHAT_MODEL_CLASS, context.getClassLoader())) {
            return false;
        }
        Environment environment = context.getEnvironment();
        if (environment == null) {
            return false;
        }
        String ollamaBaseUrl = environment.getProperty(CONTEXA_OLLAMA_CHAT_BASE_URL_PROPERTY);
        return StringUtils.hasText(ollamaBaseUrl);
    }
}
