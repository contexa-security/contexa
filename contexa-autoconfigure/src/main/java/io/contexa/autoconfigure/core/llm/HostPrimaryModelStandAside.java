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

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Contexa registers its own chat model, embedding model and chat client builder as {@code @Primary}, because its engine takes them by
 * type. An application that already has a {@code @Primary} bean of the same type (it chose its default model) then has two, and Spring
 * does not start ("more than one 'primary' bean found"). The application's choice stands: Contexa's beans lose their primary flag,
 * and Contexa's engine, which takes the type, is given the application's primary model. Applications without a primary model of their own
 * are not touched.
 */
@Slf4j
final class HostPrimaryModelStandAside implements BeanFactoryPostProcessor {

    static final String CONTEXA_PREFIX = "contexa";

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        standAside(beanFactory, ChatModel.class);
        standAside(beanFactory, EmbeddingModel.class);
        standAside(beanFactory, ChatClient.Builder.class);
    }

    private static void standAside(ConfigurableListableBeanFactory beanFactory, Class<?> type) {
        List<String> contexaPrimaries = new ArrayList<>();
        List<String> hostPrimaries = new ArrayList<>();
        for (String name : beanFactory.getBeanNamesForType(type, true, false)) {
            if (!beanFactory.containsBeanDefinition(name)) {
                continue;
            }
            BeanDefinition definition = beanFactory.getBeanDefinition(name);
            if (!definition.isPrimary()) {
                continue;
            }
            (name.startsWith(CONTEXA_PREFIX) ? contexaPrimaries : hostPrimaries).add(name);
        }
        if (hostPrimaries.isEmpty() || contexaPrimaries.isEmpty()) {
            return;
        }
        for (String name : contexaPrimaries) {
            beanFactory.getBeanDefinition(name).setPrimary(false);
        }
        // the merged definitions that the look-ups above cached still carry the flag
        beanFactory.clearMetadataCache();
        log.warn("The application has its own primary {} {}: Contexa's {} are no longer primary, and Contexa uses the application's primary {}.",
                type.getSimpleName(), hostPrimaries, contexaPrimaries, type.getSimpleName());
    }
}
