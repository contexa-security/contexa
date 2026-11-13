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

import io.contexa.contexacore.std.llm.gate.UnreachableModelServerRetryListener;
import org.springframework.ai.retry.RetryUtils;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.retry.support.RetryTemplate;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Adds {@link UnreachableModelServerRetryListener} to the RetryTemplates the model clients use: each RetryTemplate bean
 * (spring.ai.retry, which Boot's model clients take) and Spring AI's default one (models built without their own). The
 * retry settings stay as they are; the listener ends the retry only for a model call of Contexa whose server cannot be
 * reached, so the application's own model calls are not changed.
 */
final class ModelCallRetryListenerRegistrar implements BeanPostProcessor {

    private static final UnreachableModelServerRetryListener LISTENER = new UnreachableModelServerRetryListener();
    private static final AtomicBoolean DEFAULT_TEMPLATE_LISTENED = new AtomicBoolean();

    ModelCallRetryListenerRegistrar() {
        if (DEFAULT_TEMPLATE_LISTENED.compareAndSet(false, true)) {
            RetryUtils.DEFAULT_RETRY_TEMPLATE.registerListener(LISTENER);
        }
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof RetryTemplate template) {
            template.registerListener(LISTENER);
        }
        return bean;
    }
}
