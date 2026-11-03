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
package io.contexa.autoconfigure.core.scope;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.scheduling.annotation.AsyncAnnotationBeanPostProcessor;
import org.springframework.scheduling.config.TaskManagementConfigUtils;

/**
 * {@code @Async} for Contexa's own beans, without {@code @EnableAsync} for the application: an {@code @Async} method of the application
 * that the application never turned asynchronous execution on for keeps running on the caller's thread.
 */
public class ContexaAsyncAnnotationBeanPostProcessor extends AsyncAnnotationBeanPostProcessor {

    private BeanFactory beanFactory;

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(beanFactory);
        this.beanFactory = beanFactory;
    }

    @Override
    protected boolean isEligible(Class<?> targetClass) {
        return ContexaPackages.owns(targetClass)
                && !ContexaPackages.contextHas(beanFactory, TaskManagementConfigUtils.ASYNC_ANNOTATION_PROCESSOR_BEAN_NAME)
                && super.isEligible(targetClass);
    }
}
