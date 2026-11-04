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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncAnnotationBeanPostProcessor;
import org.springframework.scheduling.config.TaskManagementConfigUtils;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;

/**
 * {@code @Async} for Contexa's own beans, without {@code @EnableAsync} for the application: an {@code @Async} method of the application
 * that the application never turned asynchronous execution on for keeps running on the caller's thread.
 * <p>
 * When the application's own support is in the context it serves Contexa's beans, and this processor stands aside — unless the
 * application's support does not look at {@code @Async} at all ({@code @EnableAsync(annotation = ...)} for a marker of its own): then
 * Contexa's methods would run on the caller's thread, so this processor keeps serving them. The two never advise the same method,
 * because each looks at a different annotation.
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
        return ContexaPackages.owns(targetClass) && !applicationServesAsync() && super.isEligible(targetClass);
    }

    private boolean applicationServesAsync() {
        if (!ContexaPackages.contextHas(beanFactory, TaskManagementConfigUtils.ASYNC_ANNOTATION_PROCESSOR_BEAN_NAME)) {
            return false;
        }
        Object processor;
        try {
            processor = beanFactory.getBean(TaskManagementConfigUtils.ASYNC_ANNOTATION_PROCESSOR_BEAN_NAME);
        } catch (BeansException e) {
            // the application's processor is still being made: the bean asked about was made while it was, which that processor never sees
            return false;
        }
        Field marker = ReflectionUtils.findField(processor.getClass(), "asyncAnnotationType");
        if (marker == null) {
            // not known what the application's support looks at: two supports advising one method only hop threads twice, none loses it
            return false;
        }
        ReflectionUtils.makeAccessible(marker);
        Object type = ReflectionUtils.getField(marker, processor);
        return type == null || type == Async.class;
    }
}
