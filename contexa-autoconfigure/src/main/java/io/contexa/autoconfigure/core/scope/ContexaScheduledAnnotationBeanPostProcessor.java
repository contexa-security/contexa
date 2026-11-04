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
import org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.TaskManagementConfigUtils;
import org.springframework.scheduling.TaskScheduler;

/**
 * {@code @Scheduled} for Contexa's own beans, without {@code @EnableScheduling} for the application: a {@code @Scheduled} method of the
 * application that the application never turned scheduling on for stays dormant. The tasks run on a scheduler of Contexa's own, which
 * this processor starts and stops with itself.
 */
public class ContexaScheduledAnnotationBeanPostProcessor extends ScheduledAnnotationBeanPostProcessor {

    private BeanFactory beanFactory;

    public ContexaScheduledAnnotationBeanPostProcessor(TaskScheduler scheduler) {
        setScheduler(scheduler);
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(HiddenBeanTypes.hiding(beanFactory, SchedulingConfigurer.class));
        this.beanFactory = beanFactory;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        return ContexaPackages.ownsBean(bean)
                && !ContexaPackages.contextHas(beanFactory, TaskManagementConfigUtils.SCHEDULED_ANNOTATION_PROCESSOR_BEAN_NAME)
                ? super.postProcessAfterInitialization(bean, beanName) : bean;
    }

}
