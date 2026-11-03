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
import org.springframework.scheduling.config.TaskManagementConfigUtils;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/**
 * {@code @Scheduled} for Contexa's own beans, without {@code @EnableScheduling} for the application: a {@code @Scheduled} method of the
 * application that the application never turned scheduling on for stays dormant. The tasks run on a scheduler of Contexa's own, which
 * this processor starts and stops with itself.
 */
public class ContexaScheduledAnnotationBeanPostProcessor extends ScheduledAnnotationBeanPostProcessor {

    private final ThreadPoolTaskScheduler scheduler;
    private BeanFactory beanFactory;

    public ContexaScheduledAnnotationBeanPostProcessor(int poolSize) {
        this.scheduler = new ThreadPoolTaskScheduler();
        this.scheduler.setPoolSize(Math.max(1, poolSize));
        this.scheduler.setThreadNamePrefix("contexa-scheduling-");
        this.scheduler.setRemoveOnCancelPolicy(true);
        this.scheduler.initialize();
        setScheduler(this.scheduler);
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(beanFactory);
        this.beanFactory = beanFactory;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        return ContexaPackages.ownsBean(bean)
                && !ContexaPackages.contextHas(beanFactory, TaskManagementConfigUtils.SCHEDULED_ANNOTATION_PROCESSOR_BEAN_NAME)
                ? super.postProcessAfterInitialization(bean, beanName) : bean;
    }

    @Override
    public void destroy() {
        super.destroy();
        scheduler.shutdown();
    }
}
