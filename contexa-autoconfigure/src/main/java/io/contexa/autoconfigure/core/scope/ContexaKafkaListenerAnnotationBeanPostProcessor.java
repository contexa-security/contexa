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
import org.springframework.kafka.annotation.KafkaListenerAnnotationBeanPostProcessor;
import org.springframework.kafka.annotation.KafkaListenerConfigurer;
import org.springframework.kafka.config.KafkaListenerConfigUtils;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;

/**
 * {@code @KafkaListener} for Contexa's own beans, without {@code @EnableKafka} for the application: a {@code @KafkaListener} of the
 * application that the application never turned listening on for stays dormant, and the listeners of Contexa are registered in a registry
 * of Contexa's own, so that they neither take the application's registry nor the application's listener ids.
 * <p>
 * Contexa's collector must listen whether or not the application switched Kafka listening on, so this processor serves Contexa's beans
 * whenever the application's own support (Spring Boot's Kafka auto-configuration or an {@code @EnableKafka}) is not in the context. When it
 * is, the application's processor serves Contexa's beans too, and this one leaves them to it. The question is asked when a bean is
 * processed, not when the auto-configurations are evaluated, so the order of auto-configurations does not matter.
 */
public class ContexaKafkaListenerAnnotationBeanPostProcessor extends KafkaListenerAnnotationBeanPostProcessor<Object, Object> {

    /** The registry of Contexa's listeners; hidden from injection by type, reached by its name. */
    static final String REGISTRY_BEAN_NAME = "contexaKafkaListenerEndpointRegistry";

    private BeanFactory beanFactory;

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        super.setBeanFactory(HiddenBeanTypes.hiding(beanFactory, KafkaListenerConfigurer.class));
        this.beanFactory = beanFactory;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        return ContexaPackages.ownsBean(bean)
                && !ContexaPackages.contextHas(beanFactory, KafkaListenerConfigUtils.KAFKA_LISTENER_ANNOTATION_PROCESSOR_BEAN_NAME)
                ? super.postProcessAfterInitialization(bean, beanName) : bean;
    }

    @Override
    public void afterSingletonsInstantiated() {
        setEndpointRegistry(beanFactory.getBean(REGISTRY_BEAN_NAME, KafkaListenerEndpointRegistry.class));
        super.afterSingletonsInstantiated();
    }
}
