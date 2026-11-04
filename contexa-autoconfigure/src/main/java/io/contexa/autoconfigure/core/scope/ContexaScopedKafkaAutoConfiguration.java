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

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.kafka.annotation.KafkaListenerAnnotationBeanPostProcessor;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;

/**
 * Kafka listening for Contexa's own beans (the security event collector of the distributed mode), and for them only. Contexa used to switch
 * {@code @EnableKafka} on for the whole application, which started the application's dormant {@code @KafkaListener} methods; and with
 * the switch gone, the collector would stay silent in an application that excluded Spring Boot's Kafka auto-configuration. This support
 * keeps the collector listening in both and leaves the application's listeners as the application left them.
 */
@AutoConfiguration
@ConditionalOnClass(KafkaListenerAnnotationBeanPostProcessor.class)
@ConditionalOnProperty(prefix = "contexa.infrastructure", name = "mode", havingValue = "distributed")
public class ContexaScopedKafkaAutoConfiguration {

    @Bean(name = "contexaKafkaListenerAnnotationProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static ContexaKafkaListenerAnnotationBeanPostProcessor contexaKafkaListenerAnnotationProcessor() {
        return new ContexaKafkaListenerAnnotationBeanPostProcessor();
    }

    /** The registry of Contexa's listeners; not a candidate for injection by type, so an application that asks for its registry never gets it. */
    @Bean(name = "contexaKafkaListenerEndpointRegistry", autowireCandidate = false)
    KafkaListenerEndpointRegistry contexaKafkaListenerEndpointRegistry() {
        return new KafkaListenerEndpointRegistry();
    }
}
