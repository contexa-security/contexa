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
package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanExpressionContext;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.mock.env.MockEnvironment;

import java.lang.reflect.Method;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The topics the collector subscribes to, as Spring Kafka resolves its declaration: those of its own application, and no
 * topic of another application or of an application that is not Contexa.
 */
class KafkaSecurityEventCollectorTopicTest {

    /** The topic pattern the way Spring Kafka resolves it: the placeholders of the environment first, then the expression. */
    private static Pattern subscription() throws NoSuchMethodException {
        Method listener = KafkaSecurityEventCollector.class.getMethod("consumeZeroTrustEvents", String.class,
                String.class, int.class, long.class, ConsumerRecord.class, Acknowledgment.class);
        KafkaListener declaration = listener.getAnnotation(KafkaListener.class);
        assertThat(declaration.topics()).as("the collector names no topic outside its pattern").isEmpty();

        MockEnvironment environment = new MockEnvironment();
        try (StaticApplicationContext context = new StaticApplicationContext()) {
            context.setEnvironment(environment);
            context.refresh();
            context.getBeanFactory().addEmbeddedValueResolver(environment::resolvePlaceholders);
            String withPlaceholders = context.getBeanFactory().resolveEmbeddedValue(declaration.topicPattern());
            Object pattern = context.getBeanFactory().getBeanExpressionResolver()
                    .evaluate(withPlaceholders, new BeanExpressionContext(context.getBeanFactory(), null));
            return Pattern.compile(String.valueOf(pattern));
        }
    }

    @Test
    @DisplayName("an application with a name subscribes to ctxa.<name>.security.events.* and to nothing of another")
    void aNamedApplicationReadsItsOwnTopics() throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            Pattern subscription = subscription();

            assertThat(subscription.pattern()).isEqualTo(SecurityEventTopics.pattern());
            assertThat(subscription.matcher("ctxa.shop.security.events.authorization.method").matches()).isTrue();
            assertThat(subscription.matcher("ctxa.shop.security.events.custom.order-placed").matches()).isTrue();
            assertThat(subscription.matcher("ctxa.clinic.security.events.authorization.method").matches()).isFalse();
            assertThat(subscription.matcher("ctxa.security.events.authorization.method").matches()).isFalse();
            assertThat(subscription.matcher("security.events.authorization.method").matches()).isFalse();
        }
    }

    @Test
    @DisplayName("an application without a name subscribes to ctxa.security.events.*, not to a topic named as another application may")
    void anUnnamedApplicationReadsOnlyContexasTopics() throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            Pattern subscription = subscription();

            assertThat(subscription.matcher("ctxa.security.events.authentication.success").matches()).isTrue();
            assertThat(subscription.matcher("security.events.authentication.success").matches()).isFalse();
            assertThat(subscription.matcher("security.events.orders.created").matches()).isFalse();
            assertThat(subscription.matcher("ctxa.shop.security.events.authentication.success").matches()).isFalse();
        }
    }
}
