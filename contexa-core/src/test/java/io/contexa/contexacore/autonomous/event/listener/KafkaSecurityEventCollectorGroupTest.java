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
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanExpressionContext;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.mock.env.MockEnvironment;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The consumer group of an application: two applications on one Kafka cluster must not be one group, or they split the
 * partitions of the topics between them and each analyses the events of the other.
 */
class KafkaSecurityEventCollectorGroupTest {

    /** The group id the way Spring Kafka resolves it: the placeholders of the environment first, then the expression. */
    private static String groupOf(String groupProperty) throws NoSuchMethodException {
        Method listener = KafkaSecurityEventCollector.class.getMethod("consumeZeroTrustEvents", String.class,
                String.class, int.class, long.class, ConsumerRecord.class, Acknowledgment.class);
        String declared = listener.getAnnotation(KafkaListener.class).groupId();

        MockEnvironment environment = new MockEnvironment();
        if (groupProperty != null) {
            environment.setProperty("security.plane.kafka.group-id", groupProperty);
        }
        try (StaticApplicationContext context = new StaticApplicationContext()) {
            context.setEnvironment(environment);
            context.refresh();
            context.getBeanFactory().addEmbeddedValueResolver(environment::resolvePlaceholders);
            String withPlaceholders = context.getBeanFactory().resolveEmbeddedValue(declared);
            Object group = context.getBeanFactory().getBeanExpressionResolver()
                    .evaluate(withPlaceholders, new BeanExpressionContext(context.getBeanFactory(), null));
            return String.valueOf(group);
        }
    }

    @Test
    @DisplayName("an application without a name is in the group it always was in")
    void anUnnamedApplicationKeepsItsGroup() throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(groupOf(null)).isEqualTo("security-plane-consumer");
        }
    }

    @Test
    @DisplayName("an application with a name is in security-plane-consumer.<name>")
    void aNamedApplicationHasAGroupOfItsOwn() throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("Shop")) {
            assertThat(groupOf(null)).isEqualTo("security-plane-consumer.shop");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("clinic")) {
            assertThat(groupOf(null)).isEqualTo("security-plane-consumer.clinic");
        }
    }

    @Test
    @DisplayName("a group the operator named is still the base of the group of a named application")
    void aGroupNamedByTheOperatorGetsTheNameToo() throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(groupOf("audit-group")).isEqualTo("audit-group.shop");
        }
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(groupOf("audit-group")).isEqualTo("audit-group");
        }
    }
}
