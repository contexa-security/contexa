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
package io.contexa.autoconfigure.core.infra;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.config.KafkaTopicConfiguration;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import org.apache.kafka.clients.admin.NewTopic;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaAdmin;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-73, PR-79: Contexa's topics never stop the application's start. What cannot be checked or made is named at start,
 * whatever the application asked of its own Kafka administration.
 */
@ExtendWith(OutputCaptureExtension.class)
class ContexaKafkaTopicsStartTest {

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=127.0.0.1:1")
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class, KafkaTopicConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class));
    }

    @Test
    void aBrokerThatCannotBeReachedStopsNoStartEvenWhenTheApplicationAsksToFailFast(CapturedOutput output) {
        long began = System.nanoTime();

        runner().withPropertyValues("spring.kafka.admin.fail-fast=true").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("contexaKafkaTopics");
        });

        assertThat(Duration.ofNanos(System.nanoTime() - began)).isLessThan(Duration.ofSeconds(20));
        assertThat(output.getOut() + output.getErr()).contains("[ContexaKafkaTopics]")
                .contains(SecurityEventTopics.declared()).contains("ctxa.security-events-dlq");
    }

    @Test
    void theApplicationsKafkaAdminIsHandedNoTopicOfContexa() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(NewTopic.class)).isEmpty();
            assertThat(context.getBeansOfType(KafkaAdmin.NewTopics.class)).isEmpty();
        });
    }
}
