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
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.config.KafkaTopicConfiguration;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.KafkaTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * PR-88 (L14) on a real broker. CONTEXA_TEST_KAFKA_LOGIN_PORT: a SASL_PLAINTEXT broker of this test alone with the user
 * {@code rc}, password {@code rc-secret}. The application sets the login only the way Spring Boot documents it; Contexa's
 * admin client, producer and consumer all have to come in with it.
 */
@ExtendWith(OutputCaptureExtension.class)
class ContexaKafkaLoginBrokerTest {

    private static final String PORT = "CONTEXA_TEST_KAFKA_LOGIN_PORT";
    private static final String JAAS = "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"rc\" "
            + "password=\"%s\";";

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper().findAndRegisterModules();
        }
    }

    private static String bootstrap() {
        return "127.0.0.1:" + System.getenv(PORT);
    }

    private static Map<String, Object> login(String password) {
        return Map.of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap(),
                CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT",
                SaslConfigs.SASL_MECHANISM, "PLAIN",
                SaslConfigs.SASL_JAAS_CONFIG, JAAS.formatted(password));
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=" + bootstrap(),
                        "spring.kafka.security.protocol=SASL_PLAINTEXT", "spring.kafka.properties.sasl.mechanism=PLAIN",
                        "spring.kafka.properties.sasl.jaas.config=" + JAAS.formatted("rc-secret"))
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class, KafkaTopicConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class));
    }

    @SuppressWarnings("unchecked")
    private static KafkaSecurityEventPublisher publisher(AssertableApplicationContext context) {
        return new KafkaSecurityEventPublisher(context.getBean("contexaKafkaTemplate", KafkaTemplate.class),
                new SecurityKafkaProperties());
    }

    @SuppressWarnings("unchecked")
    private static Consumer<String, String> consumer(AssertableApplicationContext context) {
        return ((ConsumerFactory<String, String>) context.getBean("contexaConsumerFactory", ConsumerFactory.class))
                .createConsumer("login-test-" + UUID.randomUUID(), "login-test");
    }

    /** The control: this broker turns a wrong login away, so an event that goes through says the login was used. */
    @Test
    @EnabledIfEnvironmentVariable(named = PORT, matches = "[0-9]+")
    void theBrokerRefusesAWrongLogin() {
        try (Admin admin = Admin.create(login("wrong"))) {
            assertThatThrownBy(() -> admin.listTopics().names().get(20, TimeUnit.SECONDS))
                    .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(SaslAuthenticationException.class);
        }
    }

    @Test
    @EnabledIfEnvironmentVariable(named = PORT, matches = "[0-9]+")
    void contexasClientsComeInWithTheLoginSpringBootWasGiven(CapturedOutput output) throws Exception {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            try (Admin admin = Admin.create(login("rc-secret"))) {
                assertThat(admin.listTopics().names().get(20, TimeUnit.SECONDS))
                        .as("Contexa's admin client made the topics").containsAll(SecurityEventTopics.declared());
            }
            KafkaSecurityEventPublisher publisher = publisher(context);
            try (Consumer<String, String> consumer = consumer(context)) {
                consumer.subscribe(Pattern.compile(SecurityEventTopics.pattern()));
                Awaitility.await().atMost(Duration.ofSeconds(30)).pollDelay(Duration.ZERO).until(() -> {
                    consumer.poll(Duration.ofMillis(200));
                    return !consumer.assignment().isEmpty();
                });
                String type = ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS;
                String topic = SecurityEventTopics.of(ZeroTrustEventCategory.AUTHENTICATION, type);
                publisher.publishGenericSecurityEvent(ZeroTrustSpringEvent.builder("login-test")
                        .category(ZeroTrustEventCategory.AUTHENTICATION).eventType(type).userId("broker-user")
                        .sessionId("broker-session").clientIp("127.0.0.1").payload(Map.of("action", "ALLOW")).build());

                List<String> read = new ArrayList<>();
                long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
                while (read.isEmpty() && System.nanoTime() < deadline) {
                    consumer.poll(Duration.ofMillis(200)).forEach(record -> {
                        if (record.topic().equals(topic)) {
                            read.add(record.value());
                        }
                    });
                }
                assertThat(read).as("the event went through the producer and came back through the consumer").hasSize(1);
            } finally {
                publisher.destroy();
            }
        });
        assertThat(output.getOut() + output.getErr()).doesNotContain("[ContexaKafkaTopics]")
                .doesNotContain("Authentication failed").doesNotContain("Bootstrap broker");
    }
}
