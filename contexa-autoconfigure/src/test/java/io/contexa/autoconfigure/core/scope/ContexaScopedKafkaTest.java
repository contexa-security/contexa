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

import com.legacyshop.scope.LegacyKafkaApplication;
import io.contexa.autoconfigure.core.scope.sample.ContexaKafkaSample;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.KafkaListenerConfigUtils;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa's collector listens whether or not the application switched Kafka listening on, the application's own listeners are its own
 * business, and the two never take each other's registry or ids.
 */
class ContexaScopedKafkaTest {

    private static final String CONTEXA = "contexa-sample";
    private static final String APPLICATION = "app-listener";

    /** Comes after Contexa's auto-configuration and switches listening on, as Spring Boot's own Kafka auto-configuration may. */
    @AutoConfiguration(after = ContexaScopedKafkaAutoConfiguration.class)
    @EnableKafka
    static class LaterAutoConfiguration {
    }

    private ApplicationContextRunner runner(Class<?> application) {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed")
                .withUserConfiguration(application, ContexaKafkaSample.Definition.class)
                .withConfiguration(AutoConfigurations.of(ContexaScopedKafkaAutoConfiguration.class));
    }

    @Test
    void contexasListenerListensAndTheApplicationsDormantOneDoesNot() {
        runner(LegacyKafkaApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            KafkaListenerEndpointRegistry registry = context.getBean(ContexaKafkaListenerAnnotationBeanPostProcessor.REGISTRY_BEAN_NAME,
                    KafkaListenerEndpointRegistry.class);

            assertThat(registry.getListenerContainerIds()).as("listeners registered in Contexa's registry")
                    .contains(CONTEXA).doesNotContain(APPLICATION);
            assertThat(context).as("the application's own registry and processor were not made for it")
                    .doesNotHaveBean(KafkaListenerConfigUtils.KAFKA_LISTENER_ENDPOINT_REGISTRY_BEAN_NAME)
                    .doesNotHaveBean(KafkaListenerConfigUtils.KAFKA_LISTENER_ANNOTATION_PROCESSOR_BEAN_NAME);
        });
    }

    @Test
    void theApplicationsListenerConfigurerIsNeverCalledWhenListeningIsNotEnabled() {
        runner(LegacyKafkaApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBean(LegacyKafkaApplication.CountingListenerConfigurer.class).calls())
                    .as("the application never turned listening on: Contexa's listening does not bring its configurer to life").isZero();
        });
    }

    @Test
    void theApplicationsListenerConfigurerIsCalledOnceNotForContexasListeningToo() {
        runner(LegacyKafkaApplication.Enabled.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context.getBean(LegacyKafkaApplication.CountingListenerConfigurer.class).calls())
                    .as("applied to the application's own listening only").isEqualTo(1);
        });
    }

    @Test
    void applicationCodeAskingForAListenerRegistryGetsNoneOfContexas() {
        runner(LegacyKafkaApplication.Dormant.class).run(context -> {
            assertThat(context).hasNotFailed();
            LegacyKafkaApplication.RegistryConsumer consumer = context.getBean(LegacyKafkaApplication.RegistryConsumer.class);

            assertThat(consumer.viaInjection()).isNull();
            assertThat(consumer.viaProvider()).isNull();
        });
    }

    @Test
    void anApplicationThatSwitchedListeningOnItselfServesBothListenersAndContexaStandsAside() {
        runner(LegacyKafkaApplication.Enabled.class).run(context -> {
            assertThat(context).hasNotFailed();
            KafkaListenerEndpointRegistry applications = context.getBean(KafkaListenerConfigUtils.KAFKA_LISTENER_ENDPOINT_REGISTRY_BEAN_NAME,
                    KafkaListenerEndpointRegistry.class);

            assertThat(applications.getListenerContainerIds()).as("the application's processor serves both").contains(CONTEXA, APPLICATION);
            assertThat(context.getBean(ContexaKafkaListenerAnnotationBeanPostProcessor.REGISTRY_BEAN_NAME, KafkaListenerEndpointRegistry.class)
                    .getListenerContainerIds()).as("Contexa's own registry holds nothing: the application's processor registered the listener").isEmpty();
        });
    }

    @Test
    void listeningSwitchedOnLaterByAnotherAutoConfigurationRegistersContexasListenerOnce() {
        runner(LegacyKafkaApplication.Dormant.class).withConfiguration(AutoConfigurations.of(LaterAutoConfiguration.class)).run(context -> {
            assertThat(context).as("two processors registering one listener id would fail the start").hasNotFailed();
            assertThat(context).as("Contexa's was evaluated first and is there").hasBean("contexaKafkaListenerAnnotationProcessor");
            KafkaListenerEndpointRegistry applications = context.getBean(KafkaListenerConfigUtils.KAFKA_LISTENER_ENDPOINT_REGISTRY_BEAN_NAME,
                    KafkaListenerEndpointRegistry.class);
            KafkaListenerEndpointRegistry contexas = context.getBean(ContexaKafkaListenerAnnotationBeanPostProcessor.REGISTRY_BEAN_NAME,
                    KafkaListenerEndpointRegistry.class);

            assertThat(applications.getListenerContainerIds()).contains(CONTEXA, APPLICATION);
            assertThat(contexas.getListenerContainerIds()).as("Contexa's own registry holds nothing then").isEmpty();
        });
    }

    @Test
    void nothingIsMadeOutsideTheDistributedMode() {
        new ApplicationContextRunner()
                .withUserConfiguration(LegacyKafkaApplication.Dormant.class)
                .withConfiguration(AutoConfigurations.of(ContexaScopedKafkaAutoConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean("contexaKafkaListenerAnnotationProcessor")
                        .doesNotHaveBean(ContexaKafkaListenerAnnotationBeanPostProcessor.REGISTRY_BEAN_NAME));
    }
}
