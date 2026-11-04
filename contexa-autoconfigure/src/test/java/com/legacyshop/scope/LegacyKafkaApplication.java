package com.legacyshop.scope;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.annotation.KafkaListenerConfigurer;
import org.springframework.kafka.config.KafkaListenerEndpointRegistrar;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.lang.Nullable;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** A legacy application (a package that is not Contexa's) with a {@code @KafkaListener} it may or may not have turned listening on for. */
public class LegacyKafkaApplication {

    public static class AppListener {

        @KafkaListener(id = "app-listener", topics = "orders", containerFactory = "appKafkaFactory", autoStartup = "false")
        public void consume(String message) {
        }
    }

    /** The application's own listener configuration: only the application's listening support may ever call it, and once. */
    public static class CountingListenerConfigurer implements KafkaListenerConfigurer {

        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public void configureKafkaListeners(KafkaListenerEndpointRegistrar registrar) {
            calls.incrementAndGet();
        }

        public int calls() {
            return calls.get();
        }
    }

    /** Application code that asks for "the listener registry, if there is one" and acts on the answer. */
    public static class RegistryConsumer {

        private final KafkaListenerEndpointRegistry viaInjection;
        private final KafkaListenerEndpointRegistry viaProvider;

        public RegistryConsumer(@Nullable KafkaListenerEndpointRegistry viaInjection, ObjectProvider<KafkaListenerEndpointRegistry> provider) {
            this.viaInjection = viaInjection;
            this.viaProvider = provider.getIfAvailable();
        }

        public KafkaListenerEndpointRegistry viaInjection() {
            return viaInjection;
        }

        public KafkaListenerEndpointRegistry viaProvider() {
            return viaProvider;
        }
    }

    static ConcurrentKafkaListenerContainerFactory<String, String> factory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(new DefaultKafkaConsumerFactory<>(Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "127.0.0.1:1",
                ConsumerConfig.GROUP_ID_CONFIG, "app",
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)));
        return factory;
    }

    /** Listening is not switched on: the listener is dormant. */
    @Configuration(proxyBeanMethods = false)
    public static class Dormant {

        @Bean
        AppListener appListener() {
            return new AppListener();
        }

        @Bean
        CountingListenerConfigurer listenerConfigurer() {
            return new CountingListenerConfigurer();
        }

        @Bean(name = "appKafkaFactory")
        ConcurrentKafkaListenerContainerFactory<String, String> appKafkaFactory() {
            return factory();
        }

        @Bean
        RegistryConsumer registryConsumer(@Nullable KafkaListenerEndpointRegistry registry, ObjectProvider<KafkaListenerEndpointRegistry> provider) {
            return new RegistryConsumer(registry, provider);
        }
    }

    /** The application turned listening on itself. */
    @Configuration(proxyBeanMethods = false)
    @EnableKafka
    public static class Enabled {

        @Bean
        AppListener appListener() {
            return new AppListener();
        }

        @Bean
        CountingListenerConfigurer listenerConfigurer() {
            return new CountingListenerConfigurer();
        }

        @Bean(name = "appKafkaFactory")
        ConcurrentKafkaListenerContainerFactory<String, String> appKafkaFactory() {
            return factory();
        }
    }
}
