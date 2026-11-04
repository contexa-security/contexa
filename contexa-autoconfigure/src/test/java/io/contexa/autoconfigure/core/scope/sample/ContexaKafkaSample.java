package io.contexa.autoconfigure.core.scope.sample;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;

import java.util.Map;

/** A bean of a Contexa package (this package stands in for a Contexa library) with a listener, as the security event collector has it. */
public class ContexaKafkaSample {

    @KafkaListener(id = "contexa-sample", topics = "security.events.sample", containerFactory = "contexaSampleKafkaFactory", autoStartup = "false")
    public void consume(String message) {
    }

    @Configuration(proxyBeanMethods = false)
    public static class Definition {

        @Bean
        ContexaKafkaSample contexaKafkaSample() {
            return new ContexaKafkaSample();
        }

        /** Contexa's container factory, which its listener names; no broker is ever contacted (the listeners do not start). */
        @Bean(name = "contexaSampleKafkaFactory", defaultCandidate = false)
        ConcurrentKafkaListenerContainerFactory<String, String> contexaSampleKafkaFactory() {
            ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
            factory.setConsumerFactory(new DefaultKafkaConsumerFactory<>(Map.of(
                    ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "127.0.0.1:1",
                    ConsumerConfig.GROUP_ID_CONFIG, "contexa-sample",
                    ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                    ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)));
            return factory;
        }
    }
}
