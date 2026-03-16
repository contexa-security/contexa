package io.contexa.contexacore.infra.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.*;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.support.serializer.JsonSerializer;
import org.springframework.util.backoff.FixedBackOff;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableKafka
@ConditionalOnClass(KafkaTemplate.class)
@ConditionalOnBean(KafkaProperties.class)
@ConditionalOnProperty(prefix = "contexa.infrastructure", name = "mode", havingValue = "distributed")
@RequiredArgsConstructor
public class KafkaConfiguration {

    private final KafkaProperties kafkaProperties;

    @Bean
    public Map<String, Object> consumerConfigs() {
        Map<String, Object> props = new HashMap<>();
        String bootstrapServers = String.join(",", kafkaProperties.getBootstrapServers());
        String groupId = kafkaProperties.getConsumer().getGroupId() != null ? kafkaProperties.getConsumer().getGroupId() : "security-plane-consumer";
        String autoOffsetReset = kafkaProperties.getConsumer().getAutoOffsetReset() != null ? kafkaProperties.getConsumer().getAutoOffsetReset() : "earliest";
        Boolean enableAutoCommit = kafkaProperties.getConsumer().getEnableAutoCommit() != null ? kafkaProperties.getConsumer().getEnableAutoCommit() : false;
        int maxPollRecords = kafkaProperties.getConsumer().getProperties().containsKey("max.poll.records") ? Integer.parseInt(kafkaProperties.getConsumer().getProperties().get("max.poll.records")) : 500;

        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, autoOffsetReset);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, enableAutoCommit);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, maxPollRecords);

        props.put(JsonDeserializer.TRUSTED_PACKAGES, "io.contexa.contexacore.*");
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, "io.contexa.contexacore.plane.domain.SecurityEvent");
        
        return props;
    }

    @Bean
    public Map<String, Object> producerConfigs() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, String.join(",", kafkaProperties.getBootstrapServers()));
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 16384);
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10);
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);
        
        return props;
    }

    @Bean
    public ConsumerFactory<String, String> consumerFactory() {
        return new DefaultKafkaConsumerFactory<>(consumerConfigs());
    }

    @Bean
    public ProducerFactory<String, Object> producerFactory(ObjectMapper objectMapper) {
        Map<String, Object> props = new HashMap<>(producerConfigs());
        JsonSerializer<Object> serializer = new JsonSerializer<>(objectMapper);
        serializer.setAddTypeInfo(false);
        return new DefaultKafkaProducerFactory<>(props, new StringSerializer(), serializer);
    }

    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory<String, Object> producerFactory) {
        return new KafkaTemplate<>(producerFactory);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        
        factory.setConsumerFactory(consumerFactory());
        Integer concurrency = kafkaProperties.getListener().getConcurrency() != null ? kafkaProperties.getListener().getConcurrency() : 3;
        factory.setConcurrency(concurrency);

        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);

        DefaultErrorHandler errorHandler = new DefaultErrorHandler(new FixedBackOff(1000L, 3));
        factory.setCommonErrorHandler(errorHandler);

        return factory;
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> batchKafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory =
            new ConcurrentKafkaListenerContainerFactory<>();

        factory.setBatchListener(true);
        Integer concurrency = kafkaProperties.getListener().getConcurrency() != null ? kafkaProperties.getListener().getConcurrency() : 3;
        factory.setConcurrency(concurrency);

        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
        factory.getContainerProperties().setPollTimeout(3000);

        DefaultErrorHandler errorHandler = new DefaultErrorHandler(new FixedBackOff(2000L, 3));
        factory.setCommonErrorHandler(errorHandler);

        Map<String, Object> props = new HashMap<>(consumerConfigs());
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 10);       
        props.put(ConsumerConfig.FETCH_MIN_BYTES_CONFIG, 1);         
        props.put(ConsumerConfig.FETCH_MAX_WAIT_MS_CONFIG, 100);     

        ConsumerFactory<String, String> batchConsumerFactory =
            new DefaultKafkaConsumerFactory<>(props);
        factory.setConsumerFactory(batchConsumerFactory);

        return factory;
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> jsonKafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        
        Map<String, Object> props = new HashMap<>(consumerConfigs());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        
        ConsumerFactory<String, Object> jsonConsumerFactory = 
            new DefaultKafkaConsumerFactory<>(props);
        
        factory.setConsumerFactory(jsonConsumerFactory);
        Integer concurrency = kafkaProperties.getListener().getConcurrency() != null ? kafkaProperties.getListener().getConcurrency() : 3;
        factory.setConcurrency(concurrency);

        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);

        return factory;
    }
}