package io.contexa.contexacore.infra.kafka;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
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

/**
 * Kafka Configuration
 * 
 * Apache Kafka 메시징 설정을 제공합니다.
 * 보안 이벤트 수집 및 처리를 위한 배치 처리 기능을 포함합니다.
 */
@Configuration
@EnableKafka
public class KafkaConfiguration {

    @Value("${spring.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id:security-plane-consumer}")
    private String groupId;  // Listener와 통일

    @Value("${spring.kafka.consumer.auto-offset-reset:earliest}")
    private String autoOffsetReset;
    
    @Value("${spring.kafka.consumer.max-poll-records:500}")
    private int maxPollRecords;
    
    @Value("${spring.kafka.consumer.enable-auto-commit:false}")
    private boolean enableAutoCommit;
    
    @Value("${spring.kafka.listener.concurrency:3}")
    private int concurrency;

    /**
     * Kafka Consumer 설정
     */
    @Bean
    public Map<String, Object> consumerConfigs() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, autoOffsetReset);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, enableAutoCommit);
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, maxPollRecords);
        
        // JSON 역직렬화 설정
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "io.contexa.contexacore.*");
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, "io.contexa.contexacore.plane.domain.SecurityEvent");
        
        return props;
    }

    /**
     * Kafka Producer 설정
     */
    @Bean
    public Map<String, Object> producerConfigs() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 16384);
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10);
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);
        
        return props;
    }

    /**
     * Consumer Factory
     */
    @Bean
    public ConsumerFactory<String, String> consumerFactory() {
        return new DefaultKafkaConsumerFactory<>(consumerConfigs());
    }

    /**
     * Producer Factory
     */
    @Bean
    public ProducerFactory<String, Object> producerFactory() {
        return new DefaultKafkaProducerFactory<>(producerConfigs());
    }

    /**
     * Kafka Template for sending messages
     */
    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    /**
     * 기본 Kafka Listener Container Factory
     * 단일 메시지 처리용
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        
        factory.setConsumerFactory(consumerFactory());
        factory.setConcurrency(concurrency);

        // 수동 즉시 커밋 모드로 변경 (MANUAL은 비동기 커밋이라 메시지가 남을 수 있음)
        // MANUAL_IMMEDIATE: acknowledge() 호출 시 즉시 동기 커밋 → 메시지 확실히 삭제
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);

        // 에러 핸들러 설정 (3회 재시도, 1초 간격)
        DefaultErrorHandler errorHandler = new DefaultErrorHandler(new FixedBackOff(1000L, 3));
        factory.setCommonErrorHandler(errorHandler);

        return factory;
    }

    /**
     * 배치 처리용 Kafka Listener Container Factory
     * 보안 이벤트 배치 처리용 (BlockingQueue 대체)
     *
     * AI Native 비동기 구조 최적화 (Phase 1):
     * - 기존 BlockingQueue(10개, 100ms) 배치 처리를 Kafka Batch Listener로 대체
     * - max-poll-records: 10 (기존 배치 크기 유지)
     * - fetch-min-bytes: 1 (즉시 처리 - 최소 1바이트)
     * - fetch-max-wait: 100ms (기존 타임아웃 유지)
     *
     * MANUAL_IMMEDIATE ACK 모드:
     * - acknowledge() 호출 시 즉시 동기 커밋
     * - 메시지 손실 방지 (배치 전체 처리 후 ACK)
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> batchKafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory =
            new ConcurrentKafkaListenerContainerFactory<>();

        // 배치 리스너 활성화
        factory.setBatchListener(true);
        factory.setConcurrency(concurrency);

        // 배치 처리 설정 - MANUAL_IMMEDIATE로 즉시 동기 커밋
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
        factory.getContainerProperties().setPollTimeout(3000);

        // 에러 핸들러 설정 (배치 처리 실패시 3회 재시도, 2초 간격)
        DefaultErrorHandler errorHandler = new DefaultErrorHandler(new FixedBackOff(2000L, 3));
        factory.setCommonErrorHandler(errorHandler);

        // 배치 처리 Consumer 설정 (BlockingQueue 대체)
        Map<String, Object> props = new HashMap<>(consumerConfigs());
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 10);       // 기존 배치 크기 유지
        props.put(ConsumerConfig.FETCH_MIN_BYTES_CONFIG, 1);         // 즉시 처리 (최소 1바이트)
        props.put(ConsumerConfig.FETCH_MAX_WAIT_MS_CONFIG, 100);     // 기존 타임아웃 유지 (100ms)

        ConsumerFactory<String, String> batchConsumerFactory =
            new DefaultKafkaConsumerFactory<>(props);
        factory.setConsumerFactory(batchConsumerFactory);

        return factory;
    }

    /**
     * JSON 메시지용 Kafka Listener Container Factory
     * JSON 형식의 보안 이벤트 처리용
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> jsonKafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        
        Map<String, Object> props = new HashMap<>(consumerConfigs());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        
        ConsumerFactory<String, Object> jsonConsumerFactory = 
            new DefaultKafkaConsumerFactory<>(props);
        
        factory.setConsumerFactory(jsonConsumerFactory);
        factory.setConcurrency(concurrency);

        // JSON 메시지도 MANUAL_IMMEDIATE로 즉시 동기 커밋
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);

        return factory;
    }
}