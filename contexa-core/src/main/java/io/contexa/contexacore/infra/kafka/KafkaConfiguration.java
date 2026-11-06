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
package io.contexa.contexacore.infra.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.listener.DecidedRecordAcknowledger;
import io.contexa.contexacore.autonomous.service.DeletedAccountWriteFence;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import lombok.RequiredArgsConstructor;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.kafka.KafkaConnectionDetails;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.autoconfigure.kafka.SslBundleSslEngineFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.*;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.support.serializer.JsonSerializer;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;
import org.springframework.util.backoff.FixedBackOff;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;

@Configuration
@ConditionalOnClass(name = "org.springframework.kafka.core.KafkaTemplate")
@EnableConfigurationProperties(KafkaProperties.class)
@ConditionalOnProperty(prefix = "contexa.infrastructure", name = "mode", havingValue = "distributed")
@RequiredArgsConstructor
public class KafkaConfiguration {

    private final KafkaProperties kafkaProperties;
    private final ObjectProvider<SslBundles> sslBundles;
    private final ObjectProvider<KafkaConnectionDetails> connectionDetails;
    private final ObjectProvider<SecurityPlaneProperties> securityPlaneProperties;

    /**
     * How often the consumer looks for topics its pattern matches. Kafka's default is five minutes, so a topic that
     * appeared after the consumer joined stayed unread that long (PR-73).
     */
    private static final int TOPIC_DISCOVERY_INTERVAL_MS = 30_000;
    private static final String CONTEXA_CLIENT_ID_SUFFIX = "-contexa";

    /**
     * The consumer starts from what Spring Boot makes of the application's settings, so everything that says how to reach
     * and enter the cluster is the application's ({@code spring.kafka.security.*}, {@code ssl.*}, {@code properties.*}, the
     * consumer's own of these), and so are its group and how it reads. What Contexa's reading depends on is set here over
     * them: it reads strings and acknowledges a record itself, once the analysis is done with it.
     */
    @Bean(name = "contexaConsumerConfigs", defaultCandidate = false)
    public Map<String, Object> consumerConfigs() {
        Map<String, Object> props = new HashMap<>(kafkaProperties.buildConsumerProperties(sslBundles.getIfAvailable()));
        KafkaConnectionDetails details = connectionDetails.getIfAvailable();
        applyConnection(props, details != null ? details.getConsumer() : null);
        props.putIfAbsent(ConsumerConfig.GROUP_ID_CONFIG, ApplicationNamespace.consumerGroup("security-plane-consumer"));
        props.putIfAbsent(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.putIfAbsent(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 500);
        keepClientIdApart(props);

        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        props.put(ConsumerConfig.METADATA_MAX_AGE_CONFIG, TOPIC_DISCOVERY_INTERVAL_MS);

        props.put(JsonDeserializer.TRUSTED_PACKAGES, "io.contexa.contexacore.*");
        props.put(JsonDeserializer.VALUE_DEFAULT_TYPE, "io.contexa.contexacore.plane.domain.SecurityEvent");

        return props;
    }

    /**
     * The producer starts from what Spring Boot makes of the application's settings, as the consumer does. A security
     * event is sent whole, acknowledged by the cluster and never held up, whatever the application decided for its own
     * records, so its format, delivery and waits are set here over them; it takes no part in a transaction.
     */
    @Bean(name = "contexaProducerConfigs", defaultCandidate = false)
    public Map<String, Object> producerConfigs() {
        Map<String, Object> props = new HashMap<>(kafkaProperties.buildProducerProperties(sslBundles.getIfAvailable()));
        KafkaConnectionDetails details = connectionDetails.getIfAvailable();
        applyConnection(props, details != null ? details.getProducer() : null);
        keepClientIdApart(props);
        props.remove(ProducerConfig.TRANSACTIONAL_ID_CONFIG);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 16384);
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10);
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);
        // A send is given a few seconds to find the cluster and to be delivered, then it fails (the publisher counts the failure and sends the
        // event to the dead-letter path). The wait is on the publisher's own thread, never a request's; the default, a minute, would hold every
        // event behind it.
        props.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 3000);
        props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5000);
        props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10000);

        return props;
    }

    /**
     * What Spring Boot's connection details add to the settings: an SSL bundle is resolved only there, and a service
     * connection names its cluster only there. Spring Boot's own clients are made the same way.
     */
    public static void applyConnection(Map<String, Object> props, @Nullable KafkaConnectionDetails.Configuration client) {
        if (client == null) {
            return;
        }
        props.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, client.getBootstrapServers());
        if (StringUtils.hasText(client.getSecurityProtocol())) {
            props.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, client.getSecurityProtocol());
        }
        SslBundle bundle = client.getSslBundle();
        if (bundle != null) {
            props.put(SslConfigs.SSL_ENGINE_FACTORY_CLASS_CONFIG, SslBundleSslEngineFactory.class);
            props.put(SslBundle.class.getName(), bundle);
        }
    }

    /** A client id the application gave its own clients would collide with them on the broker and in JMX. */
    private static void keepClientIdApart(Map<String, Object> props) {
        Object clientId = props.get(CommonClientConfigs.CLIENT_ID_CONFIG);
        if (clientId != null) {
            props.put(CommonClientConfigs.CLIENT_ID_CONFIG, clientId + CONTEXA_CLIENT_ID_SUFFIX);
        }
    }

    @Bean(name = "contexaConsumerFactory", defaultCandidate = false)
    public ConsumerFactory<String, String> consumerFactory() {
        return new DefaultKafkaConsumerFactory<>(consumerConfigs());
    }

    @Bean(name = "contexaProducerFactory", defaultCandidate = false)
    public ProducerFactory<String, Object> producerFactory(@Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        Map<String, Object> props = new HashMap<>(producerConfigs());
        JsonSerializer<Object> serializer = new JsonSerializer<>(objectMapper);
        serializer.setAddTypeInfo(false);
        return new DefaultKafkaProducerFactory<>(props, new StringSerializer(), serializer);
    }

    @Bean(name = "contexaKafkaTemplate", defaultCandidate = false)
    public KafkaTemplate<String, Object> kafkaTemplate(@Qualifier("contexaProducerFactory") ProducerFactory<String, Object> contexaProducerFactory) {
        return new KafkaTemplate<>(contexaProducerFactory);
    }

    /** A record holds the commit of its partition for as long as the analysis of one request may take. */
    @Bean(name = "contexaDecidedRecordAcknowledger", defaultCandidate = false)
    public DecidedRecordAcknowledger decidedRecordAcknowledger() {
        SecurityPlaneProperties.AgentSettings agent = securityPlaneProperties.getIfAvailable(SecurityPlaneProperties::new).getAgent();
        return new DecidedRecordAcknowledger(DeletedAccountWriteFence.retention(agent.getEventTimeoutMs(),
                agent.getMaxDeferredRetries(), agent.getDeletedAccountFenceMarginMs()));
    }

    @Bean(name = "contexaKafkaListenerContainerFactory", defaultCandidate = false)
    public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        
        factory.setConsumerFactory(consumerFactory());
        Integer concurrency = kafkaProperties.getListener().getConcurrency() != null ? kafkaProperties.getListener().getConcurrency() : 1;
        factory.setConcurrency(concurrency);

        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
        factory.getContainerProperties().setConsumerRebalanceListener(decidedRecordAcknowledger());

        DefaultErrorHandler errorHandler = new DefaultErrorHandler(new FixedBackOff(1000L, 3));
        factory.setCommonErrorHandler(errorHandler);

        return factory;
    }

    @Bean(name = "contexaJsonKafkaListenerContainerFactory", defaultCandidate = false)
    public ConcurrentKafkaListenerContainerFactory<String, Object> jsonKafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        
        Map<String, Object> props = new HashMap<>(consumerConfigs());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        
        ConsumerFactory<String, Object> jsonConsumerFactory = 
            new DefaultKafkaConsumerFactory<>(props);
        
        factory.setConsumerFactory(jsonConsumerFactory);
        Integer concurrency = kafkaProperties.getListener().getConcurrency() != null ? kafkaProperties.getListener().getConcurrency() : 1;
        factory.setConcurrency(concurrency);

        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);

        return factory;
    }
}
