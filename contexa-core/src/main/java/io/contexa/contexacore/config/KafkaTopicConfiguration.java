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
package io.contexa.contexacore.config;

import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.infra.kafka.ContexaKafkaTopics;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.config.TopicConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.kafka.KafkaConnectionDetails;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Configuration
@ConditionalOnClass(name = "org.springframework.kafka.core.KafkaTemplate")
public class KafkaTopicConfiguration {

    @Bean(name = "contexaKafkaTopics", defaultCandidate = false)
    public ContexaKafkaTopics contexaKafkaTopics(KafkaProperties kafkaProperties, ObjectProvider<SslBundles> sslBundles,
                                                 ObjectProvider<SecurityKafkaProperties> securityKafkaProperties,
                                                 ObjectProvider<KafkaConnectionDetails> connectionDetails) {
        SecurityKafkaProperties.TopicSettings names =
                securityKafkaProperties.getIfAvailable(SecurityKafkaProperties::new).getTopic();
        return new ContexaKafkaTopics(() -> Admin.create(adminConfig(kafkaProperties, sslBundles, connectionDetails)),
                topicsToMake(names), kafkaProperties.getAdmin().isAutoCreate());
    }

    /** The application's admin settings, with waits that a start can afford. */
    private Map<String, Object> adminConfig(KafkaProperties kafkaProperties, ObjectProvider<SslBundles> sslBundles,
                                            ObjectProvider<KafkaConnectionDetails> connectionDetails) {
        Map<String, Object> config = kafkaProperties.buildAdminProperties(sslBundles.getIfAvailable());
        KafkaConnectionDetails details = connectionDetails.getIfAvailable();
        KafkaConfiguration.applyConnection(config, details != null ? details.getAdmin() : null);
        int limit = (int) ContexaKafkaTopics.ANSWER_LIMIT.toMillis();
        config.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, limit);
        config.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, limit);
        return config;
    }

    /**
     * The topics something writes to or reads, by the name each is used under: the topic of every declared event, which the
     * publisher writes and the collector reads, and the dead letters, by the name set in
     * {@code contexa.security.kafka.topic.dlq} as it is set, and otherwise the default in the application's namespace. No
     * other topic is made: nothing writes to one, nothing reads one, and one made would stay on a cluster that other
     * applications share.
     */
    List<NewTopic> topicsToMake(SecurityKafkaProperties.TopicSettings names) {
        List<NewTopic> topics = new ArrayList<>();
        SecurityEventTopics.declared().forEach(topic -> topics.add(eventTopic(topic).build()));
        topics.add(deadLetterQueueTopic(names.getDlq()).build());
        return topics;
    }

    /** The replicas are the broker's: one replica would fail every send under a broker's min.insync.replicas of two. */
    private TopicBuilder eventTopic(String name) {
        return TopicBuilder.name(name)
            .partitions(3)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");
    }

    private TopicBuilder deadLetterQueueTopic(String name) {
        return TopicBuilder.name(name)
            .partitions(1)  
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "2592000000");  
    }
}
