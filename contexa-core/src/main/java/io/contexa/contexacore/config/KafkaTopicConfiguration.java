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
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.config.TopicConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Configuration
@ConditionalOnClass(name = "org.springframework.kafka.core.KafkaTemplate")
public class KafkaTopicConfiguration {

    @Bean(name = "contexaKafkaTopics", defaultCandidate = false)
    public ContexaKafkaTopics contexaKafkaTopics(KafkaProperties kafkaProperties, ObjectProvider<SslBundles> sslBundles,
                                                 ObjectProvider<SecurityKafkaProperties> securityKafkaProperties) {
        String deadLetterTopic = securityKafkaProperties.getIfAvailable(SecurityKafkaProperties::new).getTopic().getDlq();
        Set<String> needed = new HashSet<>(SecurityEventTopics.DECLARED);
        needed.add(deadLetterTopic);
        return new ContexaKafkaTopics(() -> Admin.create(adminConfig(kafkaProperties, sslBundles)),
                allSecurityTopics(deadLetterTopic), needed, kafkaProperties.getAdmin().isAutoCreate());
    }

    /** The application's admin settings, with waits that a start can afford. */
    private Map<String, Object> adminConfig(KafkaProperties kafkaProperties, ObjectProvider<SslBundles> sslBundles) {
        Map<String, Object> config = kafkaProperties.buildAdminProperties(sslBundles.getIfAvailable());
        int limit = (int) ContexaKafkaTopics.ANSWER_LIMIT.toMillis();
        config.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, limit);
        config.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, limit);
        return config;
    }

    private List<NewTopic> allSecurityTopics(String deadLetterTopic) {
        List<NewTopic> topics = new ArrayList<>(List.of(
            authEventsCriticalTopic().build(),
            authEventsContextualTopic().build(),
            authEventsGeneralTopic().build(),

            securityAuthorizationEventsTopic().build(),
            securityIncidentEventsTopic().build(),
            securityAuditEventsTopic().build(),

            securityEventsTopic().build(),
            threatIndicatorsTopic().build(),
            networkEventsTopic().build(),

            deadLetterQueueTopic(deadLetterTopic).build(),

            soarActionEventsTopic().build()
        ));
        SecurityEventTopics.DECLARED.forEach(topic -> topics.add(eventTopic(topic).build()));
        return topics;
    }

    /** The replicas are the broker's: one replica would fail every send under a broker's min.insync.replicas of two. */
    private TopicBuilder eventTopic(String name) {
        return TopicBuilder.name(name)
            .partitions(3)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");
    }

    private TopicBuilder authEventsCriticalTopic() {
        return TopicBuilder.name("auth-events-critical")
            .partitions(3)  
            .replicas(1)    
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000")  
            .config(TopicConfig.MIN_IN_SYNC_REPLICAS_CONFIG, "1")  
            .compact();  
    }

    private TopicBuilder authEventsContextualTopic() {
        return TopicBuilder.name("auth-events-contextual")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");  
    }

    private TopicBuilder authEventsGeneralTopic() {
        return TopicBuilder.name("auth-events-general")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "259200000");  
    }

    private TopicBuilder securityAuthorizationEventsTopic() {
        return TopicBuilder.name("security-authorization-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");  
    }

    private TopicBuilder securityIncidentEventsTopic() {
        return TopicBuilder.name("security-incident-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "2592000000");  
    }

    private TopicBuilder securityAuditEventsTopic() {
        return TopicBuilder.name("security-audit-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "7776000000");  
    }

    private TopicBuilder securityEventsTopic() {
        return TopicBuilder.name("security-events")
            .partitions(5)  
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");  
    }

    private TopicBuilder threatIndicatorsTopic() {
        return TopicBuilder.name("threat-indicators")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "1209600000");  
    }

    private TopicBuilder networkEventsTopic() {
        return TopicBuilder.name("network-events")
            .partitions(5)  
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "259200000");  
    }

    private TopicBuilder soarActionEventsTopic() {
        return TopicBuilder.name("soar-action-events")
            .partitions(3)
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000");
    }

    private TopicBuilder deadLetterQueueTopic(String name) {
        return TopicBuilder.name(name)
            .partitions(1)  
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "2592000000");  
    }
}
