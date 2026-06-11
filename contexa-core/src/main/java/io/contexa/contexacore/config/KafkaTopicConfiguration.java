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

import org.apache.kafka.common.config.TopicConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.kafka.core.KafkaTemplate;

@Configuration
@ConditionalOnClass(name = "org.springframework.kafka.core.KafkaTemplate")
public class KafkaTopicConfiguration {

    @Bean
    public KafkaAdmin.NewTopics allSecurityTopics() {
        return new KafkaAdmin.NewTopics(
            
            authEventsCriticalTopic().build(),
            authEventsContextualTopic().build(),
            authEventsGeneralTopic().build(),

            securityAuthorizationEventsTopic().build(),
            securityIncidentEventsTopic().build(),
            securityAuditEventsTopic().build(),

            securityEventsTopic().build(),
            threatIndicatorsTopic().build(),
            networkEventsTopic().build(),

            deadLetterQueueTopic().build(),

            soarActionEventsTopic().build()
        );
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

    private TopicBuilder deadLetterQueueTopic() {
        return TopicBuilder.name("security-events-dlq")
            .partitions(1)  
            .replicas(1)
            .config(TopicConfig.RETENTION_MS_CONFIG, "2592000000");  
    }
}
