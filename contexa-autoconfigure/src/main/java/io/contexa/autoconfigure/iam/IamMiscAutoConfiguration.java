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
package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.support.context.service.UserContextServiceImpl;
import io.contexa.contexaiam.common.event.service.InMemoryEventBus;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.WizardSessionRepository;
import io.contexa.contexaiam.service.PolicyService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.properties.IamAdminProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(IamAdminProperties.class)
public class IamMiscAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public IntegrationEventBus integrationEventBus(ApplicationEventPublisher applicationEventPublisher) {
        return new InMemoryEventBus(applicationEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyService policyService(
            PolicyRepository policyRepository) {
        return new PolicyService(policyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserContextService userContextService(
            AuditLogRepository auditLogRepository) {
        return new UserContextServiceImpl(auditLogRepository);
    }
}

