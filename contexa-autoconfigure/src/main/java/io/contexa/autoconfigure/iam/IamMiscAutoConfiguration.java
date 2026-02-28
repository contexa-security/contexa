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
            AuditLogRepository auditLogRepository,
            WizardSessionRepository wizardSessionRepository,
            ObjectMapper objectMapper) {
        return new UserContextServiceImpl(auditLogRepository, wizardSessionRepository, objectMapper);
    }
}
