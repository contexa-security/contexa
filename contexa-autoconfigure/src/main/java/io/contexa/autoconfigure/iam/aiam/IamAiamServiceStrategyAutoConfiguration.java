package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacoreenterprise.soar.controller.SoarSimulationController;
import io.contexa.contexacoreenterprise.soar.service.SoarSimulationService;
import io.contexa.contexacoreenterprise.soar.service.SoarToolCallingService;
import io.contexa.contexaiam.aiam.service.DataIngestionServiceImpl;
import io.contexa.contexaiam.aiam.strategy.ConditionTemplateDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.PolicyGenerationDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.ResourceNamingDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.StudioQueryDiagnosisStrategy;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.simp.SimpMessagingTemplate;


@AutoConfiguration
public class IamAiamServiceStrategyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DataIngestionServiceImpl dataIngestionService(
            VectorStore vectorStore,
            PolicyRepository policyRepository,
            ObjectMapper objectMapper) {
        return new DataIngestionServiceImpl(vectorStore, policyRepository, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateDiagnosisStrategy conditionTemplateDiagnosisStrategy(AILabFactory labFactory) {
        return new ConditionTemplateDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationDiagnosisStrategy policyGenerationDiagnosisStrategy(AILabFactory labFactory) {
        return new PolicyGenerationDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingDiagnosisStrategy resourceNamingDiagnosisStrategy(AILabFactory labFactory) {
        return new ResourceNamingDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryDiagnosisStrategy studioQueryDiagnosisStrategy(AILabFactory labFactory) {
        return new StudioQueryDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarSimulationController soarSimulationController(
            SoarSimulationService simulationService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new SoarSimulationController(simulationService,brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SoarToolCallingService.class)
    public SoarSimulationService soarSimulationService(
            @Autowired(required = false) SoarToolCallingService soarToolCallingService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new SoarSimulationService(soarToolCallingService, brokerTemplate);
    }
}
