package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexaiam.aiam.service.DataIngestionServiceImpl;
import io.contexa.contexaiam.aiam.strategy.ConditionTemplateDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.PolicyGenerationDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.ResourceNamingDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.StudioQueryDiagnosisStrategy;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
public class IamAiamServiceStrategyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(VectorStore.class)
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
}
