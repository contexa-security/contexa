package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexaiam.aiam.components.prompt.*;
import io.contexa.contexaiam.aiam.components.retriever.*;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateVectorService;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAiamComponentsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationTemplate policyGenerationTemplate() {
        return new PolicyGenerationTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationStreamingTemplate policyGenerationStreamingTemplate() {
        return new PolicyGenerationStreamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryTemplate studioQueryTemplate() {
        return new StudioQueryTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingTemplate resourceNamingTemplate() {
        return new ResourceNamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplatePromptTemplate conditionTemplatePromptTemplate() {
        return new ConditionTemplatePromptTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryStreamingTemplate studioQueryStreamingTemplate() {
        return new StudioQueryStreamingTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationContextRetriever policyGenerationContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            PolicyGenerationVectorService policyGenerationVectorService) {
        return new PolicyGenerationContextRetriever(
                vectorStore, contextRetrieverRegistry, policyGenerationVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateContextRetriever conditionTemplateContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry) {
        return new ConditionTemplateContextRetriever(
                vectorStore, contextRetrieverRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingContextRetriever resourceNamingContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry) {
        return new ResourceNamingContextRetriever(
                vectorStore, contextRetrieverRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryContextRetriever studioQueryContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            StudioQueryVectorService studioQueryVectorService) {
        return new StudioQueryContextRetriever(
                vectorStore, contextRetrieverRegistry, studioQueryVectorService);
    }
}
