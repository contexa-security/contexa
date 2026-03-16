package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexaiam.aiam.components.prompt.*;
import io.contexa.contexaiam.aiam.components.retriever.*;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
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
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class, PolicyGenerationVectorService.class})
    public PolicyGenerationContextRetriever policyGenerationContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            PolicyGenerationVectorService policyGenerationVectorService,
            ContexaRagProperties ragProperties) {
        return new PolicyGenerationContextRetriever(
                vectorStore, contextRetrieverRegistry, policyGenerationVectorService, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class})
    public ConditionTemplateContextRetriever conditionTemplateContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        return new ConditionTemplateContextRetriever(
                vectorStore, contextRetrieverRegistry, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class})
    public ResourceNamingContextRetriever resourceNamingContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ContexaRagProperties ragProperties) {
        return new ResourceNamingContextRetriever(
                vectorStore, contextRetrieverRegistry, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContextRetrieverRegistry.class, StudioQueryVectorService.class})
    public StudioQueryContextRetriever studioQueryContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            StudioQueryVectorService studioQueryVectorService,
            ContexaRagProperties ragProperties) {
        return new StudioQueryContextRetriever(
                vectorStore, contextRetrieverRegistry, studioQueryVectorService, ragProperties);
    }
}
