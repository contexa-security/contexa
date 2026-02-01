package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexaiam.aiam.components.prompt.*;
import io.contexa.contexaiam.aiam.components.retriever.*;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateVectorService;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingVectorService;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexacommon.repository.*;
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
    public UniversalConditionTemplate universalConditionTemplate() {
        return new UniversalConditionTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public SpecificConditionTemplate specificConditionTemplate() {
        return new SpecificConditionTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplatePromptTemplate conditionTemplatePromptTemplate(
            UniversalConditionTemplate universalTemplate,
            SpecificConditionTemplate specificTemplate) {
        return new ConditionTemplatePromptTemplate(universalTemplate, specificTemplate);
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
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            ConditionTemplateRepository conditionTemplateRepository,
            ContextRetrieverRegistry contextRetrieverRegistry,
            PolicyGenerationVectorService policyGenerationVectorService) {
        return new PolicyGenerationContextRetriever(
                vectorStore, roleRepository, permissionRepository,
                conditionTemplateRepository, contextRetrieverRegistry, policyGenerationVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateContextRetriever conditionTemplateContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ConditionTemplateVectorService conditionTemplateVectorService) {
        return new ConditionTemplateContextRetriever(
                vectorStore, contextRetrieverRegistry, conditionTemplateVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingContextRetriever resourceNamingContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            ResourceNamingVectorService resourceNamingVectorService) {
        return new ResourceNamingContextRetriever(
                vectorStore, contextRetrieverRegistry, resourceNamingVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryContextRetriever studioQueryContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            StudioQueryVectorService studioQueryVectorService) {
        return new StudioQueryContextRetriever(
                vectorStore, contextRetrieverRegistry, userRepository,
                groupRepository, roleRepository, permissionRepository, studioQueryVectorService);
    }
}
