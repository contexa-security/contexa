package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateGenerationLab;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateVectorService;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.data.PolicyGenerationCollectionService;
import io.contexa.contexaiam.aiam.labs.data.StudioQueryCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryLab;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import io.contexa.contexaiam.aiam.labs.studio.service.QueryIntentAnalyzer;
import io.contexa.contexaiam.aiam.labs.studio.service.StudioQueryFormatter;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
public class IamAiamLabsAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationVectorService policyGenerationVectorService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new PolicyGenerationVectorService(vectorStore, vectorStoreMetrics);
    }

       @Bean
    @ConditionalOnMissingBean
    public StudioQueryVectorService studioQueryVectorService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new StudioQueryVectorService(vectorStore, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateVectorService conditionTemplateVectorService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new ConditionTemplateVectorService(vectorStore, vectorStoreMetrics);
    }


    @Bean
    @ConditionalOnMissingBean
    public StudioQueryCollectionService studioQueryCollectionService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository) {
        return new StudioQueryCollectionService(
                userRepository, groupRepository, roleRepository, permissionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationCollectionService policyGenerationCollectionService(
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository) {
        return new PolicyGenerationCollectionService(
                roleService, permissionCatalogService, conditionTemplateRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public IAMDataCollectionService iamDataCollectionService(
            StudioQueryCollectionService studioQueryCollectionService,
            PolicyGenerationCollectionService policyGenerationCollectionService) {
        return new IAMDataCollectionService(
                studioQueryCollectionService, policyGenerationCollectionService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public QueryIntentAnalyzer queryIntentAnalyzer() {
        return new QueryIntentAnalyzer();
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryFormatter studioQueryFormatter() {
        return new StudioQueryFormatter();
    }

    @Bean
    @ConditionalOnMissingBean
    public AdvancedPolicyGenerationLab advancedPolicyGenerationLab(
            PipelineOrchestrator orchestrator,
            IAMDataCollectionService dataCollectionService,
            PolicyGenerationVectorService vectorService) {
        return new AdvancedPolicyGenerationLab(orchestrator, dataCollectionService, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryLab studioQueryLab(
            PipelineOrchestrator orchestrator,
            QueryIntentAnalyzer queryIntentAnalyzer,
            IAMDataCollectionService dataCollectionService,
            StudioQueryFormatter queryFormatter,
            StudioQueryVectorService vectorService) {
        return new StudioQueryLab(orchestrator, queryIntentAnalyzer,
                dataCollectionService, queryFormatter, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingLab resourceNamingLab(
            PipelineOrchestrator orchestrator) {
        return new ResourceNamingLab(orchestrator);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateGenerationLab conditionTemplateGenerationLab(
            PipelineOrchestrator orchestrator,
            ConditionTemplateVectorService vectorService) {
        return new ConditionTemplateGenerationLab(orchestrator, vectorService);
    }
}
