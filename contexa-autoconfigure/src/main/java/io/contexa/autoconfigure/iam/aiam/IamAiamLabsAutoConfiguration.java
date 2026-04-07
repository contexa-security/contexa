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
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.data.PolicyGenerationCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
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
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
            io.contexa.contexacore.properties.ContexaRagProperties ragProperties) {
        return new PolicyGenerationVectorService(vectorStore, vectorStoreMetrics, ragProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationCollectionService policyGenerationCollectionService(
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyRepository policyRepository,
            RoleHierarchyService roleHierarchyService) {
        return new PolicyGenerationCollectionService(
                roleService, permissionCatalogService, conditionTemplateRepository,
                policyRepository, roleHierarchyService);
    }

    @Bean
    @ConditionalOnMissingBean
    public IAMDataCollectionService iamDataCollectionService(
            PolicyGenerationCollectionService policyGenerationCollectionService) {
        return new IAMDataCollectionService(policyGenerationCollectionService);
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
    public ResourceNamingLab resourceNamingLab(
            PipelineOrchestrator orchestrator) {
        return new ResourceNamingLab(orchestrator);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateGenerationLab conditionTemplateGenerationLab(
            PipelineOrchestrator orchestrator) {
        return new ConditionTemplateGenerationLab(orchestrator);
    }
}
