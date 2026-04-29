package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.properties.ContexaRagProperties;
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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;


@AutoConfiguration
@AutoConfigureAfter(name = "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration")
public class IamAiamLabsAutoConfiguration {


    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({VectorStore.class, ContexaRagProperties.class})
    public PolicyGenerationVectorService policyGenerationVectorService(
            VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
            ContexaRagProperties ragProperties,
            org.springframework.context.MessageSource messageSource) {
        return new PolicyGenerationVectorService(vectorStore, vectorStoreMetrics, ragProperties, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean(name = "policyGenerationCollectionExecutor")
    public Executor policyGenerationCollectionExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(6);
        executor.setQueueCapacity(300);
        executor.setThreadNamePrefix("Policy-Collection-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationCollectionService policyGenerationCollectionService(
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyRepository policyRepository,
            RoleHierarchyService roleHierarchyService,
            @Qualifier("policyGenerationCollectionExecutor") Executor policyGenerationCollectionExecutor) {
        return new PolicyGenerationCollectionService(
                roleService, permissionCatalogService, conditionTemplateRepository,
                policyRepository, roleHierarchyService, policyGenerationCollectionExecutor);
    }

    @Bean
    @ConditionalOnMissingBean
    public IAMDataCollectionService iamDataCollectionService(
            PolicyGenerationCollectionService policyGenerationCollectionService) {
        return new IAMDataCollectionService(policyGenerationCollectionService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PolicyGenerationVectorService.class)
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

