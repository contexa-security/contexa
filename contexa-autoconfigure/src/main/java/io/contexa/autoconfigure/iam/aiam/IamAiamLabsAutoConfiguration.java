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
package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.store.ContexaWorkCallerRunsPolicy;
import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateGenerationLab;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.data.PolicyGenerationCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import java.util.concurrent.Executor;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.MessageSource;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;


@AutoConfiguration
@AutoConfigureAfter(name = "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration")
public class IamAiamLabsAutoConfiguration {

    @Bean(name = "contexaPolicyGenerationVectorService")
    @ConditionalOnMissingBean
    @ConditionalOnBean(value = {ContexaRagProperties.class}, name = "contexaVectorStore")
    public PolicyGenerationVectorService policyGenerationVectorService(
            @Qualifier("contexaVectorStore") VectorStore vectorStore,
            @Autowired(required = false) VectorStoreMetrics contexaVectorStoreMetrics,
            ContexaRagProperties ragProperties,
            MessageSource messageSource) {
        return new PolicyGenerationVectorService(vectorStore, contexaVectorStoreMetrics, ragProperties, messageSource);
    }

    @Bean(name = "contexaPolicyGenerationCollectionExecutor", defaultCandidate = false)
    @ConditionalOnMissingBean(name = "contexaPolicyGenerationCollectionExecutor")
    public Executor policyGenerationCollectionExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(6);
        executor.setQueueCapacity(300);
        executor.setThreadNamePrefix("contexa-policy-collection-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }

    @Bean(name = "contexaPolicyGenerationCollectionService")
    @ConditionalOnMissingBean
    public PolicyGenerationCollectionService policyGenerationCollectionService(
            RoleService contexaRoleService,
            PermissionCatalogService contexaPermissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyRepository policyRepository,
            RoleHierarchyService contexaRoleHierarchyService,
            @Qualifier("contexaPolicyGenerationCollectionExecutor") Executor contexaPolicyGenerationCollectionExecutor) {
        return new PolicyGenerationCollectionService(
                contexaRoleService, contexaPermissionCatalogService, conditionTemplateRepository,
                policyRepository, contexaRoleHierarchyService, contexaPolicyGenerationCollectionExecutor);
    }

    @Bean(name = "contexaIamDataCollectionService")
    @ConditionalOnMissingBean
    public IAMDataCollectionService iamDataCollectionService(
            PolicyGenerationCollectionService contexaPolicyGenerationCollectionService) {
        return new IAMDataCollectionService(contexaPolicyGenerationCollectionService);
    }

    @Bean(name = "contexaAdvancedPolicyGenerationLab")
    @ConditionalOnMissingBean
    @ConditionalOnBean(PolicyGenerationVectorService.class)
    public AdvancedPolicyGenerationLab advancedPolicyGenerationLab(
            PipelineOrchestrator orchestrator,
            IAMDataCollectionService dataCollectionService,
            PolicyGenerationVectorService vectorService) {
        return new AdvancedPolicyGenerationLab(orchestrator, dataCollectionService, vectorService);
    }

    @Bean(name = "contexaResourceNamingLab")
    @ConditionalOnMissingBean
    public ResourceNamingLab resourceNamingLab(
            PipelineOrchestrator orchestrator) {
        return new ResourceNamingLab(orchestrator);
    }

    @Bean(name = "contexaConditionTemplateGenerationLab")
    @ConditionalOnMissingBean
    public ConditionTemplateGenerationLab conditionTemplateGenerationLab(
            PipelineOrchestrator orchestrator) {
        return new ConditionTemplateGenerationLab(orchestrator);
    }
}

