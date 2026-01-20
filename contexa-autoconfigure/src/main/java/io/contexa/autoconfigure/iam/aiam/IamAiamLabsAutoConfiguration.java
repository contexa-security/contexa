package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.contexa.contexacore.scheduler.ParallelExecutionMonitor;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.components.retriever.AccessGovernanceContextRetriever;
import io.contexa.contexaiam.aiam.components.retriever.ConditionTemplateContextRetriever;
import io.contexa.contexaiam.aiam.labs.accessGovernance.AccessGovernanceLab;
import io.contexa.contexaiam.aiam.labs.accessGovernance.AccessVectorService;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateGenerationLab;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateVectorService;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.data.PolicyGenerationCollectionService;
import io.contexa.contexaiam.aiam.labs.data.StudioQueryCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingVectorService;
import io.contexa.contexaiam.aiam.labs.securityCopilot.SecurityCopilotLab;
import io.contexa.contexaiam.aiam.labs.securityCopilot.SecurityCopilotVectorService;
import io.contexa.contexaiam.aiam.labs.securityCopilot.streaming.LabStreamMerger;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryLab;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import io.contexa.contexaiam.aiam.labs.studio.service.QueryIntentAnalyzer;
import io.contexa.contexaiam.aiam.labs.studio.service.StudioQueryFormatter;
import io.contexa.contexaiam.aiam.labs.synthesis.DynamicThreatResponseSynthesisLab;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.trace.Tracer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
public class IamAiamLabsAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationVectorService policyGenerationVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new PolicyGenerationVectorService(standardVectorStoreService, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessVectorService accessVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new AccessVectorService(standardVectorStoreService, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryVectorService studioQueryVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new StudioQueryVectorService(standardVectorStoreService, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingVectorService resourceNamingVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new ResourceNamingVectorService(standardVectorStoreService, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateVectorService conditionTemplateVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new ConditionTemplateVectorService(standardVectorStoreService, vectorStoreMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotVectorService securityCopilotVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new SecurityCopilotVectorService(standardVectorStoreService, vectorStoreMetrics);
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
    public LabStreamMerger labStreamMerger() {
        return new LabStreamMerger();
    }

    
    @Bean
    @ConditionalOnMissingBean
    public AdvancedPolicyGenerationLab advancedPolicyGenerationLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            IAMDataCollectionService dataCollectionService,
            PolicyGenerationVectorService vectorService) {
        return new AdvancedPolicyGenerationLab(
                tracer, orchestrator, dataCollectionService, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessGovernanceLab accessGovernanceLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            AccessGovernanceContextRetriever contextRetriever,
            AccessVectorService accessVectorService,
            ApplicationEventPublisher eventPublisher) {
        return new AccessGovernanceLab(
                tracer, orchestrator, contextRetriever, accessVectorService, eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryLab studioQueryLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            QueryIntentAnalyzer queryIntentAnalyzer,
            IAMDataCollectionService dataCollectionService,
            StudioQueryFormatter queryFormatter,
            StudioQueryVectorService vectorService) {
        return new StudioQueryLab(
                tracer, orchestrator, queryIntentAnalyzer,
                dataCollectionService, queryFormatter, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingLab resourceNamingLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            ResourceNamingVectorService vectorService) {
        return new ResourceNamingLab(tracer, orchestrator, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateGenerationLab conditionTemplateGenerationLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            ConditionTemplateContextRetriever contextRetriever,
            ObjectMapper objectMapper,
            ConditionTemplateVectorService vectorService) {
        return new ConditionTemplateGenerationLab(
                tracer, orchestrator, contextRetriever, objectMapper, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotLab securityCopilotLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            AILabFactory labFactory,
            ObjectMapper objectMapper,
            ParallelExecutionMonitor monitor,
            SecurityCopilotVectorService vectorService) {
        return new SecurityCopilotLab(
                tracer, orchestrator, labFactory, objectMapper, monitor, vectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    public DynamicThreatResponseSynthesisLab dynamicThreatResponseSynthesisLab(
            Tracer tracer,
            PipelineOrchestrator orchestrator,
            AdvancedPolicyGenerationLab policyGenerationLab,
            IAMDataCollectionService dataCollectionService,
            MeterRegistry meterRegistry) {
        return new DynamicThreatResponseSynthesisLab(
                tracer, orchestrator, policyGenerationLab, dataCollectionService, meterRegistry);
    }
}
