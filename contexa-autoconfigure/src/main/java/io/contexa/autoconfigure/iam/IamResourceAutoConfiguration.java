package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.ResourceEnhancementService;
import io.contexa.contexaiam.resource.WorkbenchInitializer;
import io.contexa.contexaiam.resource.scanner.MethodResourceScanner;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.resource.scanner.MvcResourceScanner;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.resource.service.ResourceRegistryServiceImpl;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.util.List;

@AutoConfiguration
public class IamResourceAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ResourceRegistryService resourceRegistryService(
            List<ResourceScanner> scanners,
            ManagedResourceRepository managedResourceRepository,
            PermissionCatalogService permissionCatalogService,
            AICoreOperations aiNativeProcessor,
            AutoConditionTemplateService autoConditionTemplateService,
            PolicyRepository policyRepository) {
        return new ResourceRegistryServiceImpl(
                scanners, managedResourceRepository, permissionCatalogService,
                aiNativeProcessor, autoConditionTemplateService, policyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionCompatibilityService conditionCompatibilityService() {
        return new ConditionCompatibilityService();
    }

    @Bean
    @ConditionalOnMissingBean
    public AutoConditionTemplateService autoConditionTemplateService(
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            AICoreOperations aiNativeProcessor) {
        return new AutoConditionTemplateService(
                conditionTemplateRepository, managedResourceRepository, aiNativeProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public MvcResourceScanner mvcResourceScanner(ApplicationContext applicationContext, IamAdminProperties iamAdminProperties) {
        return new MvcResourceScanner(applicationContext, iamAdminProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public MethodResourceScanner methodResourceScanner(
            ApplicationContext applicationContext,
            ObjectMapper objectMapper) {
        return new MethodResourceScanner(applicationContext, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceEnhancementService resourceEnhancementService(ResourceRegistryService resourceRegistryService) {
        return new ResourceEnhancementService(resourceRegistryService);
    }

    @Bean
    @ConditionalOnMissingBean
    public WorkbenchInitializer workbenchInitializer(
            ResourceRegistryService resourceRegistryService,
            PolicyRepository policyRepository,
            PolicyEnrichmentService policyEnrichmentService) {
        return new WorkbenchInitializer(resourceRegistryService, policyRepository, policyEnrichmentService);
    }
}
