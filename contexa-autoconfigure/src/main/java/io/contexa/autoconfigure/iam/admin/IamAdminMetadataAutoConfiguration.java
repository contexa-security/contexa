package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.controller.FunctionCatalogApiController;
import io.contexa.contexaiam.admin.web.metadata.controller.FunctionCatalogController;
import io.contexa.contexaiam.admin.web.metadata.controller.ResourceAdminController;
import io.contexa.contexaiam.admin.web.metadata.controller.WorkbenchMetadataController;
import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataService;
import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataServiceImpl;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogServiceImpl;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import io.contexa.contexaiam.repository.BusinessActionRepository;
import io.contexa.contexaiam.repository.BusinessResourceRepository;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.FunctionGroupRepository;
import io.contexa.contexaiam.resource.ResourceEnhancementService;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;

@AutoConfiguration
public class IamAdminMetadataAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public FunctionCatalogController functionCatalogController(
            @Lazy ResourceRegistryService resourceRegistryService,
            ResourceEnhancementService resourceEnhancementService,
            FunctionCatalogService functionCatalogService) {
        return new FunctionCatalogController(
                resourceRegistryService, resourceEnhancementService, functionCatalogService);
    }

    @Bean
    @ConditionalOnMissingBean
    public FunctionCatalogApiController functionCatalogApiController(
            FunctionCatalogService functionCatalogService) {
        return new FunctionCatalogApiController(functionCatalogService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceAdminController resourceAdminController(
            ResourceRegistryService resourceRegistryService) {
        return new ResourceAdminController(resourceRegistryService);
    }

    @Bean
    @ConditionalOnMissingBean
    public WorkbenchMetadataController workbenchMetadataController(
            BusinessMetadataService businessMetadataService,
            ModelMapper modelMapper,
            PermissionCatalogService permissionCatalogService) {
        return new WorkbenchMetadataController(
                businessMetadataService, modelMapper, permissionCatalogService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public FunctionCatalogService functionCatalogService(
            FunctionCatalogRepository functionCatalogRepository,
            FunctionGroupRepository functionGroupRepository,
            ModelMapper modelMapper) {
        return new FunctionCatalogService(
                functionCatalogRepository, functionGroupRepository, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionCatalogService permissionCatalogService(
            PermissionRepository permissionRepository,
            ModelMapper modelMapper,
            PolicyService policyService) {
        return new PermissionCatalogServiceImpl(permissionRepository, modelMapper, policyService);
    }

    @Bean
    @ConditionalOnMissingBean
    public BusinessMetadataService businessMetadataService(
            BusinessResourceRepository businessResourceRepository,
            BusinessActionRepository businessActionRepository,
            ConditionTemplateRepository conditionTemplateRepository,
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleService roleService,
            ModelMapper modelMapper) {
        return new BusinessMetadataServiceImpl(
                businessResourceRepository, businessActionRepository, conditionTemplateRepository,
                userRepository, groupRepository, roleService, modelMapper);
    }
}
