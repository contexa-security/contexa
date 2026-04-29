package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.controller.*;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.auth.service.impl.*;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

@AutoConfiguration
public class IamAdminAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LoginController loginController() {
        return new LoginController();
    }

    @Bean
    @ConditionalOnMissingBean
    public UserController userController(
            UserRepository userRepository,
            ModelMapper modelMapper,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicyService,
            MessageSource messageSource,
            SystemSettingsService systemSettingsService) {
        return new UserController(userRepository, modelMapper, passwordEncoder, passwordPolicyService, messageSource, systemSettingsService);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserManagementController userManagementController(
            UserManagementService userManagementService,
            RoleService roleService,
            GroupService groupService,
            UserRepository userRepository,
            PasswordPolicyService passwordPolicyService,
            MessageSource messageSource) {
        return new UserManagementController(userManagementService, roleService, groupService, userRepository, passwordPolicyService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleController roleController(
            RoleService roleService,
            PermissionService permissionService,
            ModelMapper modelMapper,
            RoleRepository roleRepository,
            PolicyRepository policyRepository,
            MessageSource messageSource) {
        return new RoleController(roleService, permissionService, modelMapper, roleRepository, policyRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyController roleHierarchyController(
            RoleHierarchyService roleHierarchyService,
            RoleHierarchyRepository roleHierarchyRepository,
            ModelMapper modelMapper,
            RoleService roleService,
            GroupService groupService,
            MessageSource messageSource) {
        return new RoleHierarchyController(
                roleHierarchyService, roleHierarchyRepository, modelMapper, roleService, groupService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public GroupController groupController(
            GroupService groupService,
            RoleService roleService,
            ModelMapper modelMapper,
            GroupRepository groupRepository,
            MessageSource messageSource) {
        return new GroupController(groupService, roleService, modelMapper, groupRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionController permissionController(
            PermissionService permissionService,
            ModelMapper modelMapper,
            FunctionCatalogService functionCatalogService,
            PermissionRepository permissionRepository,
            PolicyRepository policyRepository,
            MessageSource messageSource) {
        return new PermissionController(permissionService, modelMapper, functionCatalogService, permissionRepository, policyRepository, messageSource);
    }

    @Bean("userManagementService")
    @ConditionalOnMissingBean
    public UserManagementService userManagementService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            ModelMapper modelMapper,
            CentralAuditFacade centralAuditFacade,
            PasswordPolicyService passwordPolicyService,
            SystemSettingsService systemSettingsService,
            org.springframework.context.MessageSource messageSource) {
        return new UserManagementServiceImpl(
                userRepository, groupRepository, roleRepository, passwordEncoder, modelMapper,
                centralAuditFacade, passwordPolicyService, systemSettingsService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleService roleService(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            IntegrationEventBus eventBus,
            CentralAuditFacade centralAuditFacade,
            RoleHierarchyRepository roleHierarchyRepository,
            PolicySynchronizationService policySynchronizationService,
            org.springframework.context.MessageSource messageSource) {
        return new RoleServiceImpl(roleRepository, permissionRepository, eventBus, centralAuditFacade, roleHierarchyRepository, policySynchronizationService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public GroupService groupService(
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            RoleHierarchyRepository roleHierarchyRepository,
            org.springframework.context.MessageSource messageSource) {
        return new GroupServiceImpl(groupRepository, roleRepository, roleHierarchyRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionService permissionService(
            PermissionRepository permissionRepository,
            ManagedResourceRepository managedResourceRepository,
            org.springframework.context.MessageSource messageSource) {
        return new PermissionServiceImpl(
                permissionRepository, managedResourceRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyService roleHierarchyService(
            RoleHierarchyRepository roleHierarchyRepository,
            RoleRepository roleRepository,
            RoleHierarchyImpl roleHierarchy,
            org.springframework.context.MessageSource messageSource) {
        return new RoleHierarchyService(
                roleHierarchyRepository, roleRepository, roleHierarchy, messageSource);
    }
}

