package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.controller.*;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.auth.service.impl.*;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
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
            io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService passwordPolicyService,
            MessageSource messageSource) {
        return new UserController(userRepository, modelMapper, passwordEncoder, passwordPolicyService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserManagementController userManagementController(
            UserManagementService userManagementService,
            RoleService roleService,
            GroupService groupService,
            UserRepository userRepository,
            io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService passwordPolicyService,
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
            MessageSource messageSource) {
        return new RoleController(roleService, permissionService, modelMapper, roleRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyController roleHierarchyController(
            RoleHierarchyService roleHierarchyService,
            ModelMapper modelMapper,
            RoleService roleService,
            GroupService groupService,
            MessageSource messageSource) {
        return new RoleHierarchyController(
                roleHierarchyService, modelMapper, roleService, groupService, messageSource);
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
            MessageSource messageSource) {
        return new PermissionController(permissionService, modelMapper, functionCatalogService, permissionRepository, messageSource);
    }

    @Bean("userManagementService")
    @ConditionalOnMissingBean
    public UserManagementService userManagementService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            PasswordEncoder passwordEncoder,
            ModelMapper modelMapper,
            io.contexa.contexacore.autonomous.audit.CentralAuditFacade centralAuditFacade,
            io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService passwordPolicyService) {
        return new UserManagementServiceImpl(
                userRepository, groupRepository, passwordEncoder, modelMapper, centralAuditFacade, passwordPolicyService);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleService roleService(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            IntegrationEventBus eventBus,
            io.contexa.contexacore.autonomous.audit.CentralAuditFacade centralAuditFacade,
            io.contexa.contexaiam.repository.RoleHierarchyRepository roleHierarchyRepository) {
        return new RoleServiceImpl(roleRepository, permissionRepository, eventBus, centralAuditFacade, roleHierarchyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public GroupService groupService(
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            io.contexa.contexaiam.repository.RoleHierarchyRepository roleHierarchyRepository) {
        return new GroupServiceImpl(groupRepository, roleRepository, roleHierarchyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionService permissionService(
            PermissionRepository permissionRepository,
            ManagedResourceRepository managedResourceRepository) {
        return new PermissionServiceImpl(
                permissionRepository, managedResourceRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyService roleHierarchyService(
            RoleHierarchyRepository roleHierarchyRepository,
            RoleRepository roleRepository,
            RoleHierarchyImpl roleHierarchy) {
        return new RoleHierarchyService(
                roleHierarchyRepository, roleRepository, roleHierarchy);
    }
}
