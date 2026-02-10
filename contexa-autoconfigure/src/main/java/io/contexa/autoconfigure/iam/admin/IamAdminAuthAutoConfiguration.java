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
import io.contexa.contexaiam.repository.DocumentRepository;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
            PasswordEncoder passwordEncoder) {
        return new UserController(userRepository, modelMapper, passwordEncoder);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserManagementController userManagementController(
            UserManagementService userManagementService,
            RoleService roleService,
            GroupService groupService) {
        return new UserManagementController(userManagementService, roleService, groupService);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleController roleController(
            RoleService roleService,
            PermissionService permissionService,
            ModelMapper modelMapper) {
        return new RoleController(roleService, permissionService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyController roleHierarchyController(
            RoleHierarchyService roleHierarchyService,
            ModelMapper modelMapper,
            RoleService roleService,
            GroupService groupService) {
        return new RoleHierarchyController(
                roleHierarchyService, modelMapper, roleService, groupService);
    }

    @Bean
    @ConditionalOnMissingBean
    public GroupController groupController(
            GroupService groupService,
            RoleService roleService,
            ModelMapper modelMapper) {
        return new GroupController(groupService, roleService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionController permissionController(
            PermissionService permissionService,
            ModelMapper modelMapper,
            FunctionCatalogService functionCatalogService) {
        return new PermissionController(permissionService, modelMapper, functionCatalogService);
    }

    @Bean
    @ConditionalOnMissingBean
    public DocumentController documentController(DocumentService documentService) {
        return new DocumentController(documentService);
    }

    
    @Bean("userManagementService")
    @ConditionalOnMissingBean
    public UserManagementService userManagementService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            PasswordEncoder passwordEncoder,
            ModelMapper modelMapper) {
        return new UserManagementServiceImpl(
                userRepository, groupRepository, passwordEncoder, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleService roleService(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            IntegrationEventBus eventBus) {
        return new RoleServiceImpl(roleRepository, permissionRepository, eventBus);
    }

    @Bean
    @ConditionalOnMissingBean
    public GroupService groupService(
            GroupRepository groupRepository,
            RoleRepository roleRepository) {
        return new GroupServiceImpl(groupRepository, roleRepository);
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

    @Bean
    @ConditionalOnMissingBean
    public DocumentService documentService(DocumentRepository documentRepository) {
        return new DocumentService(documentRepository);
    }
}
