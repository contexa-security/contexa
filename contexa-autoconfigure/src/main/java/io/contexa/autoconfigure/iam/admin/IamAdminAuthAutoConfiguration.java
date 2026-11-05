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
package io.contexa.autoconfigure.iam.admin;

import org.springframework.beans.factory.ObjectProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OwnershipBehaviour;
import org.springframework.beans.factory.BeanFactory;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.controller.*;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.impl.*;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.FunctionCatalogRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.context.MessageSource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Qualifier;

@AutoConfiguration
public class IamAdminAuthAutoConfiguration {

    /**
     * Under HOST_OWNED the console signs its administrators in on its own chain (ownership design S-3), so the form
     * posts there. Under CONTEXA_OWNED the multi-step sign-in has its own page, whose answers only that page can follow, so
     * the console's address leads there; a single form sign-in takes the console's form as before.
     */
    @Bean(name = "contexaLoginController")
    @ConditionalOnMissingBean
    public LoginController loginController(Environment environment, ObjectProvider<MfaFlowUrlRegistry> mfaFlowUrls) {
        boolean ownChain = !ContexaOperatingProfile.ownershipUndeclared(environment)
                && OwnershipBehaviour.of(ContexaOperatingProfile.resolve(environment).ownership()).consoleSignsInOnItsOwnChain();
        if (ownChain) {
            return new LoginController(LoginController.HOST_OWNED_LOGIN_PROCESSING_URL);
        }
        return new LoginController(LoginController.DEFAULT_LOGIN_PROCESSING_URL, () -> {
            MfaFlowUrlRegistry flows = mfaFlowUrls.getIfAvailable();
            return flows != null ? flows.primaryLoginPage().orElse(null) : null;
        });
    }

    @Bean(name = "contexaUserManagementController")
    @ConditionalOnMissingBean
    public UserManagementController userManagementController(
            UserManagementService contexaUserManagementService,
            RoleService contexaRoleService,
            GroupService contexaGroupService,
            PasswordPolicyService contexaPasswordPolicyService,
            MessageSource messageSource) {
        return new UserManagementController(contexaUserManagementService, contexaRoleService, contexaGroupService, contexaPasswordPolicyService, messageSource);
    }

    @Bean(name = "contexaRoleController")
    @ConditionalOnMissingBean
    public RoleController roleController(
            RoleService contexaRoleService,
            PermissionService contexaPermissionService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            MessageSource messageSource) {
        return new RoleController(contexaRoleService, contexaPermissionService, contexaModelMapper, messageSource);
    }

    @Bean(name = "contexaRoleHierarchyController")
    @ConditionalOnMissingBean
    public RoleHierarchyController roleHierarchyController(
            RoleHierarchyService contexaRoleHierarchyService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            RoleService contexaRoleService,
            GroupService contexaGroupService,
            MessageSource messageSource) {
        return new RoleHierarchyController(contexaRoleHierarchyService, contexaModelMapper, contexaRoleService, contexaGroupService, messageSource);
    }

    @Bean(name = "contexaGroupController")
    @ConditionalOnMissingBean
    public GroupController groupController(
            GroupService contexaGroupService,
            RoleService contexaRoleService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            MessageSource messageSource) {
        return new GroupController(contexaGroupService, contexaRoleService, contexaModelMapper, messageSource);
    }

    @Bean(name = "contexaPermissionController")
    @ConditionalOnMissingBean
    public PermissionController permissionController(
            PermissionService contexaPermissionService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            FunctionCatalogService contexaFunctionCatalogService,
            MessageSource messageSource) {
        return new PermissionController(contexaPermissionService, contexaModelMapper, contexaFunctionCatalogService, messageSource);
    }

    @Bean("contexaUserManagementService")
    @ConditionalOnMissingBean
    public UserManagementService userManagementService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            BeanFactory beanFactory,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            CentralAuditFacade contexaCentralAuditFacade,
            PasswordPolicyService contexaPasswordPolicyService,
            SystemSettingsService contexaSystemSettingsService,
            MessageSource messageSource,
            UserRolePermissionRepository userRolePermissionRepository,
            BridgeUserProfileRepository bridgeUserProfileRepository,
            ApplicationEventPublisher eventPublisher) {
        return new UserManagementServiceImpl(
                userRepository, groupRepository, roleRepository, ContexaOwnBeans.passwordEncoder(beanFactory), contexaModelMapper,
                contexaCentralAuditFacade, contexaPasswordPolicyService, contexaSystemSettingsService, messageSource,
                userRolePermissionRepository, bridgeUserProfileRepository, eventPublisher);
    }

    /** Q-1: who could not answer a CHALLENGE, for the start and the console's user list. */
    @Bean(name = "contexaVerificationCoverageService")
    @ConditionalOnMissingBean
    public VerificationCoverageService verificationCoverageService(
            UserRepository userRepository,
            ObjectProvider<BridgeProperties> bridgeProperties,
            ObjectProvider<EmailService> emailService) {
        BridgeProperties bridge = bridgeProperties.getIfAvailable(BridgeProperties::new);
        return new VerificationCoverageService(userRepository, bridge.getSync().getSyntheticEmailDomain(), () -> {
            EmailService mail = emailService.getIfAvailable();
            return mail != null && mail.isMailSenderConfigured();
        });
    }

    @Bean(name = "contexaRoleService")
    @ConditionalOnMissingBean
    public RoleService roleService(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            IntegrationEventBus eventBus,
            CentralAuditFacade contexaCentralAuditFacade,
            RoleHierarchyRepository roleHierarchyRepository,
            PolicyRepository policyRepository,
            PolicySynchronizationService contexaPolicySynchronizationService,
            MessageSource messageSource) {
        return new RoleServiceImpl(roleRepository, permissionRepository, eventBus, contexaCentralAuditFacade,
                roleHierarchyRepository, policyRepository, contexaPolicySynchronizationService, messageSource);
    }

    @Bean(name = "contexaGroupService")
    @ConditionalOnMissingBean
    public GroupService groupService(
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            RoleHierarchyRepository roleHierarchyRepository,
            MessageSource messageSource) {
        return new GroupServiceImpl(groupRepository, roleRepository, roleHierarchyRepository, messageSource);
    }

    @Bean(name = "contexaPermissionService")
    @ConditionalOnMissingBean
    public PermissionService permissionService(
            PermissionRepository permissionRepository,
            ManagedResourceRepository managedResourceRepository,
            PolicyRepository policyRepository,
            MessageSource messageSource) {
        return new PermissionServiceImpl(
                permissionRepository, managedResourceRepository, policyRepository, messageSource);
    }

    @Bean(name = "contexaRoleHierarchyService")
    @ConditionalOnMissingBean
    public RoleHierarchyService roleHierarchyService(
            RoleHierarchyRepository roleHierarchyRepository,
            RoleRepository roleRepository,
            BeanFactory beanFactory,
            MessageSource messageSource) {
        return new RoleHierarchyService(roleHierarchyRepository, roleRepository,
                ContexaOwnBeans.roleHierarchyImpl(beanFactory), messageSource);
    }
}

