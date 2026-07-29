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

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.repository.*;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.web.AdminEnterpriseModelAdvice;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.menu.controller.AdminMenuController;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuManagementService;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.monitoring.controller.AiMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.controller.DashboardController;
import io.contexa.contexaiam.admin.web.monitoring.controller.SecurityMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.service.*;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;


@AutoConfiguration
public class IamAdminMonitoringAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DashboardController iamAdminDashboardController(DashboardService dashboardService) {
        return new DashboardController(dashboardService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityMonitorController securityMonitorController(AuditLogRepository auditLogRepository, CsvExportService csvExportService) {
        return new SecurityMonitorController(auditLogRepository, csvExportService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AiSecurityDecisionMonitoringService aiSecurityDecisionMonitoringService(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            SecurityZeroTrustProperties zeroTrustProperties,
            MessageSource messageSource) {
        return new AiSecurityDecisionMonitoringService(
                jdbcOperationsProvider::getIfAvailable,
                zeroTrustProperties,
                messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public AiMonitorController aiMonitorController(
            AiSecurityDecisionMonitoringService aiSecurityDecisionMonitoringService) {
        return new AiMonitorController(aiSecurityDecisionMonitoringService);
    }

    @Bean
    @ConditionalOnMissingBean
    public CsvExportService csvExportService() {
        return new CsvExportService();
    }

    @Bean
    @ConditionalOnMissingBean
    public DashboardService dashboardService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            PolicyRepository policyRepository,
            AuditLogRepository auditLogRepository,
            RoleHierarchyRepository roleHierarchyRepository,
            UserContextService userContextService,
            SecurityScoreCalculator securityScoreCalculator,
            PermissionMatrixService permissionMatrixService,
            ManagedResourceRepository managedResourceRepository,
            BlockedUserJpaRepository blockedUserJpaRepository,
            PolicyValidationService policyValidationService,
            PolicyCombiningProperties policyCombiningProperties) {
        return new DashboardServiceImpl(
                userRepository,
                groupRepository,
                roleRepository,
                permissionRepository,
                policyRepository,
                auditLogRepository,
                roleHierarchyRepository,
                userContextService,
                securityScoreCalculator,
                permissionMatrixService,
                managedResourceRepository,
                blockedUserJpaRepository,
                policyValidationService,
                policyCombiningProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityScoreCalculator securityScoreCalculator(
            UserRepository userRepository,
            PolicyRepository policyRepository,
            RoleHierarchyRepository roleHierarchyRepository,
            AuditLogRepository auditLogRepository) {
        return new SecurityScoreCalculatorImpl(
                userRepository,
                policyRepository,
                roleHierarchyRepository,
                auditLogRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionMatrixService permissionMatrixService(
            GroupRepository groupRepository,
            PermissionCatalogService permissionCatalogService) {
        return new PermissionMatrixServiceImpl(groupRepository, permissionCatalogService);
    }

    @Bean
    @ConditionalOnMissingBean(AdminEnterpriseModelAdvice.class)
    public AutoConfiguredAdminEnterpriseModelAdvice adminEnterpriseModelAdvice(
            ContexaProperties contexaProperties,
            ObjectProvider<AdminMenuService> adminMenuServiceProvider) {
        return new AutoConfiguredAdminEnterpriseModelAdvice(contexaProperties, adminMenuServiceProvider);
    }

    @ControllerAdvice(basePackages = "io.contexa")
    public static class AutoConfiguredAdminEnterpriseModelAdvice extends AdminEnterpriseModelAdvice {

        public AutoConfiguredAdminEnterpriseModelAdvice(
                ContexaProperties contexaProperties,
                ObjectProvider<AdminMenuService> adminMenuServiceProvider) {
            super(
                    contexaProperties.getEnterprise().isEnabled(),
                    contexaProperties.getSaas().isEnabled(),
                    adminMenuServiceProvider.getIfAvailable());
        }
    }
    @Bean
    @ConditionalOnMissingBean
    public AdminMenuQueryCache adminMenuQueryCache(AdminMenuRepository adminMenuRepository) {
        return new AdminMenuQueryCache(adminMenuRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOn("iamSeedDataInitializer")
    public AdminMenuService adminMenuService(
            AdminMenuRepository adminMenuRepository,
            AdminMenuQueryCache adminMenuQueryCache,
            ContexaProperties contexaProperties) {
        AdminMenuService service =
                new AdminMenuService(
                        adminMenuRepository,
                        adminMenuQueryCache,
                        contexaProperties.getEnterprise().isEnabled(),
                        contexaProperties.getSaas().isEnabled());
        service.initializeDefaultMenusIfEmpty();
        return service;
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminMenuManagementService adminMenuManagementService(
            AdminMenuService adminMenuService,
            RoleRepository roleRepository,
            MessageSource messageSource) {
        return new AdminMenuManagementService(
                adminMenuService,
                roleRepository,
                messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminMenuController adminMenuController(
            AdminMenuManagementService adminMenuManagementService) {
        return new AdminMenuController(adminMenuManagementService);
    }
}
