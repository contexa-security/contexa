package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.web.AdminEnterpriseModelAdvice;
import io.contexa.contexaiam.admin.web.menu.controller.AdminMenuController;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuManagementService;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.monitoring.controller.DashboardController;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.monitoring.controller.SecurityMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.service.*;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminMonitoringAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DashboardController dashboardController(DashboardService dashboardService) {
        return new DashboardController(dashboardService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityMonitorController securityMonitorController(AuditLogRepository auditLogRepository, CsvExportService csvExportService) {
        return new SecurityMonitorController(auditLogRepository, csvExportService);
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
    @ConditionalOnMissingBean
    public AdminEnterpriseModelAdvice adminEnterpriseModelAdvice(
            ContexaProperties contexaProperties,
            ObjectProvider<AdminMenuService> adminMenuServiceProvider) {
        return new AdminEnterpriseModelAdvice(
                contexaProperties.getEnterprise().isEnabled(),
                contexaProperties.getSaas().isEnabled(),
                adminMenuServiceProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminMenuQueryCache adminMenuQueryCache(AdminMenuRepository adminMenuRepository) {
        return new AdminMenuQueryCache(adminMenuRepository);
    }

    @Bean
    @ConditionalOnMissingBean
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
            org.springframework.context.MessageSource messageSource) {
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

