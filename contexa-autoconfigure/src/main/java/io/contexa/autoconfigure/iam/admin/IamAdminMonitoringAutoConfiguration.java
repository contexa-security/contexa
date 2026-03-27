package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.web.AdminEnterpriseModelAdvice;
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
import org.springframework.boot.autoconfigure.AutoConfiguration;
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
            BlockedUserJpaRepository blockedUserJpaRepository) {
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
                blockedUserJpaRepository);
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
            ContexaProperties contexaProperties) {
        return new AdminEnterpriseModelAdvice(
                contexaProperties.getEnterprise().isEnabled(),
                contexaProperties.getSaas().isEnabled());
    }
}
