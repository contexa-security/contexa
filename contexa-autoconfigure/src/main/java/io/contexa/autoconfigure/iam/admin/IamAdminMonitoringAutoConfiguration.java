package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.web.monitoring.controller.DashboardController;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.admin.web.monitoring.service.DashboardService;
import io.contexa.contexaiam.admin.web.monitoring.service.DashboardServiceImpl;
import io.contexa.contexaiam.admin.web.monitoring.service.PermissionMatrixService;
import io.contexa.contexaiam.admin.web.monitoring.service.PermissionMatrixServiceImpl;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityScoreCalculator;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityScoreCalculatorImpl;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
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
    public DashboardService dashboardService(
            UserRepository userRepository,
            UserContextService userContextService,
            SecurityScoreCalculator securityScoreCalculator,
            PermissionMatrixService permissionMatrixService) {
        return new DashboardServiceImpl(
                userRepository, userContextService, securityScoreCalculator, permissionMatrixService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityScoreCalculator securityScoreCalculator(UserRepository userRepository) {
        return new SecurityScoreCalculatorImpl(userRepository);
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
    public AuditLogService auditLogService(AuditLogRepository auditLogRepository) {
        return new AuditLogService(auditLogRepository);
    }
}
