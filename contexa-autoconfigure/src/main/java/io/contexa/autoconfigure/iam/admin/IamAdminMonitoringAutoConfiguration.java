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
import io.contexa.contexaiam.admin.web.AdminEnterpriseModelAdvice;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.menu.controller.AdminMenuController;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuManagementService;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import io.contexa.contexaiam.admin.web.monitoring.controller.AiMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.controller.SecurityMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.service.DecisionRecordSealCheck;
import io.contexa.contexaiam.admin.web.dashboard.DashboardController;
import io.contexa.contexaiam.admin.web.dashboard.DashboardHourlyStats;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries;
import io.contexa.contexaiam.admin.web.dashboard.DashboardService;
import io.contexa.contexaiam.admin.web.dashboard.DashboardServiceImpl;
import io.contexa.contexaiam.admin.web.dashboard.DashboardSources;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleController;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.env.Environment;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.LinkedHashSet;
import java.util.Set;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;


@AutoConfiguration
public class IamAdminMonitoringAutoConfiguration {

    private static final String IAM_SEED_DATA_INITIALIZER_BEAN = "contexaIamSeedDataInitializer";
    private static final String ADMIN_MENU_SERVICE_BEAN = "contexaAdminMenuService";

    /** Plan step 9 (N1): the admin dashboard's page and the JSON its script draws. */
    @Bean(name = "contexaIamAdminDashboardController")
    @ConditionalOnMissingBean
    public DashboardController iamAdminDashboardController(DashboardService contexaDashboardService,
                                                           MessageSource messageSource,
                                                           @Qualifier("contexaObjectMapper")
                                                           ObjectProvider<ObjectMapper> objectMapper) {
        return new DashboardController(contexaDashboardService, messageSource,
                objectMapper.getIfAvailable(ObjectMapper::new));
    }

    @Bean(name = "contexaSecurityMonitorController")
    @ConditionalOnMissingBean
    public SecurityMonitorController securityMonitorController(AuditLogRepository auditLogRepository,
                                                               CsvExportService contexaCsvExportService,
                                                               ObjectProvider<DelegationRegistry> delegationRegistry,
                                                               ObjectProvider<EvidenceSigner> evidenceSigner,
                                                               MessageSource messageSource,
                                                               ObjectProvider<DashboardQueries> dashboardQueries) {
        // docs/agent A5-5: the delegation an agent's decision ran under, when Contexa keeps delegations (OC-1).
        SecurityMonitorController controller = new SecurityMonitorController(auditLogRepository, contexaCsvExportService,
                delegationRegistry.getIfAvailable());
        // docs/agent A5-6: the decision records' integrity.
        evidenceSigner.ifAvailable(controller::setEvidenceSigner);
        controller.setMessageSource(messageSource);
        // K92: the decision records the dashboard's seal check found mismatched.
        dashboardQueries.ifAvailable(controller::setDashboardQueries);
        return controller;
    }

    /** Console plan 5-2: the AI monitor's old addresses open the Zero Trust console's screens. */
    @Bean(name = "contexaAiMonitorController")
    @ConditionalOnMissingBean
    public AiMonitorController aiMonitorController() {
        return new AiMonitorController();
    }

    /** Console design 3 to 6: the numbers of the Zero Trust console, read from its hourly tables. */
    @Bean(name = "contexaZeroTrustConsoleService")
    @ConditionalOnMissingBean
    public ZeroTrustConsoleService zeroTrustConsoleService(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            SecurityZeroTrustProperties zeroTrustProperties,
            MessageSource messageSource,
            @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper,
            ObjectProvider<SecurityPlaneAgent> securityPlaneAgent,
            Environment environment) {
        // The standalone mode keeps the decisions in force and the baselines in memory (console design 6.0).
        boolean standalone = !"distributed".equalsIgnoreCase(environment.getProperty("contexa.infrastructure.mode"));
        return new ZeroTrustConsoleService(jdbcOperationsProvider::getIfAvailable, zeroTrustProperties, messageSource,
                objectMapper.getIfAvailable(), securityPlaneAgent::getIfAvailable, standalone, null);
    }

    /** Console design 6.4 and decision 11.3: the decision records, the review queue and the evaluations. */
    @Bean(name = "contexaZeroTrustDecisionRecords")
    @ConditionalOnMissingBean
    public ZeroTrustDecisionRecords zeroTrustDecisionRecords(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            ObjectProvider<ZeroTrustDecisionOutcomes> decisionOutcomes,
            MessageSource messageSource,
            @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper,
            Environment environment) {
        ZeroTrustDecisionRecords records = new ZeroTrustDecisionRecords(jdbcOperationsProvider::getIfAvailable,
                decisionOutcomes.getIfAvailable(), messageSource, objectMapper.getIfAvailable(), null);
        // Console design 6.0: the decision detail warns of the standalone mode as every screen's band does.
        records.setStandalone(!"distributed".equalsIgnoreCase(environment.getProperty("contexa.infrastructure.mode")));
        return records;
    }

    @Bean(name = "contexaZeroTrustConsoleController")
    @ConditionalOnMissingBean
    public ZeroTrustConsoleController zeroTrustConsoleController(ZeroTrustConsoleService contexaZeroTrustConsoleService,
                                                                 ZeroTrustDecisionRecords contexaZeroTrustDecisionRecords,
                                                                 MessageSource messageSource,
                                                                 @Qualifier("contexaObjectMapper")
                                                                 ObjectProvider<ObjectMapper> objectMapper) {
        return new ZeroTrustConsoleController(contexaZeroTrustConsoleService, contexaZeroTrustDecisionRecords,
                messageSource, objectMapper.getIfAvailable(ObjectMapper::new));
    }

    @Bean(name = "contexaCsvExportService")
    @ConditionalOnMissingBean
    public CsvExportService csvExportService() {
        return new CsvExportService();
    }

    /** Plan step 9: the dashboard's own counts, one statement each. */
    @Bean(name = "contexaDashboardQueries")
    @ConditionalOnMissingBean
    public DashboardQueries dashboardQueries(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider) {
        return new DashboardQueries(jdbcOperationsProvider::getIfAvailable);
    }

    /**
     * Plan step 9 (N7, N20): the dashboard's hourly tables, the refusals of signed-in users and the seal checks of the
     * decision records, rebuilt as the Zero Trust console's are and kept as long.
     */
    @Bean(name = "contexaDashboardHourlyStats")
    @ConditionalOnMissingBean
    public DashboardHourlyStats dashboardHourlyStats(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            ObjectProvider<AuditLogRepository> auditLogRepository,
            ObjectProvider<EvidenceSigner> evidenceSigner,
            SecurityZeroTrustProperties zeroTrustProperties) {
        AuditLogRepository records = auditLogRepository.getIfAvailable();
        return new DashboardHourlyStats(jdbcOperationsProvider::getIfAvailable, records,
                records != null ? new DecisionRecordSealCheck(records, evidenceSigner::getIfAvailable) : null,
                zeroTrustProperties, null);
    }

    /** Plan step 9 (N1): every card's numbers, read from the services of the screens. */
    @Bean(name = "contexaDashboardService")
    @ConditionalOnMissingBean
    public DashboardService dashboardService(
            ZeroTrustConsoleService contexaZeroTrustConsoleService,
            ZeroTrustDecisionRecords contexaZeroTrustDecisionRecords,
            DashboardQueries contexaDashboardQueries,
            AccessCenterService contexaAccessCenterService,
            LastAdministratorGuard contexaLastAdministratorGuard,
            VerificationCoverageService contexaVerificationCoverageService,
            RoleHierarchyRepository roleHierarchyRepository,
            RoleRepository roleRepository,
            PasswordPolicyService contexaPasswordPolicyService,
            ManagedResourceRepository managedResourceRepository,
            PolicyRepository policyRepository,
            PolicyValidationService contexaPolicyValidationService,
            PolicyCenterCommandService contexaPolicyCenterCommandService,
            IpAccessRuleService contexaIpAccessRuleService,
            AuditLogRepository auditLogRepository,
            SystemSettingsService contexaSystemSettingsService,
            PolicyCombiningProperties policyCombiningProperties,
            ObjectProvider<AgentRegistry> agentRegistry,
            ObjectProvider<DelegationRegistry> delegationRegistry,
            ObjectProvider<AgentConfirmationStore> agentConfirmationStore,
            ObjectProvider<AgentContainmentAdminService> agentContainmentAdminService,
            MessageSource messageSource) {
        return new DashboardServiceImpl(new DashboardSources(contexaZeroTrustConsoleService,
                contexaZeroTrustDecisionRecords, contexaDashboardQueries, contexaAccessCenterService,
                contexaLastAdministratorGuard, contexaVerificationCoverageService, roleHierarchyRepository, roleRepository,
                contexaPasswordPolicyService, managedResourceRepository, policyRepository, contexaPolicyValidationService,
                contexaPolicyCenterCommandService, contexaIpAccessRuleService, auditLogRepository,
                contexaSystemSettingsService, policyCombiningProperties, agentRegistry.getIfAvailable(),
                delegationRegistry.getIfAvailable(), agentConfirmationStore.getIfAvailable(),
                agentContainmentAdminService.getIfAvailable(), messageSource), null);
    }

    @Bean(name = "contexaAdminEnterpriseModelAdvice")
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
    @Bean(name = "contexaAdminMenuQueryCache")
    @ConditionalOnMissingBean
    public AdminMenuQueryCache adminMenuQueryCache(AdminMenuRepository adminMenuRepository) {
        return new AdminMenuQueryCache(adminMenuRepository);
    }

    @Bean(name = "contexaAdminMenuSeedDataDependencyConfigurer")
    public static BeanFactoryPostProcessor adminMenuSeedDataDependencyConfigurer() {
        return beanFactory -> {
            if (!beanFactory.containsBeanDefinition(ADMIN_MENU_SERVICE_BEAN)
                    || !beanFactory.containsBeanDefinition(IAM_SEED_DATA_INITIALIZER_BEAN)) {
                return;
            }
            BeanDefinition adminMenuService = beanFactory.getBeanDefinition(ADMIN_MENU_SERVICE_BEAN);
            Set<String> dependsOn = new LinkedHashSet<>();
            if (adminMenuService.getDependsOn() != null) {
                for (String dependency : adminMenuService.getDependsOn()) {
                    dependsOn.add(dependency);
                }
            }
            if (dependsOn.add(IAM_SEED_DATA_INITIALIZER_BEAN)) {
                adminMenuService.setDependsOn(dependsOn.toArray(String[]::new));
            }
        };
    }

    @Bean(name = "contexaAdminMenuService")
    @ConditionalOnMissingBean
    public AdminMenuService adminMenuService(
            AdminMenuRepository adminMenuRepository,
            AdminMenuQueryCache contexaAdminMenuQueryCache,
            ContexaProperties contexaProperties) {
        AdminMenuService service =
                new AdminMenuService(
                        adminMenuRepository,
                        contexaAdminMenuQueryCache,
                        contexaProperties.getEnterprise().isEnabled(),
                        contexaProperties.getSaas().isEnabled());
        service.initializeDefaultMenusIfEmpty();
        return service;
    }

    @Bean(name = "contexaAdminMenuManagementService")
    @ConditionalOnMissingBean
    public AdminMenuManagementService adminMenuManagementService(
            AdminMenuService contexaAdminMenuService,
            RoleRepository roleRepository,
            MessageSource messageSource) {
        return new AdminMenuManagementService(
                contexaAdminMenuService,
                roleRepository,
                messageSource);
    }

    @Bean(name = "contexaAdminMenuController")
    @ConditionalOnMissingBean
    public AdminMenuController adminMenuController(
            AdminMenuManagementService contexaAdminMenuManagementService) {
        return new AdminMenuController(contexaAdminMenuManagementService);
    }
}
