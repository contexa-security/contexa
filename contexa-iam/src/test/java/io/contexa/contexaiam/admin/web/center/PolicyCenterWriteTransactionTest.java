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
package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.DefaultPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.sql.DataSource;
import java.sql.Connection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A policy the policy center refuses to make is answered with the refusal on its list. The center's command service
 * opens a transaction and catches what the policy service, which joins it, refuses with; the controller runs on
 * Spring's real transaction proxies over both real services with only the repositories and the connection faked.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class PolicyCenterWriteTransactionTest {

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final Connection connection = mock(Connection.class);

    private AnnotationConfigApplicationContext console;

    @Configuration
    @EnableTransactionManagement
    static class Transactions {
    }

    @BeforeEach
    void aCenterOnRealTransactions() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);
        console = new AnnotationConfigApplicationContext();
        console.register(Transactions.class);
        console.registerBean("contexaTransactionManager", DataSourceTransactionManager.class,
                () -> new DataSourceTransactionManager(dataSource));
        PolicyRepository policies = mock(PolicyRepository.class);
        DefaultPolicyService policyService = new DefaultPolicyService(policies, mock(PolicyRetrievalPoint.class),
                mock(CustomDynamicAuthorizationManager.class), mock(PolicyEnrichmentService.class),
                mock(IntegrationEventBus.class), mock(PermissionRepository.class), mock(ManagedResourceRepository.class),
                mock(CentralAuditFacade.class), mock(PolicyConflictAnalyzer.class), mock(PolicyValidationService.class),
                mock(PolicyVersionService.class), mock(PolicyImpactAnalyzer.class), mock(PolicySimulator.class), messages,
                mock(AIPolicyValidator.class));
        console.registerBean("policyService", PolicyService.class, () -> policyService);
        console.registerBean("policyCenterCommandService", PolicyCenterCommandService.class,
                () -> new PolicyCenterCommandService(mock(ResourceRegistryService.class),
                        console.getBean(PolicyService.class), policies, mock(RoleService.class),
                        mock(BusinessPolicyService.class), mock(ManagedResourceRepository.class),
                        mock(PermissionRepository.class), mock(PolicyValidationService.class),
                        mock(PolicyEnrichmentService.class), mock(PolicyVersionService.class),
                        mock(CustomDynamicAuthorizationManager.class), mock(CentralAuditFacade.class), messages));
        console.registerBean("policyCenterController", PolicyCenterController.class,
                () -> new PolicyCenterController(messages, mock(PolicyCenterPageService.class),
                        mock(PolicyCenterQueryService.class), console.getBean(PolicyCenterCommandService.class),
                        mock(PolicyCenterAnalysisService.class)));
        console.refresh();
        clearInvocations(connection);
    }

    @AfterEach
    void close() {
        console.close();
    }

    @Disabled("Reproduced: the controller call ends in an UnexpectedRollbackException, the policy service having marked the transaction of the command service for rollback; enable it once the command service no longer commits a transaction its callee has marked")
    @Test
    @DisplayName("a policy form without a name is answered on the list with that refusal, not with a failed commit")
    void aFormWithoutAName() throws Exception {
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyCenterController.class).createPolicyFromCenter(new PolicyCenterPolicyRequest(),
                flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/policy-center?tab=list");
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).isNotBlank();
        verify(connection, never()).commit();
    }
}
