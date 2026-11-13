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
package io.contexa.contexaiam.security.xacml.pap.controller;

import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.DefaultPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A policy form that the service refuses (a policy that is not there, one approved already, a form without a name)
 * answers with the refusal, as the user, role, group and role hierarchy forms do. The controller runs on Spring's real
 * transaction proxies over the real service, with only the repositories and the connection faked: a controller method
 * that opens a transaction of its own and catches the exception of a service that joined it leaves the transaction
 * marked for rollback, so its commit fails with an {@code UnexpectedRollbackException} and the person gets an error
 * page in place of the message.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class PolicyWriteTransactionTest {

    private static final String LIST = "redirect:/contexa/admin/policy-center?tab=list";

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final Connection connection = mock(Connection.class);
    private final PolicyRepository policies = mock(PolicyRepository.class);

    private AnnotationConfigApplicationContext console;

    @Configuration
    @EnableTransactionManagement
    static class Transactions {
    }

    @BeforeEach
    void aConsoleOnRealTransactions() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);
        console = new AnnotationConfigApplicationContext();
        console.register(Transactions.class);
        console.registerBean("contexaTransactionManager", DataSourceTransactionManager.class,
                () -> new DataSourceTransactionManager(dataSource));
        DefaultPolicyService service = new DefaultPolicyService(policies, mock(PolicyRetrievalPoint.class),
                mock(CustomDynamicAuthorizationManager.class), mock(PolicyEnrichmentService.class),
                mock(IntegrationEventBus.class), mock(PermissionRepository.class), mock(ManagedResourceRepository.class),
                mock(CentralAuditFacade.class), mock(PolicyConflictAnalyzer.class), mock(PolicyValidationService.class),
                mock(PolicyVersionService.class), mock(PolicyImpactAnalyzer.class), mock(PolicySimulator.class), messages,
                mock(AIPolicyValidator.class));
        console.registerBean("policyService", PolicyService.class, () -> service);
        console.registerBean("policyController", PolicyController.class,
                () -> new PolicyController(console.getBean(PolicyService.class), mock(ModelMapper.class), messages));
        console.refresh();
        clearInvocations(connection);
    }

    @AfterEach
    void close() {
        console.close();
    }

    @Test
    @DisplayName("a policy form without a name is refused with that message, not with a failed commit")
    void aFormWithoutAName() throws Exception {
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyController.class).createPolicy(new PolicyDto(), flash);

        assertThat(view).isEqualTo(LIST);
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).isNotBlank();
        verify(policies, never()).save(any());
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a policy that is not there cannot be edited: the person is told so, not met with a failed commit")
    void editingAPolicyThatIsNotThere() throws Exception {
        when(policies.findByIdWithDetails(9L)).thenReturn(Optional.empty());
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyController.class).updatePolicy(9L, new PolicyDto(), flash);

        // D01: back to the policy's screen, which sends a policy that is not there on to the list with the reason.
        assertThat(view).isEqualTo("redirect:/contexa/admin/policies/9");
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("9");
        verify(policies, never()).save(any());
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a policy that is not there cannot be deleted: the person is told so, not met with a failed commit")
    void deletingAPolicyThatIsNotThere() throws Exception {
        when(policies.findByIdWithDetails(9L)).thenReturn(Optional.empty());
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyController.class).deletePolicy(9L, null, flash);

        assertThat(view).isEqualTo(LIST);
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("9");
        verify(policies, never()).deleteById(any());
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a policy approved already cannot be approved again: the person is told so, not met with a failed commit")
    void approvingAPolicyApprovedAlready() throws Exception {
        Policy approved = Policy.builder().id(5L).name("approved").approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        when(policies.findByIdWithDetails(5L)).thenReturn(Optional.of(approved));
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyController.class).approvePolicy(5L, flash);

        assertThat(view).isEqualTo(LIST);
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).isNotBlank();
        verify(policies, never()).save(any());
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a policy rejected already cannot be rejected again: the person is told so, not met with a failed commit")
    void rejectingAPolicyRejectedAlready() throws Exception {
        Policy rejected = Policy.builder().id(5L).name("rejected").approvalStatus(Policy.ApprovalStatus.REJECTED).build();
        when(policies.findByIdWithDetails(5L)).thenReturn(Optional.of(rejected));
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyController.class).rejectPolicy(5L, flash);

        assertThat(view).isEqualTo(LIST);
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).isNotBlank();
        verify(policies, never()).save(any());
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a policy that waits is approved and the approval is committed once")
    void approvingAPolicyThatWaits() throws Exception {
        Policy waiting = Policy.builder().id(5L).name("waiting").approvalStatus(Policy.ApprovalStatus.PENDING).build();
        when(policies.findByIdWithDetails(5L)).thenReturn(Optional.of(waiting));
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyController.class).approvePolicy(5L, flash);

        assertThat(view).isEqualTo(LIST);
        assertThat(flash.getFlashAttributes()).containsKey("message").doesNotContainKey("errorMessage");
        assertThat(waiting.getApprovalStatus()).isEqualTo(Policy.ApprovalStatus.APPROVED);
        verify(policies).save(waiting);
        verify(connection, times(1)).commit();
    }
}
