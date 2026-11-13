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

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyBatchCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyCleanupResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMigrationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyQuickCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.interceptor.MatchAlwaysTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Arrays;
import org.springframework.context.event.EventListener;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What the policy center's command service answers when something it calls fails. The service opens a transaction, the
 * services and repositories it calls join it, and a callee that fails marks the shared transaction for rollback before
 * the command service catches what it threw: the commit at the end of the method then ends in an
 * {@code UnexpectedRollbackException} and the answer the service built never reaches the person. The service and its
 * callees run on Spring's real transaction proxies here, over the real policy service, with only the repositories, the
 * other collaborators and the connection faked. A repository or a service that is a mock is wrapped in the same
 * transaction interceptor the real one has, so that its failure marks the transaction as it does.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class PolicyCenterWriteTransactionTest {

    private static final String LIST = "redirect:/contexa/admin/policy-center?tab=list";

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final Connection connection = mock(Connection.class);
    private final PolicyRepository policies = mock(PolicyRepository.class);
    private final PermissionRepository permissions = mock(PermissionRepository.class);
    private final ManagedResourceRepository resources = mock(ManagedResourceRepository.class);
    private final RoleService roles = mock(RoleService.class);
    private final BusinessPolicyService business = mock(BusinessPolicyService.class);
    private final PolicyValidationService validation = mock(PolicyValidationService.class);
    private final PolicyVersionService versions = mock(PolicyVersionService.class);

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
        DefaultPolicyService policyService = new DefaultPolicyService(policies, mock(PolicyRetrievalPoint.class),
                mock(CustomDynamicAuthorizationManager.class), mock(PolicyEnrichmentService.class),
                mock(IntegrationEventBus.class), permissions, resources, mock(CentralAuditFacade.class),
                mock(PolicyConflictAnalyzer.class), mock(PolicyValidationService.class), versions,
                mock(PolicyImpactAnalyzer.class), mock(PolicySimulator.class), messages, mock(AIPolicyValidator.class));
        console.registerBean("policyService", PolicyService.class, () -> policyService);
        console.registerBean("policyCenterCommandService", PolicyCenterCommandService.class, () -> {
            PlatformTransactionManager manager = console.getBean(PlatformTransactionManager.class);
            PolicyCenterCommandService service = new PolicyCenterCommandService(mock(ResourceRegistryService.class),
                    console.getBean(PolicyService.class), transactional(policies, PolicyRepository.class, manager),
                    transactional(roles, RoleService.class, manager),
                    transactional(business, BusinessPolicyService.class, manager),
                    transactional(resources, ManagedResourceRepository.class, manager),
                    transactional(permissions, PermissionRepository.class, manager), validation,
                    mock(PolicyEnrichmentService.class), versions, mock(CustomDynamicAuthorizationManager.class),
                    mock(CentralAuditFacade.class), messages);
            TransactionTemplate item = new TransactionTemplate(manager);
            item.setPropagationBehavior(TransactionTemplate.PROPAGATION_REQUIRES_NEW);
            service.setItemTransactions(item);
            return service;
        });
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

    @Test
    @DisplayName("a policy form without a name is answered on the list with that refusal, not with a failed commit")
    void aFormWithoutAName() throws Exception {
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PolicyCenterController.class).createPolicyFromCenter(new PolicyCenterPolicyRequest(),
                flash);

        assertThat(view).isEqualTo(LIST);
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).isNotBlank();
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a policy the center makes is committed once, with the answer that it was made")
    void aPolicyThatIsMade() throws Exception {
        when(policies.save(any(Policy.class))).thenAnswer(call -> call.getArgument(0));
        PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
        request.setName("allow-orders");
        request.setEffect("ALLOW");
        PolicyCenterPolicyRequest.TargetRequest target = new PolicyCenterPolicyRequest.TargetRequest();
        target.setTargetType("URL");
        target.setTargetIdentifier("/api/orders");
        request.setTargets(List.of(target));

        PolicyActionResponse response = console.getBean(PolicyCenterCommandService.class).createPolicyFromCenter(request);

        assertThat(response.success()).isTrue();
        verify(connection, times(1)).commit();
    }

    @Test
    @DisplayName("a rollback to a version that is not there is answered with that refusal, not with a failed commit")
    void aRollbackToAVersionThatIsNotThere() throws Exception {
        PolicyActionResponse response = console.getBean(PolicyCenterCommandService.class).rollbackPolicy(5L, 9, null);

        assertThat(response.success()).isFalse();
        assertThat(response.message()).contains("9");
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a quick policy made after a role that is not there was looked for is made and answered as made")
    void aQuickPolicyAfterAMissingRole() throws Exception {
        when(roles.getRole(7L)).thenThrow(new IllegalArgumentException("Role not found: 7"));
        when(business.createPolicyFromBusinessRule(any())).thenReturn(Policy.builder().id(3L).name("quick").build());
        QuickPolicyRequest request = new QuickPolicyRequest();
        request.setRoleIds(Set.of(7L));

        PolicyQuickCreateResponse response = console.getBean(PolicyCenterCommandService.class).quickCreatePolicy(request);

        assertThat(response.success()).isTrue();
        assertThat(response.policyId()).isEqualTo(3L);
    }

    @Test
    @DisplayName("a quick policy the business service refuses is answered with that refusal, not with a failed commit")
    void aQuickPolicyThatIsRefused() throws Exception {
        when(business.createPolicyFromBusinessRule(any())).thenThrow(new IllegalArgumentException("The policy is empty"));

        PolicyQuickCreateResponse response = console.getBean(PolicyCenterCommandService.class)
                .quickCreatePolicy(new QuickPolicyRequest());

        assertThat(response.success()).isFalse();
        assertThat(response.message()).contains("The policy is empty");
    }

    @Test
    @DisplayName("a batch with an item the database refuses answers that item and writes the others")
    void aBatchWithAnItemTheDatabaseRefuses() throws Exception {
        when(roles.getRole(10L)).thenReturn(Role.builder().id(10L).roleName("USER").build());
        when(policies.findAllWithDetails()).thenReturn(new ArrayList<>());
        PolicyValidationReport report = mock(PolicyValidationReport.class);
        when(report.canCreate()).thenReturn(true);
        when(validation.validate(any(), any())).thenReturn(report);
        when(policies.save(any(Policy.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate key value violates unique constraint"))
                .thenAnswer(call -> call.getArgument(0));

        PolicyBatchCreateResponse response = console.getBean(PolicyCenterCommandService.class)
                .batchCreatePolicies(batch("/api/first", "/api/second"));

        assertThat(response.success()).isTrue();
        assertThat(response.created()).isEqualTo(1);
        assertThat(response.results()).extracting(item -> item.status()).containsExactly("ERROR", "CREATED");
        // The item the database refused was rolled back by itself; the reads and the other item were committed.
        verify(connection, times(1)).rollback();
    }

    @Test
    @DisplayName("the migration of policy expressions that fails is answered as failed, not with a failed commit")
    void aMigrationThatFails() throws Exception {
        when(policies.findAllWithDetails()).thenThrow(new IllegalStateException("The expressions cannot be read"));

        PolicyMigrationResponse response = console.getBean(PolicyCenterCommandService.class)
                .migratePolicyExpressionsToCrud();

        assertThat(response.success()).isFalse();
        assertThat(response.message()).isEqualTo("The expressions cannot be read");
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("the cleanup of old permissions that fails is answered as failed, not with a failed commit")
    void aCleanupThatFails() throws Exception {
        when(permissions.findAll()).thenThrow(new IllegalStateException("The permissions cannot be read"));

        PolicyCleanupResponse response = console.getBean(PolicyCenterCommandService.class)
                .cleanupOldAutoCreatedPermissions();

        assertThat(response.success()).isFalse();
        assertThat(response.message()).isEqualTo("The permissions cannot be read");
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("D41: the start of the application rewrites no policy expression")
    void theStartRewritesNoExpression() {
        assertThat(Arrays.stream(PolicyCenterCommandService.class.getMethods())
                .filter(method -> method.isAnnotationPresent(EventListener.class)))
                .isEmpty();
    }

    @Test
    @DisplayName("resources that are reset one by one: one that fails is skipped and the others are reset")
    void resourcesResetOneByOne() throws Exception {
        ManagedResource second = ManagedResource.builder().id(2L).status(ManagedResource.Status.PERMISSION_CREATED).build();
        when(resources.findById(1L)).thenThrow(new IllegalStateException("The resource cannot be read"));
        when(resources.findById(2L)).thenReturn(Optional.of(second));

        PolicyActionResponse response = console.getBean(PolicyCenterCommandService.class)
                .resetPolicyStatus(List.of(1L, 2L));

        assertThat(response.success()).isTrue();
        assertThat(response.updated()).isEqualTo(1);
        verify(connection, times(1)).commit();
    }

    // ----- helpers -----

    private static BatchCreateRequest batch(String... identifiers) {
        List<BatchCreateRequest.BatchItem> items = new ArrayList<>();
        for (String identifier : identifiers) {
            BatchCreateRequest.BatchItem item = new BatchCreateRequest.BatchItem();
            item.setResourceIdentifier(identifier);
            item.setCrudPermissions(Set.of("READ"));
            items.add(item);
        }
        BatchCreateRequest request = new BatchCreateRequest();
        request.setItems(items);
        request.setRoleIds(Set.of(10L));
        request.setEffect(Policy.Effect.ALLOW);
        return request;
    }

    /** What a repository or a service of Spring's own is: the same interceptor around the target, so a failure marks. */
    @SuppressWarnings("unchecked")
    private static <T> T transactional(T target, Class<T> type, PlatformTransactionManager manager) {
        ProxyFactory factory = new ProxyFactory(target);
        factory.addInterface(type);
        factory.addAdvice(new TransactionInterceptor(manager, new MatchAlwaysTransactionAttributeSource()));
        return (T) factory.getProxy();
    }
}
