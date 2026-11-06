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
package io.contexa.contexaiam.admin.web;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceBatchDefineRequest;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceBatchDefineResult;
import io.contexa.contexaiam.admin.web.metadata.service.ResourceAdminService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The services behind the policy center and the resource workbench answer with a text the screens show: the policy that
 * could not be created, the migration that failed, the resource that could not be defined. What they put in it is what
 * the administrator reads, so it follows the rule of the controllers: a refusal the services mean is told in its own
 * words, anything else is told as an action that could not be completed, and the exception is in the log.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class ConsoleServiceErrorTextTest {

    private static final String SQL = "could not execute statement [ERROR: relation \"ctxa_policy\" does not exist] "
            + "[select p1_0.id from ctxa_policy p1_0]";
    private static final String GENERAL = "The action could not be completed. See the server log.";
    private static final String REFUSAL = "The policy name is taken: allow-ops";

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger("io.contexa.contexaiam");

    private final PolicyService policyService = mock(PolicyService.class);
    private final PolicyRepository policyRepository = mock(PolicyRepository.class);
    private final RoleService roleService = mock(RoleService.class);
    private final BusinessPolicyService businessPolicyService = mock(BusinessPolicyService.class);
    private final PermissionRepository permissionRepository = mock(PermissionRepository.class);
    private final PolicyValidationService validation = mock(PolicyValidationService.class);
    private PolicyCenterCommandService command;

    @BeforeEach
    void listen() {
        command = new PolicyCenterCommandService(mock(ResourceRegistryService.class), policyService, policyRepository,
                roleService, businessPolicyService, mock(ManagedResourceRepository.class), permissionRepository,
                validation, mock(PolicyEnrichmentService.class), mock(PolicyVersionService.class),
                mock(CustomDynamicAuthorizationManager.class), mock(CentralAuditFacade.class), messages);
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    @Test
    @DisplayName("a policy made from the center: a refusal says why, a fault is told in general words")
    void createFromTheCenter() {
        doThrow(new IllegalArgumentException(REFUSAL)).when(policyService).createPolicy(any());
        PolicyActionResponse refused = command.createPolicyFromCenter(new PolicyCenterPolicyRequest());
        assertThat(refused.success()).isFalse();
        assertThat(refused.message()).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(policyService).createPolicy(any());
        PolicyActionResponse faulted = command.createPolicyFromCenter(new PolicyCenterPolicyRequest());
        assertThat(faulted.success()).isFalse();
        assertGeneral(faulted.message());
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("a quick policy: a refusal says why, a fault is told in general words")
    void quickCreate() {
        doThrow(new IllegalStateException(REFUSAL)).when(businessPolicyService).createPolicyFromBusinessRule(any());
        PolicyQuickCreateResponse refused = command.quickCreatePolicy(new QuickPolicyRequest());
        assertThat(refused.success()).isFalse();
        assertThat(refused.message()).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(businessPolicyService).createPolicyFromBusinessRule(any());
        PolicyQuickCreateResponse faulted = command.quickCreatePolicy(new QuickPolicyRequest());
        assertThat(faulted.success()).isFalse();
        assertGeneral(faulted.message());
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("a batch of policies: an item and the whole batch say why when refused, and are told in general words when they fault")
    void batchCreate() {
        when(roleService.getRole(10L)).thenReturn(Role.builder().id(10L).roleName("USER").build());
        when(policyRepository.findAllWithDetails()).thenReturn(new ArrayList<>());
        PolicyValidationReport report = mock(PolicyValidationReport.class);
        when(report.canCreate()).thenReturn(true);
        when(validation.validate(any(), any())).thenReturn(report);

        doThrow(new IllegalArgumentException(REFUSAL)).when(policyRepository).save(any());
        PolicyBatchCreateResponse itemRefused = command.batchCreatePolicies(batch());
        assertThat(itemRefused.results().get(0).status()).isEqualTo("ERROR");
        assertThat(itemRefused.results().get(0).reason()).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(policyRepository).save(any());
        PolicyBatchCreateResponse itemFaulted = command.batchCreatePolicies(batch());
        assertThat(itemFaulted.results().get(0).status()).isEqualTo("ERROR");
        assertGeneral(itemFaulted.results().get(0).reason());

        doThrow(new IllegalStateException(REFUSAL)).when(policyRepository).findAllWithDetails();
        PolicyBatchCreateResponse wholeRefused = command.batchCreatePolicies(batch());
        assertThat(wholeRefused.success()).isFalse();
        assertThat(wholeRefused.message()).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(policyRepository).findAllWithDetails();
        PolicyBatchCreateResponse wholeFaulted = command.batchCreatePolicies(batch());
        assertThat(wholeFaulted.success()).isFalse();
        assertGeneral(wholeFaulted.message());
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the migration of policy expressions: a refusal says why, a fault is told in general words")
    void migration() {
        doThrow(new IllegalStateException(REFUSAL)).when(policyRepository).findAllWithDetails();
        PolicyMigrationResponse refused = command.migratePolicyExpressionsToCrud();
        assertThat(refused.success()).isFalse();
        assertThat(refused.message()).isEqualTo(REFUSAL);

        doThrow(fault()).when(policyRepository).findAllWithDetails();
        PolicyMigrationResponse faulted = command.migratePolicyExpressionsToCrud();
        assertThat(faulted.success()).isFalse();
        assertThat(faulted.message()).isEqualTo(GENERAL);
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the cleanup of old permissions: a refusal says why, a fault is told in general words")
    void cleanup() {
        doThrow(new IllegalStateException(REFUSAL)).when(permissionRepository).findAll();
        PolicyCleanupResponse refused = command.cleanupOldAutoCreatedPermissions();
        assertThat(refused.success()).isFalse();
        assertThat(refused.message()).isEqualTo(REFUSAL);

        doThrow(fault()).when(permissionRepository).findAll();
        PolicyCleanupResponse faulted = command.cleanupOldAutoCreatedPermissions();
        assertThat(faulted.success()).isFalse();
        assertThat(faulted.message()).isEqualTo(GENERAL);
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the rollback of a policy: a refusal says why, a fault is told in general words")
    void rollback() {
        doThrow(new IllegalArgumentException(REFUSAL)).when(policyService).rollbackPolicy(any(), anyInt(), any());
        PolicyActionResponse refused = command.rollbackPolicy(1L, 2, null);
        assertThat(refused.success()).isFalse();
        assertThat(refused.message()).isEqualTo(REFUSAL);

        doThrow(fault()).when(policyService).rollbackPolicy(any(), anyInt(), any());
        PolicyActionResponse faulted = command.rollbackPolicy(1L, 2, null);
        assertThat(faulted.success()).isFalse();
        assertThat(faulted.message()).isEqualTo(GENERAL);
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the batch definition of resources: a refusal says why, a fault is told in general words")
    void batchDefinition() {
        ResourceRegistryService registry = mock(ResourceRegistryService.class);
        ResourceAdminService resources = new ResourceAdminService(registry, mock(ManagedResourceRepository.class), messages);
        List<ResourceBatchDefineRequest> requests = List.of(new ResourceBatchDefineRequest(5L, "Orders", "read orders"));

        doThrow(new IllegalArgumentException(REFUSAL)).when(registry).defineResourceAsPermission(any(), any());
        List<ResourceBatchDefineResult> refused = resources.defineResourcesBatch(requests);
        assertThat(refused.get(0).error()).isEqualTo(REFUSAL);

        doThrow(fault()).when(registry).defineResourceAsPermission(any(), any());
        List<ResourceBatchDefineResult> faulted = resources.defineResourcesBatch(requests);
        assertThat(faulted.get(0).error()).isEqualTo(GENERAL);
        assertTheLogKeepsTheFault();
    }

    // ----- helpers -----

    private static RuntimeException fault() {
        return new DataAccessResourceFailureException(SQL);
    }

    private static BatchCreateRequest batch() {
        BatchCreateRequest.BatchItem item = new BatchCreateRequest.BatchItem();
        item.setResourceIdentifier("/api/orders");
        item.setCrudPermissions(Set.of("READ"));
        BatchCreateRequest request = new BatchCreateRequest();
        request.setItems(List.of(item));
        request.setRoleIds(Set.of(10L));
        request.setEffect(Policy.Effect.ALLOW);
        return request;
    }

    private static void assertGeneral(String shown) {
        assertThat(shown).contains(GENERAL).doesNotContain("ctxa_policy", "statement", "Exception");
    }

    private void assertTheLogKeepsTheFault() {
        assertThat(logged.list).anySatisfy(event -> {
            assertThat(event.getThrowableProxy()).isNotNull();
            assertThat(event.getThrowableProxy().getMessage()).isEqualTo(SQL);
        });
    }
}
