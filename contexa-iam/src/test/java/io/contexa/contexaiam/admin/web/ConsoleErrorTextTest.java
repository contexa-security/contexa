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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexaiam.admin.web.agent.controller.AgentAdminController;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.auth.controller.BlacklistController;
import io.contexa.contexaiam.admin.web.auth.controller.GroupController;
import io.contexa.contexaiam.admin.web.auth.controller.IpManagementController;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordPolicyController;
import io.contexa.contexaiam.admin.web.auth.controller.PermissionController;
import io.contexa.contexaiam.admin.web.auth.controller.RoleController;
import io.contexa.contexaiam.admin.web.auth.controller.RoleHierarchyController;
import io.contexa.contexaiam.admin.web.auth.controller.SessionManagementController;
import io.contexa.contexaiam.admin.web.auth.controller.SystemSettingsController;
import io.contexa.contexaiam.admin.web.auth.controller.UserManagementController;
import io.contexa.contexaiam.admin.web.auth.dto.PasswordPolicyDtos.PasswordPolicyForm;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.center.AccessCenterController;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
import io.contexa.contexaiam.admin.web.center.PolicyCenterOperationsController;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleAssignmentsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateRolePermissionsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateUserGroupsRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyAiValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSnapshotResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.metadata.controller.ResourceAdminController;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceDefineResponse;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceManagementForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceMetadataForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceStatusResponse;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.admin.web.metadata.service.ResourceAdminService;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictException;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyController;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ConcurrentModel;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import io.contexa.contexacommon.entity.ManagedResource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What the console's screens and API tell an administrator when a request fails inside. A refusal the application
 * means (a name taken, a record that is not there, a state that does not allow it) is told in its own words. Anything
 * else is a fault of the server, and what an exception says of it (a statement, a constraint, a class) is the
 * operators', in the log, where the exception is kept with its stack: the administrator is told that the action could
 * not be completed. The status of the answer, the attribute or the field that carries the text are as they were.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class ConsoleErrorTextTest {

    private static final String SQL = "could not execute statement [ERROR: update or delete on table \"ctxa_role\" "
            + "violates foreign key constraint \"fk_user_roles_role\"] [delete from ctxa_role where role_id=?]";
    private static final String GENERAL = "The action could not be completed. See the server log.";
    private static final String REFUSAL = "That name is taken: ops";

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger("io.contexa.contexaiam");

    @BeforeEach
    void signInAndListen() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin-1", null, List.of()));
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void signOutAndStopListening() {
        SecurityContextHolder.clearContext();
        logger.detachAppender(logged);
    }

    // ----- JSON answers -----

    @Test
    @DisplayName("the access center: a refusal says why, a fault is a 400 that says the action could not be completed")
    void theAccessCenter() {
        AccessCenterService service = mock(AccessCenterService.class);
        AccessCenterController controller = new AccessCenterController(service);

        doThrow(new IllegalArgumentException(REFUSAL)).when(service).updateUserGroups(any(), any());
        ResponseEntity<AccessActionResponse> refused = controller.updateUserGroups(1L, new UpdateUserGroupsRequest());
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(refused.getBody()).isEqualTo(new AccessActionResponse(false, REFUSAL));

        doThrow(fault()).when(service).updateUserGroups(any(), any());
        doThrow(fault()).when(service).updateUserDirectRoles(any(), any());
        doThrow(fault()).when(service).updateGroupRoles(any(), any());
        doThrow(fault()).when(service).updateRolePermissions(any(), any());
        List<ResponseEntity<AccessActionResponse>> answers = List.of(
                controller.updateUserGroups(1L, new UpdateUserGroupsRequest()),
                controller.updateUserDirectRoles(1L, new AccessRoleAssignmentsRequest()),
                controller.updateGroupRoles(1L, new AccessRoleAssignmentsRequest()),
                controller.updateRolePermissions(1L, new UpdateRolePermissionsRequest()));
        for (ResponseEntity<AccessActionResponse> answer : answers) {
            assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(answer.getBody()).isEqualTo(new AccessActionResponse(false, GENERAL));
        }
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the policy center: a refusal says why, a fault is told in general words with the status it had")
    void thePolicyCenterApi() {
        PolicyCenterAnalysisService analysis = mock(PolicyCenterAnalysisService.class);
        PolicyCenterQueryService query = mock(PolicyCenterQueryService.class);
        PolicyCenterController center = new PolicyCenterController(messages, mock(PolicyCenterPageService.class), query,
                mock(PolicyCenterCommandService.class), analysis);
        PolicyCenterOperationsController operations = new PolicyCenterOperationsController(messages, query,
                mock(PolicyCenterCommandService.class), analysis);

        doThrow(new IllegalArgumentException(REFUSAL)).when(analysis).validatePolicy(any());
        doThrow(new IllegalArgumentException("Version not found")).when(query).getVersionSnapshot(anyLong(), anyInt());
        assertThat(center.validatePolicy(new PolicyCenterPolicyRequest()).getBody().blockedReason()).isEqualTo(REFUSAL);
        assertThat(operations.getVersionSnapshot(1L, 2).getBody().error()).isEqualTo("Version not found");

        doThrow(fault()).when(analysis).validatePolicy(any());
        doThrow(fault()).when(analysis).validateQuickPolicy(any());
        doThrow(fault()).when(analysis).validateAIPolicy(any());
        doThrow(fault()).when(query).getVersionSnapshot(anyLong(), anyInt());
        ResponseEntity<PolicyValidationResponse> validation = center.validatePolicy(new PolicyCenterPolicyRequest());
        ResponseEntity<PolicyValidationResponse> quick = center.validateQuickPolicy(new QuickPolicyRequest());
        ResponseEntity<PolicyAiValidationResponse> ai = center.validateAIPolicy(5L);
        ResponseEntity<PolicyVersionSnapshotResponse> snapshot = operations.getVersionSnapshot(1L, 2);
        assertThat(validation.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(validation.getBody().blockedReason()).isEqualTo(GENERAL);
        assertThat(quick.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(quick.getBody().blockedReason()).isEqualTo(GENERAL);
        assertThat(ai.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ai.getBody().blockedReason()).isEqualTo(GENERAL);
        assertThat(snapshot.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(snapshot.getBody().error()).isEqualTo(GENERAL);
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the resource workbench API: a refusal says why, a fault is a 400 that says the action could not be completed")
    void theResourceWorkbenchApi() {
        ResourceRegistryService registry = mock(ResourceRegistryService.class);
        ManagedResourceRepository resources = mock(ManagedResourceRepository.class);
        // Restoring takes an excluded resource back (D58): the fault comes from the registry after that check.
        when(resources.findById(1L)).thenReturn(Optional.of(ManagedResource
                .builder().id(1L).status(ManagedResource.Status.EXCLUDED).build()));
        ResourceAdminController controller = new ResourceAdminController(
                new ResourceAdminService(registry, resources, messages));

        doThrow(new IllegalArgumentException(REFUSAL)).when(registry).defineResourceAsPermission(any(), any());
        ResponseEntity<ResourceDefineResponse> refused = controller.defineResourceAsPermissionApi(1L,
                new ResourceMetadataForm());
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(refused.getBody().message()).isEqualTo(REFUSAL);

        doThrow(fault()).when(registry).defineResourceAsPermission(any(), any());
        doThrow(fault()).when(registry).updateResourceManagementStatus(any(), any());
        doThrow(fault()).when(registry).excludeResourceFromManagement(any());
        ResponseEntity<ResourceDefineResponse> define = controller.defineResourceAsPermissionApi(1L,
                new ResourceMetadataForm());
        ResponseEntity<ResourceStatusResponse> restore = controller.restoreResource(1L);
        ResponseEntity<ResourceStatusResponse> exclude = controller.excludeResource(1L);
        assertThat(define.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(define.getBody().message()).isEqualTo(GENERAL);
        assertThat(restore.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(restore.getBody().message()).isEqualTo(GENERAL);
        assertThat(exclude.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exclude.getBody().message()).isEqualTo(GENERAL);
        assertTheLogKeepsTheFault();
    }

    // ----- screens: the message flashed to the page the administrator returns to -----

    @Test
    @DisplayName("the resource workbench screens: a refusal says why, a fault is told in general words")
    void theResourceWorkbenchScreens() {
        ResourceRegistryService registry = mock(ResourceRegistryService.class);
        ResourceAdminController controller = new ResourceAdminController(
                new ResourceAdminService(registry, mock(ManagedResourceRepository.class), messages));

        doThrow(new IllegalArgumentException(REFUSAL)).when(registry).updateResourceManagementStatus(any(), any());
        RedirectAttributesModelMap refused = flash();
        controller.updateManagementStatus(1L, new ResourceManagementForm(), refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(registry).updateResourceManagementStatus(any(), any());
        doThrow(fault()).when(registry).refreshAndSynchronizeResources();
        RedirectAttributesModelMap status = flash();
        RedirectAttributesModelMap refresh = flash();
        controller.updateManagementStatus(1L, new ResourceManagementForm(), status);
        controller.refreshResources(refresh);
        assertGeneral(errorMessage(status));
        assertGeneral(errorMessage(refresh));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the policy center screen: a refusal says why, a fault is told in general words")
    void thePolicyCenterScreen() {
        PolicyCenterCommandService command = mock(PolicyCenterCommandService.class);
        PolicyCenterController controller = new PolicyCenterController(messages, mock(PolicyCenterPageService.class),
                mock(PolicyCenterQueryService.class), command, mock(PolicyCenterAnalysisService.class));

        doThrow(new IllegalStateException(REFUSAL)).when(command).refreshResources();
        RedirectAttributesModelMap refused = flash();
        controller.refreshResources(refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(command).refreshResources();
        RedirectAttributesModelMap faulted = flash();
        controller.refreshResources(faulted);
        assertGeneral(errorMessage(faulted));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the agent screens: a refusal says why, a fault is told in general words")
    void theAgentScreens() {
        AgentLearningAdminService learning = mock(AgentLearningAdminService.class);
        AgentDelegationService delegations = mock(AgentDelegationService.class);
        AgentProvisioning provisioning = mock(AgentProvisioning.class);
        AgentAdminController controller = new AgentAdminController(
                mock(AgentRegistry.class), messages, learning,
                delegations, provisioning);
        MockHttpServletRequest request = new MockHttpServletRequest();

        doThrow(new IllegalStateException(REFUSAL)).when(learning).apply(any(), any(), any(), any(), any());
        doThrow(new NoSuchElementException(REFUSAL)).when(provisioning).rotateSecret(any(), any(), any());
        RedirectAttributesModelMap learningRefused = flash();
        RedirectAttributesModelMap manageRefused = flash();
        controller.learning("agt-1", null, null, "quarantine", "why", learningRefused);
        controller.rotateSecret("agt-1", null, new ConcurrentModel(), new MockHttpServletResponse(), manageRefused);
        assertThat(errorMessage(learningRefused)).contains(REFUSAL).doesNotContain(GENERAL);
        assertThat(errorMessage(manageRefused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(learning).apply(any(), any(), any(), any(), any());
        doThrow(fault()).when(provisioning).rotateSecret(any(), any(), any());
        doThrow(fault()).when(provisioning).register(any(), any());
        doThrow(fault()).when(delegations).revokeAsAdministrator(any(), any(), any());
        RedirectAttributesModelMap learningFault = flash();
        RedirectAttributesModelMap manageFault = flash();
        RedirectAttributesModelMap revokeFault = flash();
        ConcurrentModel registration = new ConcurrentModel();
        controller.learning("agt-1", null, null, "quarantine", "why", learningFault);
        controller.rotateSecret("agt-1", null, new ConcurrentModel(), new MockHttpServletResponse(), manageFault);
        controller.register("agt-1", null, null, null, null, null, null, false, false, null, false, null, registration,
                new MockHttpServletResponse());
        controller.revokeDelegation("agt-1", null, "del-1", "why", request, revokeFault);
        assertGeneral(errorMessage(learningFault));
        assertGeneral(errorMessage(manageFault));
        assertGeneral(errorMessage(revokeFault));
        assertGeneral(String.valueOf(registration.getAttribute("errorMessage")));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the block list: a record that refuses is told in its words, a fault in general words")
    void theBlockList() {
        BlockedUserService blocks = mock(BlockedUserService.class);
        BlacklistController controller = new BlacklistController(blocks, messages);

        doThrow(new IllegalStateException(REFUSAL)).when(blocks).resolveBlockById(any(), any(), any(), any());
        RedirectAttributesModelMap refused = flash();
        controller.resolveBlock(7L, "ALLOW", "why", refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(blocks).resolveBlockById(any(), any(), any(), any());
        doThrow(fault()).when(blocks).deleteBlockRecord(any(), any());
        RedirectAttributesModelMap resolve = flash();
        RedirectAttributesModelMap delete = flash();
        controller.resolveBlock(7L, "ALLOW", "why", resolve);
        controller.deleteBlockRecord(7L, delete);
        assertGeneral(errorMessage(resolve));
        assertGeneral(errorMessage(delete));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the groups: a refusal says why, a fault is told in general words")
    void theGroups() {
        GroupService groups = mock(GroupService.class);
        GroupController controller = new GroupController(groups, mock(RoleService.class), mock(ModelMapper.class), messages);

        doThrow(new IllegalArgumentException(REFUSAL)).when(groups).createGroup(any(), any());
        RedirectAttributesModelMap refused = flash();
        controller.createGroup(new GroupDto(), List.of(), refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);
        doThrow(new IllegalStateException(REFUSAL)).when(groups).deleteGroup(any());
        RedirectAttributesModelMap deleteRefused = flash();
        controller.deleteGroup(3L, deleteRefused);
        assertThat(errorMessage(deleteRefused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(groups).createGroup(any(), any());
        doThrow(fault()).when(groups).updateGroup(any(), any());
        doThrow(fault()).when(groups).deleteGroup(any());
        when(groups.getGroup(any())).thenThrow(fault());
        RedirectAttributesModelMap create = flash();
        RedirectAttributesModelMap update = flash();
        RedirectAttributesModelMap delete = flash();
        RedirectAttributesModelMap load = flash();
        controller.createGroup(new GroupDto(), List.of(), create);
        controller.updateGroup(3L, new GroupDto(), List.of(), update);
        controller.deleteGroup(3L, delete);
        controller.getGroupDetails(3L, new ConcurrentModel(), load);
        assertGeneral(errorMessage(create));
        assertGeneral(errorMessage(update));
        assertGeneral(errorMessage(delete));
        assertGeneral(errorMessage(load));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the IP rules: a refusal says why, a fault is told in general words")
    void theIpRules() {
        IpAccessRuleService rules = mock(IpAccessRuleService.class);
        IpManagementController controller = new IpManagementController(rules, messages, mock(CsvExportService.class));

        doThrow(new IllegalArgumentException(REFUSAL)).when(rules).deleteRule(any(), any());
        RedirectAttributesModelMap refused = flash();
        controller.deleteRule(4L, new MockHttpServletRequest(), refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(rules).deleteRule(any(), any());
        doThrow(fault()).when(rules).toggleRule(any(), any());
        RedirectAttributesModelMap delete = flash();
        RedirectAttributesModelMap toggle = flash();
        controller.deleteRule(4L, new MockHttpServletRequest(), delete);
        controller.toggleRule(4L, new MockHttpServletRequest(), toggle);
        assertGeneral(errorMessage(delete));
        assertGeneral(errorMessage(toggle));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the password policy: a refusal says why, a fault is told in general words and logged with its stack")
    void thePasswordPolicy() {
        PasswordPolicyService policy = mock(PasswordPolicyService.class);
        PasswordPolicyController controller = new PasswordPolicyController(policy, messages);

        doThrow(new IllegalArgumentException(REFUSAL)).when(policy).updatePolicy(any());
        RedirectAttributesModelMap refused = flash();
        controller.updatePolicy(new PasswordPolicyForm(), refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);
        assertThat(logged.list).noneMatch(event -> event.getLevel() == Level.ERROR);

        doThrow(fault()).when(policy).updatePolicy(any());
        RedirectAttributesModelMap faulted = flash();
        controller.updatePolicy(new PasswordPolicyForm(), faulted);
        assertGeneral(errorMessage(faulted));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the permissions: a refusal says why, a fault is told in general words and logged with its stack")
    void thePermissions() {
        PermissionService permissions = mock(PermissionService.class);
        PermissionController controller = new PermissionController(permissions, mock(ModelMapper.class),
                mock(FunctionCatalogService.class), messages);

        doThrow(new IllegalStateException(REFUSAL)).when(permissions).deletePermission(any());
        RedirectAttributesModelMap refused = flash();
        controller.deletePermission(4L, refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);
        assertThat(logged.list).noneMatch(event -> event.getLevel() == Level.ERROR);

        doThrow(fault()).when(permissions).deletePermission(any());
        RedirectAttributesModelMap faulted = flash();
        controller.deletePermission(4L, faulted);
        assertGeneral(errorMessage(faulted));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the roles: a refusal says why, a fault is told in general words and logged with its stack")
    void theRoles() {
        RoleService roles = mock(RoleService.class);
        RoleController controller = new RoleController(roles, mock(PermissionService.class), mock(ModelMapper.class),
                messages);

        doThrow(new IllegalStateException(REFUSAL)).when(roles).deleteRole(anyLong());
        RedirectAttributesModelMap refused = flash();
        controller.deleteRole(5L, refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);
        assertThat(logged.list).noneMatch(event -> event.getLevel() == Level.ERROR);

        doThrow(fault()).when(roles).deleteRole(anyLong());
        RedirectAttributesModelMap faulted = flash();
        controller.deleteRole(5L, faulted);
        assertGeneral(errorMessage(faulted));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the role hierarchies: a refusal says why, a fault is told in general words")
    void theRoleHierarchies() {
        RoleHierarchyService hierarchies = mock(RoleHierarchyService.class);
        RoleHierarchyController controller = new RoleHierarchyController(hierarchies, mock(ModelMapper.class),
                mock(RoleService.class), mock(GroupService.class), messages);

        doThrow(new IllegalArgumentException(REFUSAL)).when(hierarchies).deleteRoleHierarchy(any());
        RedirectAttributesModelMap refused = flash();
        controller.deleteRoleHierarchy(6L, refused);
        assertThat(String.valueOf(refused.getFlashAttributes().get("error"))).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(hierarchies).deleteRoleHierarchy(any());
        RedirectAttributesModelMap faulted = flash();
        controller.deleteRoleHierarchy(6L, faulted);
        assertGeneral(String.valueOf(faulted.getFlashAttributes().get("error")));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the sessions: a refusal says why, a fault is told in general words")
    void theSessions() {
        SessionManagementService sessions = mock(SessionManagementService.class);
        SessionManagementController controller = new SessionManagementController(sessions, messages,
                mock(CsvExportService.class));

        doThrow(new IllegalArgumentException(REFUSAL)).when(sessions).invalidateSession(any());
        RedirectAttributesModelMap refused = flash();
        controller.invalidateSession("s-1", refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);

        doThrow(fault()).when(sessions).invalidateSession(any());
        doThrow(fault()).when(sessions).invalidateAllSessionsForUser(any());
        RedirectAttributesModelMap one = flash();
        RedirectAttributesModelMap all = flash();
        controller.invalidateSession("s-1", one);
        controller.invalidateAllForUser("u-1", all);
        assertGeneral(errorMessage(one));
        assertGeneral(errorMessage(all));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the system settings: a refusal says why, a fault is told in general words and logged with its stack")
    void theSystemSettings() {
        SystemSettingsService settings = mock(SystemSettingsService.class);
        SystemSettingsController controller = new SystemSettingsController(settings,
                mock(PolicyCombiningProperties.class), messages, null,
                null);

        doThrow(new IllegalArgumentException(REFUSAL)).when(settings).updateSettings(any());
        RedirectAttributesModelMap refused = flash();
        controller.updateSettings(new SystemSettingsForm(), refused);
        assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);
        assertThat(logged.list).noneMatch(event -> event.getLevel() == Level.ERROR);

        doThrow(fault()).when(settings).updateSettings(any());
        RedirectAttributesModelMap faulted = flash();
        controller.updateSettings(new SystemSettingsForm(), faulted);
        assertGeneral(errorMessage(faulted));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the users: a refusal says why, a fault is told in general words")
    void theUsers() {
        UserManagementService users = mock(UserManagementService.class);
        UserManagementController controller = new UserManagementController(users, mock(RoleService.class),
                mock(GroupService.class), mock(PasswordPolicyService.class), messages);

        doThrow(new IllegalArgumentException(REFUSAL)).when(users).modifyUser(any());
        doThrow(new IllegalArgumentException(REFUSAL)).when(users).createUser(any());
        RedirectAttributesModelMap updateRefused = flash();
        ConcurrentModel createRefused = new ConcurrentModel();
        controller.updateUser(7L, new UserDto(), List.of(), updateRefused);
        controller.createUser(new UserDto(), List.of(), createRefused, flash());
        assertThat(errorMessage(updateRefused)).contains(REFUSAL).doesNotContain(GENERAL);
        assertThat(String.valueOf(createRefused.getAttribute("errorMessage"))).isEqualTo(REFUSAL);

        doThrow(fault()).when(users).modifyUser(any());
        doThrow(fault()).when(users).createUser(any());
        doThrow(fault()).when(users).deleteUser(any());
        when(users.findUser(any())).thenThrow(fault());
        RedirectAttributesModelMap update = flash();
        ConcurrentModel create = new ConcurrentModel();
        RedirectAttributesModelMap delete = flash();
        RedirectAttributesModelMap load = flash();
        controller.updateUser(7L, new UserDto(), List.of(), update);
        controller.createUser(new UserDto(), List.of(), create, flash());
        controller.removeUser(7L, delete);
        controller.getUser(7L, new ConcurrentModel(), load);
        assertGeneral(errorMessage(update));
        assertThat(String.valueOf(create.getAttribute("errorMessage"))).isEqualTo(GENERAL);
        assertGeneral(errorMessage(delete));
        assertGeneral(errorMessage(load));
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("the policies: a refusal and a conflict say why, a fault is told in general words")
    void thePolicies() {
        PolicyService policies = mock(PolicyService.class);
        PolicyController controller = new PolicyController(policies, mock(ModelMapper.class), messages);

        doThrow(new PolicyConflictException(REFUSAL, List.of())).when(policies).createPolicy(any());
        doThrow(new IllegalArgumentException(REFUSAL)).when(policies).updatePolicy(any());
        doThrow(new IllegalStateException(REFUSAL)).when(policies).approvePolicy(anyLong(), anyString());
        doThrow(new IllegalStateException(REFUSAL)).when(policies).rejectPolicy(anyLong(), anyString());
        doThrow(new IllegalArgumentException(REFUSAL)).when(policies).deletePolicy(anyLong(), any());
        List<RedirectAttributesModelMap> refusals = List.of(flash(), flash(), flash(), flash(), flash());
        controller.createPolicy(new PolicyDto(), refusals.get(0));
        controller.updatePolicy(8L, new PolicyDto(), refusals.get(1));
        controller.approvePolicy(8L, refusals.get(2));
        controller.rejectPolicy(8L, refusals.get(3));
        controller.deletePolicy(8L, null, refusals.get(4));
        for (RedirectAttributesModelMap refused : refusals) {
            assertThat(errorMessage(refused)).contains(REFUSAL).doesNotContain(GENERAL);
        }

        doThrow(fault()).when(policies).createPolicy(any());
        doThrow(fault()).when(policies).updatePolicy(any());
        doThrow(fault()).when(policies).approvePolicy(anyLong(), anyString());
        doThrow(fault()).when(policies).rejectPolicy(anyLong(), anyString());
        doThrow(fault()).when(policies).deletePolicy(anyLong(), any());
        List<RedirectAttributesModelMap> faults = List.of(flash(), flash(), flash(), flash(), flash());
        controller.createPolicy(new PolicyDto(), faults.get(0));
        controller.updatePolicy(8L, new PolicyDto(), faults.get(1));
        controller.approvePolicy(8L, faults.get(2));
        controller.rejectPolicy(8L, faults.get(3));
        controller.deletePolicy(8L, null, faults.get(4));
        for (RedirectAttributesModelMap faulted : faults) {
            assertGeneral(errorMessage(faulted));
        }
        assertTheLogKeepsTheFault();
    }

    @Test
    @DisplayName("a value that is no constant of an enum is told as an action that could not be completed, with the 400 it had")
    void aValueThatIsNoConstantOfAnEnum() {
        PolicyCenterAnalysisService analysis = new PolicyCenterAnalysisService(mock(PolicyService.class),
                mock(PolicyValidationService.class), mock(PermissionRepository.class), mock(PolicyMatrixService.class));
        PolicyCenterController center = new PolicyCenterController(messages, mock(PolicyCenterPageService.class),
                mock(PolicyCenterQueryService.class), mock(PolicyCenterCommandService.class), analysis);
        PolicyCenterPolicyRequest policy = new PolicyCenterPolicyRequest();
        policy.setEffect("BOGUS");

        ResponseEntity<PolicyValidationResponse> validation = center.validatePolicy(policy);

        assertThat(validation.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(validation.getBody().blockedReason()).isEqualTo(GENERAL);
        assertThat(logged.list).anySatisfy(event -> assertThat(event.getThrowableProxy().getMessage())
                .startsWith("No enum constant "));

        ResourceRegistryService registry = mock(ResourceRegistryService.class);
        ResourceAdminController resources = new ResourceAdminController(
                new ResourceAdminService(registry, mock(ManagedResourceRepository.class), messages));
        ResourceManagementForm form = new ResourceManagementForm();
        form.setStatus("BOGUS");
        RedirectAttributesModelMap flash = flash();

        resources.updateManagementStatus(1L, form, flash);

        assertGeneral(errorMessage(flash));
        assertThat(errorMessage(flash)).doesNotContain("No enum constant");
    }

    // ----- helpers -----

    private static RuntimeException fault() {
        return new DataAccessResourceFailureException(SQL);
    }

    private static RedirectAttributesModelMap flash() {
        return new RedirectAttributesModelMap();
    }

    private static String errorMessage(RedirectAttributesModelMap flash) {
        return String.valueOf(flash.getFlashAttributes().get("errorMessage"));
    }

    /** The page says that the action could not be completed, and nothing of what the exception said of it. */
    private static void assertGeneral(String shown) {
        assertThat(shown).contains(GENERAL).doesNotContain("ctxa_", "fk_user_roles_role", "statement", "Exception");
    }

    private void assertTheLogKeepsTheFault() {
        assertThat(logged.list).anySatisfy(event -> {
            assertThat(event.getThrowableProxy()).isNotNull();
            assertThat(event.getThrowableProxy().getMessage()).isEqualTo(SQL);
        });
    }
}
