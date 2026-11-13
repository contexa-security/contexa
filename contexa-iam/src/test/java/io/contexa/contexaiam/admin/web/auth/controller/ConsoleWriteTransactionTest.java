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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.auth.service.impl.GroupServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.PermissionServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleServiceImpl;
import io.contexa.contexaiam.admin.web.auth.service.impl.UserManagementServiceImpl;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexaiam.domain.dto.RoleHierarchyDto;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.ui.ConcurrentModel;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A console form that fails with a message the page can show (a password the policy refuses, a role a hierarchy still
 * names, a duplicate) answers with that message. The controllers run on Spring's real transaction proxies over the
 * real services, with only the repositories and the connection faked: a controller method that opens a transaction of
 * its own and catches the exception of a service that joined it leaves the transaction marked for rollback, so its
 * commit fails with an {@code UnexpectedRollbackException} and the page the person was to see is an error instead.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class ConsoleWriteTransactionTest {

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final ModelMapper mapper = mock(ModelMapper.class);
    private final Connection connection = mock(Connection.class);

    private final RoleRepository roles = mock(RoleRepository.class);
    private final GroupRepository groups = mock(GroupRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final PermissionRepository permissions = mock(PermissionRepository.class);
    private final RoleHierarchyRepository hierarchies = mock(RoleHierarchyRepository.class);
    private final PasswordPolicyService passwordPolicy = mock(PasswordPolicyService.class);
    private final LastAdministratorGuard guard = mock(LastAdministratorGuard.class);

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

        RoleServiceImpl roleService = new RoleServiceImpl(roles, permissions, mock(IntegrationEventBus.class),
                mock(CentralAuditFacade.class), hierarchies, mock(PolicyRepository.class),
                mock(PolicySynchronizationService.class), messages, guard);
        console.registerBean("roleService", RoleService.class, () -> roleService);
        GroupServiceImpl groupService = new GroupServiceImpl(groups, roles, hierarchies, messages, guard);
        console.registerBean("groupService", GroupService.class, () -> groupService);
        PermissionServiceImpl permissionService = new PermissionServiceImpl(permissions,
                mock(ManagedResourceRepository.class), mock(PolicyRepository.class),
                messages, guard);
        console.registerBean("permissionService", PermissionService.class, () -> permissionService);
        UserManagementServiceImpl userService = new UserManagementServiceImpl(users, groups, roles,
                mock(PasswordEncoder.class), mock(ModelMapper.class), mock(CentralAuditFacade.class), passwordPolicy,
                mock(SystemSettingsService.class), messages, mock(UserRolePermissionRepository.class),
                mock(BridgeUserProfileRepository.class), mock(ApplicationEventPublisher.class),
                guard);
        console.registerBean("userManagementService", UserManagementService.class, () -> userService);
        RoleHierarchyService hierarchyService = new RoleHierarchyService(hierarchies, roles, new RoleHierarchyImpl(),
                messages, guard);
        console.registerBean("roleHierarchyService", RoleHierarchyService.class, () -> hierarchyService);

        console.registerBean("roleController", RoleController.class,
                () -> new RoleController(console.getBean(RoleService.class), console.getBean(PermissionService.class),
                        mapper, messages));
        console.registerBean("groupController", GroupController.class,
                () -> new GroupController(console.getBean(GroupService.class), console.getBean(RoleService.class),
                        mapper, messages));
        console.registerBean("userController", UserManagementController.class,
                () -> new UserManagementController(console.getBean(UserManagementService.class),
                        console.getBean(RoleService.class), console.getBean(GroupService.class), passwordPolicy,
                        messages));
        console.registerBean("hierarchyController", RoleHierarchyController.class,
                () -> new RoleHierarchyController(console.getBean(RoleHierarchyService.class), mapper,
                        console.getBean(RoleService.class), console.getBean(GroupService.class), messages));
        console.registerBean("permissionController", PermissionController.class,
                () -> new PermissionController(console.getBean(PermissionService.class), mapper,
                        mock(FunctionCatalogService.class), messages));
        console.refresh();
        // Starting the context reloads the role hierarchy once, in a read-only transaction of its own.
        clearInvocations(connection);
    }

    @AfterEach
    void close() {
        console.close();
    }

    @Test
    @DisplayName("a role a hierarchy still names is refused with that message, not with a failed commit")
    void deletingARoleAHierarchyStillNames() throws Exception {
        Role sales = Role.builder().id(5L).roleName("ROLE_SALES").build();
        when(roles.findById(5L)).thenReturn(Optional.of(sales));
        when(hierarchies.findAllByIsActiveTrue()).thenReturn(List.of(RoleHierarchyEntity.builder().id(2L)
                .hierarchyString("ROLE_BOSS > ROLE_SALES").description("sales line").isActive(true).build()));
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(RoleController.class).deleteRole(5L, flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/roles");
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("ROLE_SALES");
        verify(roles, never()).deleteById(anyLong());
        verify(connection, never()).commit();
    }

    @Test
    @DisplayName("a role nobody names is deleted and the deletion is committed once")
    void deletingARoleNobodyNames() throws Exception {
        Role sales = Role.builder().id(5L).roleName("ROLE_SALES").build();
        when(roles.findById(5L)).thenReturn(Optional.of(sales));
        when(hierarchies.findAllByIsActiveTrue()).thenReturn(List.of());
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(RoleController.class).deleteRole(5L, flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/roles");
        assertThat(flash.getFlashAttributes()).containsKey("message");
        verify(roles).deleteById(5L);
        verify(connection, times(1)).commit();
    }

    @Test
    @DisplayName("a password the policy refuses is told to the person on the user's page")
    void aPasswordThePolicyRefuses() throws Exception {
        Users alice = Users.builder().id(7L).username("alice").enabled(true).build();
        when(users.findByIdWithGroupsRolesAndPermissions(7L)).thenReturn(Optional.of(alice));
        when(passwordPolicy.validatePassword("short")).thenReturn(List.of("at least 12 characters"));
        UserDto form = new UserDto();
        form.setUsername("alice");
        form.setName("Alice");
        form.setEmail("alice@example.com");
        form.setPassword("short");
        form.setEnabled(true);
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(UserManagementController.class).updateUser(7L, form, null, flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/users/7");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("at least 12 characters");
        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("a user name taken is told to the person on the form")
    void aUserNameTaken() throws Exception {
        when(users.findByUsername("alice")).thenReturn(Optional.of(Users.builder().id(7L).username("alice").build()));
        when(roles.findAllRolesWithoutExpression()).thenReturn(List.of());
        when(groups.findAllWithRolesAndUsers()).thenReturn(List.of());
        UserDto form = new UserDto();
        form.setUsername("alice");
        form.setName("Alice");
        form.setEmail("alice@example.com");
        ConcurrentModel model = new ConcurrentModel();

        String view = console.getBean(UserManagementController.class).createUser(form, null, model,
                new RedirectAttributesModelMap());

        assertThat(view).isEqualTo("contexa/admin/userdetails");
        assertThat(String.valueOf(model.getAttribute("errorMessage"))).contains("alice");
    }

    @Test
    @DisplayName("a group role that does not exist is told to the person, not met with a failed commit")
    void aGroupRoleThatDoesNotExist() throws Exception {
        Group staff = Group.builder().id(3L).name("staff").build();
        when(groups.findByIdWithRoles(3L)).thenReturn(Optional.of(staff));
        when(roles.findAllById(any())).thenReturn(List.of());
        GroupDto form = new GroupDto();
        form.setName("staff");
        when(mapper.map(any(GroupDto.class), eq(Group.class))).thenReturn(staff);
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(GroupController.class).updateGroup(3L, form, List.of(99L), flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/groups");
        assertThat(flash.getFlashAttributes()).doesNotContainKey("message");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).isNotBlank();
        verify(groups, never()).save(any());
    }

    @Test
    @DisplayName("a hierarchy that exists already is told to the person on the form")
    void aHierarchyThatExistsAlready() throws Exception {
        RoleHierarchyEntity existing = RoleHierarchyEntity.builder().id(2L).hierarchyString("ROLE_A > ROLE_B")
                .description("A over B").build();
        when(hierarchies.findByHierarchyString("ROLE_A > ROLE_B")).thenReturn(Optional.of(existing));
        when(mapper.map(any(RoleHierarchyDto.class), eq(RoleHierarchyEntity.class))).thenReturn(existing);
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(RoleHierarchyController.class).createRoleHierarchy(new RoleHierarchyDto(), flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/role-hierarchies/register");
        assertThat(flash.getFlashAttributes()).containsKey("error");
    }

    @Test
    @DisplayName("a permission that cannot be deleted is told to the person (the controller opens no transaction of its own)")
    void aPermissionThatCannotBeDeleted() throws Exception {
        when(permissions.countRoleAssignments(4L)).thenReturn(2L);
        RedirectAttributesModelMap flash = new RedirectAttributesModelMap();

        String view = console.getBean(PermissionController.class).deletePermission(4L, flash);

        assertThat(view).isEqualTo("redirect:/contexa/admin/permissions");
        assertThat(String.valueOf(flash.getFlashAttributes().get("errorMessage"))).contains("assigned to 2 role(s)");
    }
}
