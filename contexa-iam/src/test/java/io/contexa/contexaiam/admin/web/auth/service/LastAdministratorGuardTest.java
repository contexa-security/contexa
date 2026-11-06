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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.repository.UserRoleRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.impl.UserManagementServiceImpl;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleAssignmentsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateUserGroupsRequest;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * A change of a user that takes the console's last active administrator is refused with a 409, on every path that
 * changes a user: the user's form (groups, enabled), the access center (groups, direct roles) and the deletion. An
 * administrator by the role hierarchy counts as one; a change that leaves another active administrator goes on.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class LastAdministratorGuardTest {

    private final UserRepository users = mock(UserRepository.class);
    private final GroupRepository groups = mock(GroupRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final ApplicationEventPublisher events = mock(ApplicationEventPublisher.class);
    private final UserRolePermissionRepository userRolePermissions = mock(UserRolePermissionRepository.class);

    private final Role admin = role(1L, "ROLE_ADMIN");
    private final Role supervisor = role(3L, "ROLE_SUPERVISOR");
    private final Role member = role(5L, "ROLE_USER");
    private final Role deputy = disabled(role(8L, "ROLE_DEPUTY"));
    private final Group administrators = group(10L, admin);
    private final Group supervisors = group(11L, supervisor);
    private final Group staff = group(12L, member);
    private final Group deputies = group(13L, deputy);

    private UserManagementServiceImpl userManagement;
    private AccessCenterService accessCenter;

    @BeforeEach
    void aConsole() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_SUPERVISOR > ROLE_ADMIN\nROLE_DEPUTY > ROLE_ADMIN");
        LastAdministratorGuard guard = new LastAdministratorGuard(users, roles, hierarchy,
                I18nTestSupport.englishMessageSource());
        userManagement = new UserManagementServiceImpl(users, groups, roles, mock(PasswordEncoder.class),
                mock(ModelMapper.class), audit, mock(PasswordPolicyService.class), mock(SystemSettingsService.class),
                I18nTestSupport.englishMessageSource(), userRolePermissions, mock(BridgeUserProfileRepository.class),
                events, guard);
        accessCenter = new AccessCenterService(users, mock(UserRoleRepository.class), groups, roles,
                mock(PermissionRepository.class), mock(RoleService.class), userRolePermissions,
                mock(GroupRolePermissionRepository.class), guard);
        when(roles.findAll()).thenReturn(List.of(admin, supervisor, member, deputy));
        when(roles.findById(1L)).thenReturn(Optional.of(admin));
        when(roles.findById(5L)).thenReturn(Optional.of(member));
        for (Group group : List.of(administrators, supervisors, staff, deputies)) {
            when(groups.findById(group.getId())).thenReturn(Optional.of(group));
        }
    }

    @Test
    void takingTheGroupOfTheLastAdministratorIsRefused() {
        Users root = account(1L, "root", administrators);
        noOtherAdministrator();

        assertThatThrownBy(() -> userManagement.modifyUser(form(root, true, 12L)))
                .isInstanceOf(LastAdministratorException.class)
                .hasMessageContaining("without an active administrator");

        verify(users, never()).save(any());
        verifyNoInteractions(events);
    }

    @Test
    void disablingTheLastAdministratorIsRefused() {
        Users root = account(1L, "root", administrators);
        noOtherAdministrator();

        assertThatThrownBy(() -> userManagement.modifyUser(form(root, false, 10L)))
                .isInstanceOf(LastAdministratorException.class);

        verify(users, never()).save(any());
        verifyNoInteractions(events);
    }

    @Test
    void deletingTheLastAdministratorIsRefusedAndNothingIsRecordedAsDeleted() {
        account(1L, "root", administrators);
        noOtherAdministrator();

        assertThatThrownBy(() -> userManagement.deleteUser(1L)).isInstanceOf(LastAdministratorException.class);

        verify(users, never()).deleteById(anyLong());
        verify(userRolePermissions, never()).deleteByUserId(anyLong());
        verifyNoInteractions(audit, events);
    }

    @Test
    void theAccessCenterRefusesTheSameChanges() {
        account(1L, "root", administrators);
        noOtherAdministrator();
        UpdateUserGroupsRequest noGroups = new UpdateUserGroupsRequest();
        noGroups.setGroupIds(List.of(12L));

        assertThatThrownBy(() -> accessCenter.updateUserGroups(1L, noGroups))
                .isInstanceOf(LastAdministratorException.class);

        Users direct = account(2L, "direct-admin");
        direct.getUserRoles().add(UserRole.builder().user(direct).role(admin).build());
        when(users.countEnabledOwnAccountsHoldingAnyRole(eq(2L), any())).thenReturn(0L);
        AccessRoleAssignmentsRequest memberOnly = new AccessRoleAssignmentsRequest();
        memberOnly.setRoleIds(List.of(5L));

        assertThatThrownBy(() -> accessCenter.updateUserDirectRoles(2L, memberOnly))
                .isInstanceOf(LastAdministratorException.class);
        verify(users, never()).save(any());
    }

    @Test
    void anAdministratorByTheRoleHierarchyIsOne() {
        Users chief = account(1L, "chief", supervisors);
        noOtherAdministrator();

        assertThatThrownBy(() -> userManagement.modifyUser(form(chief, true, 12L)))
                .isInstanceOf(LastAdministratorException.class);
    }

    @Test
    void withAnotherActiveAdministratorTheChangeGoesOn() {
        Users root = account(1L, "root", administrators);
        when(users.countEnabledOwnAccountsHoldingAnyRole(eq(1L), argThat(LastAdministratorGuardTest::adminRoles)))
                .thenReturn(1L);

        userManagement.modifyUser(form(root, false, 12L));
        userManagement.deleteUser(1L);

        verify(users).save(root);
        verify(users).deleteById(1L);
    }

    @Test
    void aChangeThatKeepsTheAdministratorOrConcernsAnotherUserGoesOn() {
        Users root = account(1L, "root", administrators);
        Users carol = account(2L, "carol", staff);
        noOtherAdministrator();
        when(users.countEnabledOwnAccountsHoldingAnyRole(eq(2L), any())).thenReturn(0L);

        userManagement.modifyUser(form(root, true, 10L, 12L));
        userManagement.modifyUser(form(carol, false));
        userManagement.deleteUser(2L);

        verify(users).save(root);
        verify(users).save(carol);
        verify(users).deleteById(2L);
    }

    @Test
    void aDisabledRoleAndAnAccountOfTheApplicationMakeNoAdministrator() {
        // A disabled role grants nothing, whatever the hierarchy says it reaches.
        Users stand = account(3L, "stand-in", deputies);
        // An application's user mirrored into Contexa is no console administrator.
        Users mirror = account(4L, "mirror", administrators);
        mirror.setBridgeManaged(true);
        when(users.countEnabledOwnAccountsHoldingAnyRole(anyLong(), any())).thenReturn(0L);

        userManagement.modifyUser(form(stand, false));
        userManagement.modifyUser(form(mirror, false));

        verify(users).save(stand);
        verify(users).save(mirror);
    }

    private void noOtherAdministrator() {
        when(users.countEnabledOwnAccountsHoldingAnyRole(eq(1L), argThat(LastAdministratorGuardTest::adminRoles)))
                .thenReturn(0L);
    }

    /** The roles that make an administrator: the administrator role, and the one above it in the hierarchy. */
    private static boolean adminRoles(Collection<Long> ids) {
        return ids != null && ids.contains(1L) && ids.contains(3L) && !ids.contains(5L) && !ids.contains(8L);
    }

    private Users account(Long id, String username, Group... memberOf) {
        Users user = Users.builder().id(id).username(username).name(username).email(username + "@test.com")
                .password("encoded").enabled(true).userGroups(new HashSet<>()).userRoles(new HashSet<>()).build();
        for (Group group : memberOf) {
            user.getUserGroups().add(UserGroup.builder().user(user).group(group).build());
        }
        when(users.findByIdWithGroupsRolesAndPermissions(id)).thenReturn(Optional.of(user));
        when(users.findById(id)).thenReturn(Optional.of(user));
        return user;
    }

    private static UserDto form(Users user, boolean enabled, Long... groupIds) {
        return UserDto.builder().id(user.getId()).username(user.getUsername()).name(user.getName())
                .email(user.getEmail()).enabled(enabled).selectedGroupIds(List.of(groupIds)).build();
    }

    private static Role role(Long id, String name) {
        return Role.builder().id(id).roleName(name).enabled(true).build();
    }

    private static Role disabled(Role role) {
        role.setEnabled(false);
        return role;
    }

    private static Group group(Long id, Role role) {
        Group group = Group.builder().id(id).name("group-" + id).build();
        group.getGroupRoles().add(GroupRole.builder().group(group).role(role).build());
        return group;
    }
}
