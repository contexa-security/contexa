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
import io.contexa.contexacommon.entity.Role;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.mockito.InOrder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What the guard does for the changes of roles, groups and the role hierarchy: it takes the lock first, it reads the
 * administrators before and after, and it refuses a change that leaves none. The user's own changes and the access
 * center take the lock before they read anything.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class LastAdministratorGuardRolesTest {

    private static final String SUPERVISORS_ARE_ADMINISTRATORS = "ROLE_SUPERVISOR > ROLE_ADMIN";

    private final UserRepository users = mock(UserRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private final GroupRepository groups = mock(GroupRepository.class);

    private final Role admin = role(1L, "ROLE_ADMIN");
    private final Role supervisor = role(3L, "ROLE_SUPERVISOR");
    private final Role member = role(5L, "ROLE_USER");

    private LastAdministratorGuard guard;

    @BeforeEach
    void aConsole() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy(SUPERVISORS_ARE_ADMINISTRATORS);
        guard = new LastAdministratorGuard(users, roles, hierarchy, I18nTestSupport.englishMessageSource());
        when(roles.findAll()).thenReturn(List.of(admin, supervisor, member));
        // "root" holds the supervisor role only: it is an administrator while the hierarchy puts that role over ROLE_ADMIN
        when(users.findEnabledOwnUsernamesHoldingAnyRole(anyCollection(), any(Pageable.class))).thenAnswer(call -> {
            Collection<Long> roleIds = call.getArgument(0);
            return roleIds.contains(supervisor.getId()) ? List.of("root") : List.<String>of();
        });
    }

    @Test
    @DisplayName("a hierarchy that places a role above ROLE_ADMIN is refused with the roles it would make administrators")
    void aRoleAboveTheAdministratorIsRefused() {
        assertThatThrownBy(() -> guard.refuseRolesAboveAdministrator("ROLE_ADMIN > ROLE_SUPERVISOR\nROLE_USER > ROLE_ADMIN"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("above ROLE_ADMIN").hasMessageContaining("ROLE_USER");
        // Through another role as well: the user role reaches ROLE_ADMIN by the supervisor.
        assertThatThrownBy(() -> guard.refuseRolesAboveAdministrator("ROLE_USER > ROLE_SUPERVISOR\nROLE_SUPERVISOR > ROLE_ADMIN"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ROLE_SUPERVISOR, ROLE_USER");
    }

    @Test
    @DisplayName("a hierarchy below ROLE_ADMIN, or none, goes on")
    void aHierarchyBelowTheAdministratorGoesOn() {
        guard.refuseRolesAboveAdministrator("ROLE_ADMIN > ROLE_SUPERVISOR\nROLE_SUPERVISOR > ROLE_USER");
        guard.refuseRolesAboveAdministrator("");
        guard.refuseRolesAboveAdministrator(null);
    }

    @Test
    @DisplayName("the lock is the rows of the roles")
    void theLockIsTheRoles() {
        guard.serializeChanges();

        verify(roles).findAllForUpdate();
    }

    @Test
    @DisplayName("the administrators are named by the roles that grant ROLE_ADMIN, by the hierarchy too")
    void theAdministratorsAreNamed() {
        assertThat(guard.administrators()).containsExactly("root");

        when(roles.findAll()).thenReturn(List.of(member));
        assertThat(guard.administrators()).isEmpty();
    }

    @Test
    @DisplayName("a change that leaves no administrator is refused with the accounts that lose the role named")
    void aChangeThatLeavesNoneIsRefused() {
        List<String> before = guard.administrators();
        when(roles.findAll()).thenReturn(List.of(admin, member));

        assertThatThrownBy(() -> guard.refuseLosingEveryAdministrator(before))
                .isInstanceOf(LastAdministratorException.class)
                .hasMessageContaining("without an active administrator").hasMessageContaining("root");
    }

    @Test
    @DisplayName("a change that leaves an administrator goes on, and so does one on a console that had none")
    void aChangeThatLeavesOneGoesOn() {
        List<String> before = guard.administrators();

        assertThatCode(() -> guard.refuseLosingEveryAdministrator(before)).doesNotThrowAnyException();
        assertThatCode(() -> guard.refuseLosingEveryAdministrator(List.of())).doesNotThrowAnyException();
        assertThatCode(() -> guard.refuseLosingEveryAdministrator(null)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a hierarchy that no longer puts the supervisors over ROLE_ADMIN is refused, one that still does is not")
    void theHierarchyAfterTheChangeIsTheOneRead() {
        List<String> before = guard.administrators();

        assertThatThrownBy(() -> guard.refuseLosingEveryAdministrator(before, ""))
                .isInstanceOf(LastAdministratorException.class).hasMessageContaining("root");
        assertThatThrownBy(() -> guard.refuseLosingEveryAdministrator(before, "ROLE_SUPERVISOR > ROLE_USER"))
                .isInstanceOf(LastAdministratorException.class);
        assertThatCode(() -> guard.refuseLosingEveryAdministrator(before, SUPERVISORS_ARE_ADMINISTRATORS))
                .doesNotThrowAnyException();
        // The text of a stored hierarchy keeps its lines apart with a newline written as two characters.
        assertThatCode(() -> guard.refuseLosingEveryAdministrator(before,
                "ROLE_USER > ROLE_USER2\\nROLE_SUPERVISOR > ROLE_ADMIN")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a user's change and the access center take the lock before they read anything")
    void theLockComesFirst() {
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        UserRolePermissionRepository userRolePermissions = mock(UserRolePermissionRepository.class);
        UserManagementServiceImpl userManagement = new UserManagementServiceImpl(users, groups, roles, encoder,
                mock(ModelMapper.class), mock(CentralAuditFacade.class), mock(PasswordPolicyService.class),
                mock(SystemSettingsService.class), I18nTestSupport.englishMessageSource(), userRolePermissions,
                mock(BridgeUserProfileRepository.class), mock(ApplicationEventPublisher.class), guard);
        AccessCenterService accessCenter = new AccessCenterService(users, mock(UserRoleRepository.class), groups, roles,
                mock(PermissionRepository.class), mock(RoleService.class), userRolePermissions,
                mock(GroupRolePermissionRepository.class), guard);
        UserDto form = new UserDto();
        form.setId(7L);

        assertThatThrownBy(() -> userManagement.modifyUser(form)).isInstanceOf(IllegalArgumentException.class);
        userManagement.deleteUser(7L);
        assertThatThrownBy(() -> accessCenter.updateUserGroups(7L, new UpdateUserGroupsRequest()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> accessCenter.updateUserDirectRoles(7L, new AccessRoleAssignmentsRequest()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> accessCenter.updateGroupRoles(3L, new AccessRoleAssignmentsRequest()))
                .isInstanceOf(IllegalArgumentException.class);

        InOrder order = inOrder(roles, users, groups);
        order.verify(roles).findAllForUpdate();
        order.verify(users).findByIdWithGroupsRolesAndPermissions(7L);
        order.verify(roles).findAllForUpdate();
        order.verify(users).findById(7L);
        order.verify(roles).findAllForUpdate();
        order.verify(users).findById(7L);
        order.verify(roles).findAllForUpdate();
        order.verify(users).findById(7L);
        order.verify(roles).findAllForUpdate();
        order.verify(groups).findById(3L);
    }

    private static Role role(long id, String name) {
        return Role.builder().id(id).roleName(name).build();
    }
}
