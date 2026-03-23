package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RoleServiceImplTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private IntegrationEventBus eventBus;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    @Mock
    private RoleHierarchyRepository roleHierarchyRepository;

    @InjectMocks
    private RoleServiceImpl service;

    // ===== Helper methods =====

    private Role buildRole(Long id, String roleName) {
        return Role.builder()
                .id(id)
                .roleName(roleName)
                .roleDesc("Test role")
                .isExpression(false)
                .enabled(true)
                .rolePermissions(new HashSet<>())
                .build();
    }

    private Permission buildPermission(Long id, String name) {
        return Permission.builder()
                .id(id)
                .name(name)
                .build();
    }

    private RoleHierarchyEntity buildHierarchy(Long id, String hierarchyString, boolean active) {
        return RoleHierarchyEntity.builder()
                .id(id)
                .hierarchyString(hierarchyString)
                .description("Test hierarchy")
                .isActive(active)
                .build();
    }

    // =========================================================================
    // getRoles
    // =========================================================================

    @Nested
    @DisplayName("getRoles")
    class GetRoles {

        @Test
        @DisplayName("should return all roles with permissions")
        void shouldReturnAll() {
            Role r1 = buildRole(1L, "ROLE_ADMIN");
            Role r2 = buildRole(2L, "ROLE_USER");
            when(roleRepository.findAllWithPermissions()).thenReturn(List.of(r1, r2));

            List<Role> result = service.getRoles();

            assertThat(result).hasSize(2);
            verify(roleRepository).findAllWithPermissions();
        }

        @Test
        @DisplayName("should return empty list when no roles")
        void shouldReturnEmpty() {
            when(roleRepository.findAllWithPermissions()).thenReturn(Collections.emptyList());

            List<Role> result = service.getRoles();

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // getRolesWithoutExpression
    // =========================================================================

    @Nested
    @DisplayName("getRolesWithoutExpression")
    class GetRolesWithoutExpression {

        @Test
        @DisplayName("should return only non-expression roles")
        void shouldReturnNonExpression() {
            Role r1 = buildRole(1L, "ROLE_ADMIN");
            when(roleRepository.findAllRolesWithoutExpression()).thenReturn(List.of(r1));

            List<Role> result = service.getRolesWithoutExpression();

            assertThat(result).hasSize(1);
            assertThat(result.get(0).getRoleName()).isEqualTo("ROLE_ADMIN");
        }
    }

    // =========================================================================
    // getRole
    // =========================================================================

    @Nested
    @DisplayName("getRole")
    class GetRole {

        @Test
        @DisplayName("should return role with permissions when found")
        void shouldReturnRole() {
            Role role = buildRole(1L, "ROLE_ADMIN");
            when(roleRepository.findByIdWithPermissions(1L)).thenReturn(Optional.of(role));

            Role result = service.getRole(1L);

            assertThat(result).isNotNull();
            assertThat(result.getRoleName()).isEqualTo("ROLE_ADMIN");
        }

        @Test
        @DisplayName("should throw when role not found")
        void shouldThrowWhenNotFound() {
            when(roleRepository.findByIdWithPermissions(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.getRole(999L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Role not found");
        }
    }

    // =========================================================================
    // searchRoles
    // =========================================================================

    @Nested
    @DisplayName("searchRoles")
    class SearchRoles {

        @Test
        @DisplayName("should return paged results")
        void shouldReturnPagedResults() {
            Role role = buildRole(1L, "ROLE_ADMIN");
            Pageable pageable = PageRequest.of(0, 10);
            Page<Role> page = new PageImpl<>(List.of(role), pageable, 1);
            when(roleRepository.searchByKeyword("admin", pageable)).thenReturn(page);

            Page<Role> result = service.searchRoles("admin", pageable);

            assertThat(result.getTotalElements()).isEqualTo(1);
            assertThat(result.getContent().get(0).getRoleName()).isEqualTo("ROLE_ADMIN");
        }
    }

    // =========================================================================
    // createRole
    // =========================================================================

    @Nested
    @DisplayName("createRole")
    class CreateRole {

        @Test
        @DisplayName("should create role with permissions")
        void shouldCreateWithPermissions() {
            Role role = buildRole(null, "ROLE_NEW");
            Permission perm = buildPermission(1L, "READ");
            when(roleRepository.findByRoleName("ROLE_NEW")).thenReturn(Optional.empty());
            when(permissionRepository.findById(1L)).thenReturn(Optional.of(perm));
            when(roleRepository.save(any(Role.class))).thenAnswer(inv -> {
                Role r = inv.getArgument(0);
                r.setId(1L);
                return r;
            });

            Role result = service.createRole(role, List.of(1L));

            assertThat(result.getRolePermissions()).hasSize(1);
            verify(roleRepository).save(role);
        }

        @Test
        @DisplayName("should create role without permissions")
        void shouldCreateWithoutPermissions() {
            Role role = buildRole(null, "ROLE_NEW");
            when(roleRepository.findByRoleName("ROLE_NEW")).thenReturn(Optional.empty());
            when(roleRepository.save(any(Role.class))).thenAnswer(inv -> {
                Role r = inv.getArgument(0);
                r.setId(1L);
                return r;
            });

            Role result = service.createRole(role, null);

            assertThat(result).isNotNull();
            verify(roleRepository).save(role);
        }

        @Test
        @DisplayName("should throw when duplicate role name")
        void shouldThrowOnDuplicateName() {
            Role role = buildRole(null, "ROLE_EXISTING");
            when(roleRepository.findByRoleName("ROLE_EXISTING"))
                    .thenReturn(Optional.of(buildRole(1L, "ROLE_EXISTING")));

            assertThatThrownBy(() -> service.createRole(role, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("already exists");
        }

        @Test
        @DisplayName("should throw when permission not found")
        void shouldThrowWhenPermNotFound() {
            Role role = buildRole(null, "ROLE_NEW");
            when(roleRepository.findByRoleName("ROLE_NEW")).thenReturn(Optional.empty());
            when(permissionRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.createRole(role, List.of(999L)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Permission not found");
        }
    }

    // =========================================================================
    // updateRole
    // =========================================================================

    @Nested
    @DisplayName("updateRole")
    class UpdateRole {

        @Test
        @DisplayName("should update role fields and sync permissions")
        void shouldUpdateAndSyncPermissions() {
            Role existing = buildRole(1L, "ROLE_OLD");
            Permission oldPerm = buildPermission(10L, "OLD_PERM");
            existing.getRolePermissions().add(RolePermission.builder().role(existing).permission(oldPerm).build());

            Role updateInput = buildRole(1L, "ROLE_UPDATED");
            updateInput.setRoleDesc("Updated desc");

            Permission newPerm = buildPermission(20L, "NEW_PERM");
            when(roleRepository.findByIdWithPermissions(1L)).thenReturn(Optional.of(existing));
            when(permissionRepository.findById(20L)).thenReturn(Optional.of(newPerm));
            when(roleRepository.save(any(Role.class))).thenAnswer(inv -> inv.getArgument(0));

            Role result = service.updateRole(updateInput, List.of(20L));

            assertThat(result.getRoleName()).isEqualTo("ROLE_UPDATED");
            verify(eventBus).publish(any());
        }

        @Test
        @DisplayName("should throw when role not found")
        void shouldThrowWhenNotFound() {
            Role role = buildRole(999L, "ROLE_GHOST");
            when(roleRepository.findByIdWithPermissions(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.updateRole(role, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Role not found");
        }
    }

    // =========================================================================
    // deleteRole
    // =========================================================================

    @Nested
    @DisplayName("deleteRole")
    class DeleteRole {

        @Test
        @DisplayName("should delete role not in active hierarchy")
        void shouldDeleteWhenNotInHierarchy() {
            Role role = buildRole(1L, "ROLE_OLD");
            when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
            when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(Collections.emptyList());

            service.deleteRole(1L);

            verify(roleRepository).deleteById(1L);
        }

        @Test
        @DisplayName("should throw when role is referenced in active hierarchy")
        void shouldThrowWhenInActiveHierarchy() {
            Role role = buildRole(1L, "ROLE_ADMIN");
            RoleHierarchyEntity hierarchy = buildHierarchy(1L, "ROLE_ADMIN > ROLE_USER", true);
            when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
            when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(List.of(hierarchy));

            assertThatThrownBy(() -> service.deleteRole(1L))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Cannot delete role")
                    .hasMessageContaining("ROLE_ADMIN");
        }

        @Test
        @DisplayName("should throw when role not found")
        void shouldThrowWhenNotFound() {
            when(roleRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.deleteRole(999L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Role not found");
        }
    }
}
