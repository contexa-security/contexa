package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PermissionServiceImplTest {

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private ManagedResourceRepository managedResourceRepository;

    @InjectMocks
    private PermissionServiceImpl service;

    // ===== Helper methods =====

    private Permission buildPermission(Long id, String name) {
        return Permission.builder()
                .id(id)
                .name(name)
                .friendlyName("Friendly " + name)
                .description("Description for " + name)
                .targetType("URL")
                .actionType("GET")
                .build();
    }

    private PermissionDto buildPermissionDto(String name) {
        return PermissionDto.builder()
                .name(name)
                .friendlyName("Friendly " + name)
                .description("Updated description")
                .targetType("URL")
                .actionType("POST")
                .conditionExpression(null)
                .build();
    }

    // =========================================================================
    // getAllPermissions
    // =========================================================================

    @Nested
    @DisplayName("getAllPermissions")
    class GetAllPermissions {

        @Test
        @DisplayName("should return all permissions")
        void shouldReturnAll() {
            Permission p1 = buildPermission(1L, "READ");
            Permission p2 = buildPermission(2L, "WRITE");
            when(permissionRepository.findAll()).thenReturn(List.of(p1, p2));

            List<Permission> result = service.getAllPermissions();

            assertThat(result).hasSize(2);
            verify(permissionRepository).findAll();
        }

        @Test
        @DisplayName("should return empty list when none exist")
        void shouldReturnEmpty() {
            when(permissionRepository.findAll()).thenReturn(Collections.emptyList());

            List<Permission> result = service.getAllPermissions();

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // getPermission
    // =========================================================================

    @Nested
    @DisplayName("getPermission")
    class GetPermission {

        @Test
        @DisplayName("should return permission when found")
        void shouldReturnWhenFound() {
            Permission perm = buildPermission(1L, "READ");
            when(permissionRepository.findById(1L)).thenReturn(Optional.of(perm));

            Optional<Permission> result = service.getPermission(1L);

            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("READ");
        }

        @Test
        @DisplayName("should return empty when not found")
        void shouldReturnEmpty() {
            when(permissionRepository.findById(999L)).thenReturn(Optional.empty());

            Optional<Permission> result = service.getPermission(999L);

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // findByName
    // =========================================================================

    @Nested
    @DisplayName("findByName")
    class FindByName {

        @Test
        @DisplayName("should return permission by name")
        void shouldReturnByName() {
            Permission perm = buildPermission(1L, "READ");
            when(permissionRepository.findByName("READ")).thenReturn(Optional.of(perm));

            Optional<Permission> result = service.findByName("READ");

            assertThat(result).isPresent();
            assertThat(result.get().getId()).isEqualTo(1L);
        }

        @Test
        @DisplayName("should return empty when name not found")
        void shouldReturnEmpty() {
            when(permissionRepository.findByName("NONEXISTENT")).thenReturn(Optional.empty());

            Optional<Permission> result = service.findByName("NONEXISTENT");

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // createPermission
    // =========================================================================

    @Nested
    @DisplayName("createPermission")
    class CreatePermission {

        @Test
        @DisplayName("should create permission successfully")
        void shouldCreate() {
            Permission perm = buildPermission(null, "NEW_PERM");
            when(permissionRepository.findByName("NEW_PERM")).thenReturn(Optional.empty());
            when(permissionRepository.save(any(Permission.class))).thenAnswer(inv -> {
                Permission p = inv.getArgument(0);
                p.setId(1L);
                return p;
            });

            Permission result = service.createPermission(perm);

            assertThat(result.getId()).isEqualTo(1L);
            verify(permissionRepository).save(perm);
        }

        @Test
        @DisplayName("should throw when duplicate name")
        void shouldThrowOnDuplicate() {
            Permission perm = buildPermission(null, "EXISTING");
            when(permissionRepository.findByName("EXISTING"))
                    .thenReturn(Optional.of(buildPermission(1L, "EXISTING")));

            assertThatThrownBy(() -> service.createPermission(perm))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("already exists");
        }
    }

    // =========================================================================
    // updatePermission
    // =========================================================================

    @Nested
    @DisplayName("updatePermission")
    class UpdatePermission {

        @Test
        @DisplayName("should update permission fields")
        void shouldUpdateFields() {
            Permission existing = buildPermission(1L, "OLD_NAME");
            PermissionDto dto = buildPermissionDto("UPDATED_NAME");
            when(permissionRepository.findById(1L)).thenReturn(Optional.of(existing));
            when(permissionRepository.save(any(Permission.class))).thenAnswer(inv -> inv.getArgument(0));

            Permission result = service.updatePermission(1L, dto);

            assertThat(result.getName()).isEqualTo("UPDATED_NAME");
            assertThat(result.getActionType()).isEqualTo("POST");
            verify(permissionRepository).save(existing);
        }

        @Test
        @DisplayName("should throw when permission not found")
        void shouldThrowWhenNotFound() {
            PermissionDto dto = buildPermissionDto("X");
            when(permissionRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.updatePermission(999L, dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Permission not found");
        }
    }

    // =========================================================================
    // deletePermission
    // =========================================================================

    @Nested
    @DisplayName("deletePermission")
    class DeletePermission {

        @Test
        @DisplayName("should delete permission not assigned to roles")
        void shouldDeleteWhenNotAssigned() {
            Permission perm = buildPermission(1L, "DELETABLE");
            when(permissionRepository.countRoleAssignments(1L)).thenReturn(0L);
            when(permissionRepository.findById(1L)).thenReturn(Optional.of(perm));

            service.deletePermission(1L);

            verify(permissionRepository).delete(perm);
        }

        @Test
        @DisplayName("should orphan ManagedResource when linked")
        void shouldOrphanManagedResource() {
            Permission perm = buildPermission(1L, "LINKED");
            ManagedResource resource = new ManagedResource();
            resource.setPermission(perm);
            perm.setManagedResource(resource);
            when(permissionRepository.countRoleAssignments(1L)).thenReturn(0L);
            when(permissionRepository.findById(1L)).thenReturn(Optional.of(perm));

            service.deletePermission(1L);

            verify(managedResourceRepository).save(resource);
            assertThat(resource.getPermission()).isNull();
            assertThat(resource.getStatus()).isEqualTo(ManagedResource.Status.NEEDS_DEFINITION);
            verify(permissionRepository).delete(perm);
        }

        @Test
        @DisplayName("should throw when permission is assigned to roles")
        void shouldThrowWhenAssigned() {
            when(permissionRepository.countRoleAssignments(1L)).thenReturn(3L);

            assertThatThrownBy(() -> service.deletePermission(1L))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("assigned to");
        }

        @Test
        @DisplayName("should throw when permission not found")
        void shouldThrowWhenNotFound() {
            when(permissionRepository.countRoleAssignments(999L)).thenReturn(0L);
            when(permissionRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.deletePermission(999L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Permission not found");
        }
    }
}
