package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
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
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RoleHierarchyServiceTest {

    @Mock
    private RoleHierarchyRepository roleHierarchyRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private RoleHierarchyImpl roleHierarchy;

    @InjectMocks
    private RoleHierarchyService service;

    // ===== Helper methods =====

    private RoleHierarchyEntity buildEntity(Long id, String hierarchyString, String description, boolean active) {
        return RoleHierarchyEntity.builder()
                .id(id)
                .hierarchyString(hierarchyString)
                .description(description)
                .isActive(active)
                .build();
    }

    private Role buildRole(String roleName) {
        return Role.builder().roleName(roleName).enabled(true).build();
    }

    private void stubRolesExist(String... roleNames) {
        List<Role> roles = new java.util.ArrayList<>();
        for (String name : roleNames) {
            roles.add(buildRole(name));
        }
        when(roleRepository.findAll()).thenReturn(roles);
    }

    private void stubNoActiveHierarchies() {
        when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(Collections.emptyList());
    }

    private void stubActiveHierarchies(RoleHierarchyEntity... entities) {
        when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(List.of(entities));
    }

    private void stubNoDuplicateHierarchyString() {
        when(roleHierarchyRepository.findByHierarchyString(any())).thenReturn(Optional.empty());
    }

    private void stubSaveReturnsInput() {
        when(roleHierarchyRepository.save(any(RoleHierarchyEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    // =========================================================================
    // 1. CRUD - Basic operations
    // =========================================================================

    @Nested
    @DisplayName("getAllRoleHierarchies")
    class GetAllRoleHierarchies {

        @Test
        @DisplayName("should return all hierarchies")
        void shouldReturnAll() {
            RoleHierarchyEntity h1 = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            RoleHierarchyEntity h2 = buildEntity(2L, "ROLE_MANAGER > ROLE_USER", "H2", false);
            when(roleHierarchyRepository.findAll()).thenReturn(List.of(h1, h2));

            List<RoleHierarchyEntity> result = service.getAllRoleHierarchies();

            assertThat(result).hasSize(2);
            verify(roleHierarchyRepository).findAll();
        }

        @Test
        @DisplayName("should return empty list when no hierarchies exist")
        void shouldReturnEmptyList() {
            when(roleHierarchyRepository.findAll()).thenReturn(Collections.emptyList());

            List<RoleHierarchyEntity> result = service.getAllRoleHierarchies();

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getRoleHierarchy")
    class GetRoleHierarchy {

        @Test
        @DisplayName("should return hierarchy by ID")
        void shouldReturnById() {
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Test", true);
            when(roleHierarchyRepository.findById(1L)).thenReturn(Optional.of(entity));

            Optional<RoleHierarchyEntity> result = service.getRoleHierarchy(1L);

            assertThat(result).isPresent();
            assertThat(result.get().getHierarchyString()).isEqualTo("ROLE_ADMIN > ROLE_USER");
        }

        @Test
        @DisplayName("should return empty when ID not found")
        void shouldReturnEmpty() {
            when(roleHierarchyRepository.findById(999L)).thenReturn(Optional.empty());

            Optional<RoleHierarchyEntity> result = service.getRoleHierarchy(999L);

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("deleteRoleHierarchy")
    class DeleteRoleHierarchy {

        @Test
        @DisplayName("should delete and reload bean")
        void shouldDeleteAndReload() {
            stubNoActiveHierarchies();

            service.deleteRoleHierarchy(1L);

            verify(roleHierarchyRepository).deleteById(1L);
            verify(roleHierarchy).setHierarchy(any());
        }
    }

    // =========================================================================
    // 2. getMergedActiveHierarchyString
    // =========================================================================

    @Nested
    @DisplayName("getMergedActiveHierarchyString")
    class MergedActiveString {

        @Test
        @DisplayName("should return empty when no active hierarchies")
        void shouldReturnEmptyWhenNoActive() {
            stubNoActiveHierarchies();

            String result = service.getMergedActiveHierarchyString();

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should return single active hierarchy string")
        void shouldReturnSingle() {
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            stubActiveHierarchies(entity);

            String result = service.getMergedActiveHierarchyString();

            assertThat(result).isEqualTo("ROLE_ADMIN > ROLE_USER");
        }

        @Test
        @DisplayName("should merge multiple active hierarchies with newline separator")
        void shouldMergeMultiple() {
            RoleHierarchyEntity h1 = buildEntity(1L, "ROLE_ADMIN > ROLE_MANAGER", "H1", true);
            RoleHierarchyEntity h2 = buildEntity(2L, "ROLE_MANAGER > ROLE_USER", "H2", true);
            stubActiveHierarchies(h1, h2);

            String result = service.getMergedActiveHierarchyString();

            assertThat(result).isEqualTo("ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER");
        }
    }

    // =========================================================================
    // 3. createRoleHierarchy - Success cases
    // =========================================================================

    @Nested
    @DisplayName("createRoleHierarchy - success")
    class CreateSuccess {

        @Test
        @DisplayName("should create valid hierarchy")
        void shouldCreate() {
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "Test", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result.getHierarchyString()).isEqualTo("ROLE_ADMIN > ROLE_USER");
            verify(roleHierarchyRepository).save(entity);
        }

        @Test
        @DisplayName("should reload bean when creating active hierarchy")
        void shouldReloadWhenActive() {
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "Test", true);
            entity.setIsActive(true);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            service.createRoleHierarchy(entity);

            verify(roleHierarchy).setHierarchy(any());
        }

        @Test
        @DisplayName("should not reload bean when creating inactive hierarchy")
        void shouldNotReloadWhenInactive() {
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "Test", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            service.createRoleHierarchy(entity);

            verify(roleHierarchy, never()).setHierarchy(any());
        }

        @Test
        @DisplayName("should create multi-line hierarchy")
        void shouldCreateMultiLine() {
            String hs = "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Multi", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result.getHierarchyString()).isEqualTo(hs);
        }
    }

    // =========================================================================
    // 4. createRoleHierarchy - Duplicate string check
    // =========================================================================

    @Nested
    @DisplayName("createRoleHierarchy - duplicate string")
    class CreateDuplicate {

        @Test
        @DisplayName("should reject identical hierarchy string")
        void shouldRejectDuplicate() {
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "Dup", false);
            when(roleHierarchyRepository.findByHierarchyString("ROLE_ADMIN > ROLE_USER"))
                    .thenReturn(Optional.of(buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Existing", true)));

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("identical");
        }
    }

    // =========================================================================
    // 5. validateHierarchyString - Role existence (via create)
    // =========================================================================

    @Nested
    @DisplayName("validateHierarchyString - role existence")
    class ValidateRoleExistence {

        @Test
        @DisplayName("should reject non-existent role")
        void shouldRejectNonExistentRole() {
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_ADMIN > ROLE_GHOST", "Test", false);
            stubRolesExist("ROLE_ADMIN");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("non-existent role");
        }

        @Test
        @DisplayName("should validate role names case-insensitively")
        void shouldValidateCaseInsensitive() {
            RoleHierarchyEntity entity = buildEntity(null, "role_admin > role_user", "Test", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result).isNotNull();
        }
    }

    // =========================================================================
    // 6. validateHierarchyLogic - 12 cases (via create)
    // =========================================================================

    @Nested
    @DisplayName("validateHierarchyLogic - case (b) duplicate relation")
    class ValidateDuplicateRelation {

        @Test
        @DisplayName("should reject duplicate A>B + A>B")
        void shouldRejectDuplicate() {
            String hs = "ROLE_ADMIN > ROLE_USER\nROLE_ADMIN > ROLE_USER";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Test", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Duplicate");
        }
    }

    @Nested
    @DisplayName("validateHierarchyLogic - case (c) reverse relation")
    class ValidateReverseRelation {

        @Test
        @DisplayName("should reject A>B + B>A")
        void shouldRejectReverse() {
            String hs = "ROLE_ADMIN > ROLE_USER\nROLE_USER > ROLE_ADMIN";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Test", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Reverse");
        }
    }

    @Nested
    @DisplayName("validateHierarchyLogic - case (d) transitive redundancy")
    class ValidateTransitiveRedundancy {

        @Test
        @DisplayName("should reject A>B + B>C + A>C")
        void shouldRejectTransitive() {
            String hs = "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER\nROLE_ADMIN > ROLE_USER";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Test", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Redundant");
        }

        @Test
        @DisplayName("should reject deep transitive A>B>C>D + A>D")
        void shouldRejectDeepTransitive() {
            String hs = "ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_D\nROLE_A > ROLE_D";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Test", false);
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C", "ROLE_D");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Redundant");
        }
    }

    @Nested
    @DisplayName("validateHierarchyLogic - case (e) cycle detection")
    class ValidateCycleDetection {

        @Test
        @DisplayName("should reject A>B>C>A cycle")
        void shouldRejectCycle() {
            String hs = "ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_A";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Test", false);
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }

        @Test
        @DisplayName("should reject 4-node cycle A>B>C>D>A")
        void shouldRejectLongCycle() {
            String hs = "ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_D\nROLE_D > ROLE_A";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Test", false);
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C", "ROLE_D");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(entity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }
    }

    @Nested
    @DisplayName("validateHierarchyLogic - valid topologies")
    class ValidTopologies {

        @Test
        @DisplayName("should accept simple chain A>B>C")
        void shouldAcceptChain() {
            String hs = "ROLE_A > ROLE_B\nROLE_B > ROLE_C";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Chain", false);
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should accept tree topology A>B, A>C")
        void shouldAcceptTree() {
            String hs = "ROLE_A > ROLE_B\nROLE_A > ROLE_C";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Tree", false);
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should accept diamond without shortcut: A>B, A>C, B>D, C>D")
        void shouldAcceptDiamond() {
            String hs = "ROLE_A > ROLE_B\nROLE_A > ROLE_C\nROLE_B > ROLE_D\nROLE_C > ROLE_D";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Diamond", false);
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C", "ROLE_D");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should accept single relation")
        void shouldAcceptSingle() {
            String hs = "ROLE_ADMIN > ROLE_USER";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Single", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);

            assertThat(result).isNotNull();
        }
    }

    // =========================================================================
    // 7. createRoleHierarchy - Merged validation (cross with existing active)
    // =========================================================================

    @Nested
    @DisplayName("createRoleHierarchy - merged validation cases (f,g,h,i)")
    class CreateMergedValidation {

        @Test
        @DisplayName("case (f): should reject reverse against existing active hierarchy")
        void shouldRejectReverseAgainstExisting() {
            // Existing active: ROLE_ADMIN > ROLE_USER
            RoleHierarchyEntity existing = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_USER > ROLE_ADMIN (reverse)
            RoleHierarchyEntity newEntity = buildEntity(null, "ROLE_USER > ROLE_ADMIN", "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(newEntity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Reverse");
        }

        @Test
        @DisplayName("case (g): should reject duplicate against existing active hierarchy")
        void shouldRejectDuplicateAgainstExisting() {
            // Existing active: ROLE_ADMIN > ROLE_USER
            RoleHierarchyEntity existing = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_ADMIN > ROLE_USER (same)
            RoleHierarchyEntity newEntity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            // This will be caught by findByHierarchyString check first
            when(roleHierarchyRepository.findByHierarchyString("ROLE_ADMIN > ROLE_USER"))
                    .thenReturn(Optional.of(existing));

            assertThatThrownBy(() -> service.createRoleHierarchy(newEntity))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("case (h): should reject merged cycle - existing A>B>C + new C>A")
        void shouldRejectMergedCycle() {
            // Existing active: ROLE_ADMIN > ROLE_MANAGER, ROLE_MANAGER > ROLE_USER
            RoleHierarchyEntity existing = buildEntity(1L,
                    "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_USER > ROLE_ADMIN (creates cycle via merge)
            RoleHierarchyEntity newEntity = buildEntity(null, "ROLE_USER > ROLE_ADMIN", "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(newEntity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }

        @Test
        @DisplayName("case (h): should reject merged cycle via intermediate - existing A>B>C + new C>D, D>A")
        void shouldRejectMergedCycleViaIntermediate() {
            // Existing: ROLE_ADMIN > ROLE_MANAGER > ROLE_USER
            RoleHierarchyEntity existing = buildEntity(1L,
                    "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_USER > ROLE_DEV, ROLE_DEV > ROLE_ADMIN (merged cycle)
            String newHs = "ROLE_USER > ROLE_DEV\nROLE_DEV > ROLE_ADMIN";
            RoleHierarchyEntity newEntity = buildEntity(null, newHs, "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER", "ROLE_DEV");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(newEntity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }

        @Test
        @DisplayName("case (i): should reject merged transitive - existing A>B>C + new A>C")
        void shouldRejectMergedTransitive() {
            // Existing: ROLE_ADMIN > ROLE_MANAGER > ROLE_USER
            RoleHierarchyEntity existing = buildEntity(1L,
                    "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_ADMIN > ROLE_USER (transitive via merge)
            RoleHierarchyEntity newEntity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
            stubNoDuplicateHierarchyString();

            assertThatThrownBy(() -> service.createRoleHierarchy(newEntity))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Redundant");
        }

        @Test
        @DisplayName("should accept valid non-conflicting new hierarchy against existing")
        void shouldAcceptValidMerge() {
            // Existing: ROLE_ADMIN > ROLE_MANAGER
            RoleHierarchyEntity existing = buildEntity(1L, "ROLE_ADMIN > ROLE_MANAGER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_MANAGER > ROLE_USER (extends chain, no conflict)
            RoleHierarchyEntity newEntity = buildEntity(null, "ROLE_MANAGER > ROLE_USER", "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(newEntity);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should accept independent new hierarchy against existing")
        void shouldAcceptIndependentHierarchy() {
            // Existing: ROLE_ADMIN > ROLE_USER
            RoleHierarchyEntity existing = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Existing", true);
            stubActiveHierarchies(existing);

            // New: ROLE_MANAGER > ROLE_DEV (completely independent)
            RoleHierarchyEntity newEntity = buildEntity(null, "ROLE_MANAGER > ROLE_DEV", "New", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER", "ROLE_MANAGER", "ROLE_DEV");
            stubNoDuplicateHierarchyString();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(newEntity);

            assertThat(result).isNotNull();
        }
    }

    // =========================================================================
    // 8. updateRoleHierarchy
    // =========================================================================

    @Nested
    @DisplayName("updateRoleHierarchy")
    class UpdateRoleHierarchy {

        @Test
        @DisplayName("should update hierarchy successfully")
        void shouldUpdate() {
            RoleHierarchyEntity existing = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Old", true);
            when(roleHierarchyRepository.findById(1L)).thenReturn(Optional.of(existing));
            stubRolesExist("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity updateInput = buildEntity(1L, "ROLE_ADMIN > ROLE_MANAGER", "Updated", true);
            RoleHierarchyEntity result = service.updateRoleHierarchy(updateInput);

            assertThat(result.getHierarchyString()).isEqualTo("ROLE_ADMIN > ROLE_MANAGER");
            assertThat(result.getDescription()).isEqualTo("Updated");
        }

        @Test
        @DisplayName("should throw when hierarchy not found")
        void shouldThrowWhenNotFound() {
            when(roleHierarchyRepository.findById(999L)).thenReturn(Optional.empty());

            RoleHierarchyEntity updateInput = buildEntity(999L, "ROLE_A > ROLE_B", "X", false);

            assertThatThrownBy(() -> service.updateRoleHierarchy(updateInput))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not found");
        }

        @Test
        @DisplayName("should reject update with invalid hierarchy logic")
        void shouldRejectInvalidUpdate() {
            RoleHierarchyEntity existing = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Old", true);
            when(roleHierarchyRepository.findById(1L)).thenReturn(Optional.of(existing));
            stubRolesExist("ROLE_A", "ROLE_B", "ROLE_C");

            // Cycle in the new value
            RoleHierarchyEntity updateInput = buildEntity(1L,
                    "ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_A", "Cycle", true);

            assertThatThrownBy(() -> service.updateRoleHierarchy(updateInput))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }
    }

    // =========================================================================
    // 9. activateRoleHierarchy
    // =========================================================================

    @Nested
    @DisplayName("activateRoleHierarchy")
    class ActivateRoleHierarchy {

        @Test
        @DisplayName("should activate inactive hierarchy")
        void shouldActivate() {
            RoleHierarchyEntity target = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", false);
            when(roleHierarchyRepository.findById(1L)).thenReturn(Optional.of(target));
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            boolean result = service.activateRoleHierarchy(1L);

            assertThat(result).isTrue();
            assertThat(target.getIsActive()).isTrue();
            verify(roleHierarchyRepository).save(target);
        }

        @Test
        @DisplayName("should deactivate active hierarchy")
        void shouldDeactivate() {
            RoleHierarchyEntity target = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            when(roleHierarchyRepository.findById(1L)).thenReturn(Optional.of(target));
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            boolean result = service.activateRoleHierarchy(1L);

            assertThat(result).isFalse();
            assertThat(target.getIsActive()).isFalse();
        }

        @Test
        @DisplayName("should reject activation that causes merged cycle")
        void shouldRejectConflictingActivation() {
            // Already active: ROLE_ADMIN > ROLE_MANAGER > ROLE_USER
            RoleHierarchyEntity active = buildEntity(1L,
                    "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER", "Active", true);
            stubActiveHierarchies(active);

            // Target to activate: ROLE_USER > ROLE_ADMIN (would create cycle)
            RoleHierarchyEntity target = buildEntity(2L, "ROLE_USER > ROLE_ADMIN", "Conflict", false);
            when(roleHierarchyRepository.findById(2L)).thenReturn(Optional.of(target));

            assertThatThrownBy(() -> service.activateRoleHierarchy(2L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }

        @Test
        @DisplayName("should throw when hierarchy not found")
        void shouldThrowNotFound() {
            when(roleHierarchyRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.activateRoleHierarchy(999L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("not found");
        }
    }

    // =========================================================================
    // 10. validateMergedHierarchy
    // =========================================================================

    @Nested
    @DisplayName("validateMergedHierarchy")
    class ValidateMergedHierarchy {

        @Test
        @DisplayName("should pass for null or empty string")
        void shouldPassForEmpty() {
            service.validateMergedHierarchy(null);
            service.validateMergedHierarchy("");
            service.validateMergedHierarchy("  ");
            // No exception
        }

        @Test
        @DisplayName("should normalize escaped newlines before validation")
        void shouldNormalizeEscapedNewlines() {
            // "\\n" literal in string should be replaced with actual newline
            String merged = "ROLE_A > ROLE_B\\nROLE_B > ROLE_C";
            // After normalization: valid chain, should pass
            service.validateMergedHierarchy(merged);
        }

        @Test
        @DisplayName("should detect cycle in merged string")
        void shouldDetectCycle() {
            String merged = "ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_A";

            assertThatThrownBy(() -> service.validateMergedHierarchy(merged))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Circular");
        }
    }

    // =========================================================================
    // 11. reloadRoleHierarchyBean
    // =========================================================================

    @Nested
    @DisplayName("reloadRoleHierarchyBean")
    class ReloadBean {

        @Test
        @DisplayName("should set hierarchy string on bean")
        void shouldSetHierarchyString() {
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            stubActiveHierarchies(entity);

            service.reloadRoleHierarchyBean();

            verify(roleHierarchy).setHierarchy("ROLE_ADMIN > ROLE_USER");
        }

        @Test
        @DisplayName("should set empty string when no active hierarchies")
        void shouldSetEmptyString() {
            stubNoActiveHierarchies();

            service.reloadRoleHierarchyBean();

            verify(roleHierarchy).setHierarchy("");
        }

        @Test
        @DisplayName("should normalize escaped newlines")
        void shouldNormalizeEscapedNewlines() {
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_A > ROLE_B\\nROLE_B > ROLE_C", "H1", true);
            stubActiveHierarchies(entity);

            service.reloadRoleHierarchyBean();

            verify(roleHierarchy).setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C");
        }

        @Test
        @DisplayName("should not throw on bean reload failure")
        void shouldNotThrowOnFailure() {
            stubNoActiveHierarchies();
            doThrow(new RuntimeException("Bean error")).when(roleHierarchy).setHierarchy(any());

            // Should not throw - error is logged
            service.reloadRoleHierarchyBean();
        }
    }

    // =========================================================================
    // 12. Edge cases and boundary tests
    // =========================================================================

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        @DisplayName("should handle empty hierarchy string gracefully in create")
        void shouldHandleEmptyString() {
            RoleHierarchyEntity entity = buildEntity(null, "", "Empty", false);
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            // Empty string passes validation (no roles to check)
            RoleHierarchyEntity result = service.createRoleHierarchy(entity);
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should handle whitespace-only hierarchy string")
        void shouldHandleWhitespaceString() {
            RoleHierarchyEntity entity = buildEntity(null, "   ", "Whitespace", false);
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should handle hierarchy with extra whitespace around roles")
        void shouldTrimRoleNames() {
            String hs = "  ROLE_ADMIN  >  ROLE_USER  ";
            RoleHierarchyEntity entity = buildEntity(null, hs, "Spaces", false);
            stubRolesExist("ROLE_ADMIN", "ROLE_USER");
            stubNoDuplicateHierarchyString();
            stubNoActiveHierarchies();
            stubSaveReturnsInput();

            RoleHierarchyEntity result = service.createRoleHierarchy(entity);
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should accept activation of hierarchy with multiple existing actives - no conflict")
        void shouldAcceptMultipleActiveNoConflict() {
            RoleHierarchyEntity active1 = buildEntity(1L, "ROLE_ADMIN > ROLE_MANAGER", "H1", true);
            stubActiveHierarchies(active1);

            // Target: ROLE_DEV > ROLE_INTERN (independent)
            RoleHierarchyEntity target = buildEntity(2L, "ROLE_DEV > ROLE_INTERN", "H2", false);
            when(roleHierarchyRepository.findById(2L)).thenReturn(Optional.of(target));
            stubSaveReturnsInput();

            boolean result = service.activateRoleHierarchy(2L);

            assertThat(result).isTrue();
        }
    }
}
