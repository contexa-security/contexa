package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.GroupRepository;
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

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GroupServiceImplTest {

    @Mock
    private GroupRepository groupRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private RoleHierarchyRepository roleHierarchyRepository;

    @InjectMocks
    private GroupServiceImpl service;

    // ===== Helper methods =====

    private Group buildGroup(Long id, String name) {
        return Group.builder()
                .id(id)
                .name(name)
                .description("Test group")
                .groupRoles(new HashSet<>())
                .build();
    }

    private Role buildRole(Long id, String roleName) {
        return Role.builder()
                .id(id)
                .roleName(roleName)
                .enabled(true)
                .build();
    }

    private RoleHierarchyEntity buildHierarchy(Long id, String hierarchyString, boolean active) {
        return RoleHierarchyEntity.builder()
                .id(id)
                .hierarchyString(hierarchyString)
                .isActive(active)
                .build();
    }

    // =========================================================================
    // getAllGroups
    // =========================================================================

    @Nested
    @DisplayName("getAllGroups")
    class GetAllGroups {

        @Test
        @DisplayName("should return all groups")
        void shouldReturnAll() {
            Group g1 = buildGroup(1L, "Admins");
            Group g2 = buildGroup(2L, "Users");
            when(groupRepository.findAllWithRolesAndUsers()).thenReturn(List.of(g1, g2));

            List<Group> result = service.getAllGroups();

            assertThat(result).hasSize(2);
            verify(groupRepository).findAllWithRolesAndUsers();
        }

        @Test
        @DisplayName("should return empty list when no groups exist")
        void shouldReturnEmpty() {
            when(groupRepository.findAllWithRolesAndUsers()).thenReturn(Collections.emptyList());

            List<Group> result = service.getAllGroups();

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // getGroup
    // =========================================================================

    @Nested
    @DisplayName("getGroup")
    class GetGroup {

        @Test
        @DisplayName("should return group when found")
        void shouldReturnGroup() {
            Group group = buildGroup(1L, "Admins");
            when(groupRepository.findByIdWithRoles(1L)).thenReturn(Optional.of(group));

            Optional<Group> result = service.getGroup(1L);

            assertThat(result).isPresent();
            assertThat(result.get().getName()).isEqualTo("Admins");
        }

        @Test
        @DisplayName("should return empty when not found")
        void shouldReturnEmpty() {
            when(groupRepository.findByIdWithRoles(999L)).thenReturn(Optional.empty());

            Optional<Group> result = service.getGroup(999L);

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // createGroup
    // =========================================================================

    @Nested
    @DisplayName("createGroup")
    class CreateGroup {

        @Test
        @DisplayName("should create group with roles")
        void shouldCreateWithRoles() {
            Group group = buildGroup(null, "NewGroup");
            Role role = buildRole(1L, "ROLE_USER");
            when(groupRepository.findByName("NewGroup")).thenReturn(Optional.empty());
            when(roleRepository.findById(1L)).thenReturn(Optional.of(role));
            when(groupRepository.save(any(Group.class))).thenAnswer(inv -> inv.getArgument(0));

            Group result = service.createGroup(group, List.of(1L));

            assertThat(result.getGroupRoles()).hasSize(1);
            verify(groupRepository).save(group);
        }

        @Test
        @DisplayName("should create group without roles")
        void shouldCreateWithoutRoles() {
            Group group = buildGroup(null, "NewGroup");
            when(groupRepository.findByName("NewGroup")).thenReturn(Optional.empty());
            when(groupRepository.save(any(Group.class))).thenAnswer(inv -> inv.getArgument(0));

            Group result = service.createGroup(group, null);

            assertThat(result).isNotNull();
            verify(groupRepository).save(group);
        }

        @Test
        @DisplayName("should throw when duplicate name")
        void shouldThrowOnDuplicateName() {
            Group group = buildGroup(null, "Existing");
            when(groupRepository.findByName("Existing")).thenReturn(Optional.of(buildGroup(1L, "Existing")));

            assertThatThrownBy(() -> service.createGroup(group, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("already exists");
        }

        @Test
        @DisplayName("should throw when role not found")
        void shouldThrowWhenRoleNotFound() {
            Group group = buildGroup(null, "NewGroup");
            when(groupRepository.findByName("NewGroup")).thenReturn(Optional.empty());
            when(roleRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.createGroup(group, List.of(999L)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Role not found");
        }
    }

    // =========================================================================
    // updateGroup
    // =========================================================================

    @Nested
    @DisplayName("updateGroup")
    class UpdateGroup {

        @Test
        @DisplayName("should update group and sync roles")
        void shouldUpdateAndSyncRoles() {
            Group existing = buildGroup(1L, "OldName");
            Role role = buildRole(10L, "ROLE_ADMIN");
            existing.getGroupRoles().add(GroupRole.builder().group(existing).role(role).build());

            Role newRole = buildRole(20L, "ROLE_USER");
            Group updateInput = buildGroup(1L, "UpdatedName");
            updateInput.setDescription("Updated desc");

            when(groupRepository.findByIdWithRoles(1L)).thenReturn(Optional.of(existing));
            when(roleRepository.findById(20L)).thenReturn(Optional.of(newRole));

            Group result = service.updateGroup(updateInput, List.of(20L));

            assertThat(result.getName()).isEqualTo("UpdatedName");
            assertThat(result.getDescription()).isEqualTo("Updated desc");
        }

        @Test
        @DisplayName("should throw when group not found")
        void shouldThrowWhenNotFound() {
            Group group = buildGroup(999L, "Ghost");
            when(groupRepository.findByIdWithRoles(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.updateGroup(group, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Group not found");
        }
    }

    // =========================================================================
    // deleteGroup
    // =========================================================================

    @Nested
    @DisplayName("deleteGroup")
    class DeleteGroup {

        @Test
        @DisplayName("should delete group by ID")
        void shouldDeleteById() {
            service.deleteGroup(1L);

            verify(groupRepository).deleteById(1L);
        }
    }

    // =========================================================================
    // checkHierarchyWarnings
    // =========================================================================

    @Nested
    @DisplayName("checkHierarchyWarnings")
    class CheckHierarchyWarnings {

        @Test
        @DisplayName("should return empty for null roleIds")
        void shouldReturnEmptyForNull() {
            List<String> result = service.checkHierarchyWarnings(null);

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should return empty for single roleId")
        void shouldReturnEmptyForSingle() {
            List<String> result = service.checkHierarchyWarnings(List.of(1L));

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should detect redundant role via hierarchy")
        void shouldDetectRedundantRole() {
            Role admin = buildRole(1L, "ROLE_ADMIN");
            Role user = buildRole(2L, "ROLE_USER");
            when(roleRepository.findById(1L)).thenReturn(Optional.of(admin));
            when(roleRepository.findById(2L)).thenReturn(Optional.of(user));

            RoleHierarchyEntity hierarchy = buildHierarchy(1L, "ROLE_ADMIN > ROLE_USER", true);
            when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(List.of(hierarchy));

            List<String> result = service.checkHierarchyWarnings(List.of(1L, 2L));

            assertThat(result).hasSize(1);
            assertThat(result.get(0)).contains("ROLE_USER").contains("inherited").contains("ROLE_ADMIN");
        }

        @Test
        @DisplayName("should return empty when no hierarchy exists")
        void shouldReturnEmptyWhenNoHierarchy() {
            Role admin = buildRole(1L, "ROLE_ADMIN");
            Role user = buildRole(2L, "ROLE_USER");
            when(roleRepository.findById(1L)).thenReturn(Optional.of(admin));
            when(roleRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(Collections.emptyList());

            List<String> result = service.checkHierarchyWarnings(List.of(1L, 2L));

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should detect transitive redundancy via BFS")
        void shouldDetectTransitiveRedundancy() {
            Role admin = buildRole(1L, "ROLE_ADMIN");
            Role manager = buildRole(2L, "ROLE_MANAGER");
            Role user = buildRole(3L, "ROLE_USER");
            when(roleRepository.findById(1L)).thenReturn(Optional.of(admin));
            when(roleRepository.findById(2L)).thenReturn(Optional.of(manager));
            when(roleRepository.findById(3L)).thenReturn(Optional.of(user));

            RoleHierarchyEntity hierarchy = buildHierarchy(1L,
                    "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER", true);
            when(roleHierarchyRepository.findAllByIsActiveTrue()).thenReturn(List.of(hierarchy));

            List<String> result = service.checkHierarchyWarnings(List.of(1L, 3L));

            assertThat(result).isNotEmpty();
            assertThat(result.get(0)).contains("ROLE_USER");
        }
    }
}
