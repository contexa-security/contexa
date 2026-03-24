package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.domain.dto.UserListDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserManagementServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private GroupRepository groupRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @InjectMocks
    private UserManagementServiceImpl service;

    // ===== Helper methods =====

    private Users buildUser(Long id, String username, String name) {
        return Users.builder()
                .id(id)
                .username(username)
                .name(name)
                .email(username + "@test.com")
                .password("encoded")
                .mfaEnabled(false)
                .enabled(true)
                .userGroups(new HashSet<>())
                .build();
    }

    private UserDto buildUserDto(Long id, String username, String name) {
        return UserDto.builder()
                .id(id)
                .username(username)
                .name(name)
                .mfaEnabled(false)
                .selectedGroupIds(List.of())
                .build();
    }

    private Group buildGroup(Long id, String name) {
        return Group.builder()
                .id(id)
                .name(name)
                .build();
    }

    private UserListDto buildUserListDto(Long id, String name, String username) {
        UserListDto dto = new UserListDto();
        dto.setId(id);
        dto.setName(name);
        dto.setUsername(username);
        dto.setMfaEnabled(false);
        dto.setGroupCount(0);
        dto.setRoleCount(0);
        return dto;
    }

    // =========================================================================
    // getUsers
    // =========================================================================

    @Nested
    @DisplayName("getUsers")
    class GetUsers {

        @Test
        @DisplayName("should return mapped user list from repository")
        void shouldReturnMappedList() {
            Users user1 = buildUser(1L, "alice", "Alice");
            Users user2 = buildUser(2L, "bob", "Bob");
            when(userRepository.findAllWithDetails()).thenReturn(List.of(user1, user2));
            when(modelMapper.map(any(Users.class), eq(UserListDto.class)))
                    .thenAnswer(inv -> {
                        Users u = inv.getArgument(0);
                        return buildUserListDto(u.getId(), u.getName(), u.getUsername());
                    });

            List<UserListDto> result = service.getUsers();

            assertThat(result).hasSize(2);
            assertThat(result.get(0).getUsername()).isEqualTo("alice");
            assertThat(result.get(1).getUsername()).isEqualTo("bob");
            verify(userRepository).findAllWithDetails();
        }

        @Test
        @DisplayName("should return empty list when no users exist")
        void shouldReturnEmptyList() {
            when(userRepository.findAllWithDetails()).thenReturn(Collections.emptyList());

            List<UserListDto> result = service.getUsers();

            assertThat(result).isEmpty();
        }
    }

    // =========================================================================
    // getUser
    // =========================================================================

    @Nested
    @DisplayName("getUser")
    class GetUser {

        @Test
        @DisplayName("should return user dto when found")
        void shouldReturnUserDto() {
            Users user = buildUser(1L, "alice", "Alice");
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(modelMapper.map(user, UserDto.class)).thenReturn(dto);

            UserDto result = service.getUser(1L);

            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo("alice");
        }

        @Test
        @DisplayName("should throw IllegalArgumentException when user not found")
        void shouldThrowWhenNotFound() {
            when(userRepository.findByIdWithGroupsRolesAndPermissions(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.getUser(999L))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("User not found");
        }
    }

    // =========================================================================
    // modifyUser
    // =========================================================================

    @Nested
    @DisplayName("modifyUser")
    class ModifyUser {

        @Test
        @DisplayName("should update user name and mfaEnabled")
        void shouldUpdateBasicFields() {
            Users user = buildUser(1L, "alice", "Alice");
            UserDto dto = buildUserDto(1L, "alice", "Alice Updated");
            dto.setMfaEnabled(true);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(userRepository.save(any(Users.class))).thenReturn(user);

            service.modifyUser(dto);

            assertThat(user.getName()).isEqualTo("Alice Updated");
            assertThat(user.isMfaEnabled()).isTrue();
            verify(userRepository).save(user);
        }

        @Test
        @DisplayName("should encode password when provided")
        void shouldEncodePassword() {
            Users user = buildUser(1L, "alice", "Alice");
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setPassword("newPassword");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(passwordEncoder.encode("newPassword")).thenReturn("encodedNew");
            when(userRepository.save(any(Users.class))).thenReturn(user);

            service.modifyUser(dto);

            assertThat(user.getPassword()).isEqualTo("encodedNew");
            verify(passwordEncoder).encode("newPassword");
        }

        @Test
        @DisplayName("should not change password when not provided")
        void shouldNotChangePasswordWhenEmpty() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setPassword("oldEncoded");
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setPassword(null);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(userRepository.save(any(Users.class))).thenReturn(user);

            service.modifyUser(dto);

            assertThat(user.getPassword()).isEqualTo("oldEncoded");
            verify(passwordEncoder, never()).encode(any());
        }

        @Test
        @DisplayName("should sync group assignments")
        void shouldSyncGroups() {
            Users user = buildUser(1L, "alice", "Alice");
            Group group = buildGroup(10L, "Admins");
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setSelectedGroupIds(List.of(10L));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(groupRepository.findById(10L)).thenReturn(Optional.of(group));
            when(userRepository.save(any(Users.class))).thenReturn(user);

            service.modifyUser(dto);

            assertThat(user.getUserGroups()).hasSize(1);
            verify(groupRepository).findById(10L);
        }

        @Test
        @DisplayName("should throw when user not found")
        void shouldThrowWhenNotFound() {
            UserDto dto = buildUserDto(999L, "ghost", "Ghost");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.modifyUser(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("User not found");
        }

        @Test
        @DisplayName("should throw when group not found")
        void shouldThrowWhenGroupNotFound() {
            Users user = buildUser(1L, "alice", "Alice");
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setSelectedGroupIds(List.of(999L));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(groupRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.modifyUser(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Group not found");
        }
    }

    // =========================================================================
    // deleteUser
    // =========================================================================

    @Nested
    @DisplayName("deleteUser")
    class DeleteUser {

        @Test
        @DisplayName("should delete user by ID")
        void shouldDeleteById() {
            service.deleteUser(1L);

            verify(userRepository).deleteById(1L);
        }

        @Test
        @DisplayName("should attempt audit before deletion")
        void shouldAttemptAudit() {
            Users user = buildUser(1L, "alice", "Alice");
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));

            service.deleteUser(1L);

            verify(centralAuditFacade).recordAsync(any());
            verify(userRepository).deleteById(1L);
        }
    }
}
