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
package io.contexa.contexaiam.admin.web.auth.service.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.security.UserAccountDeletedEvent;
import io.contexa.contexacommon.security.UserAccountDisabledEvent;
import io.contexa.contexacommon.security.UserAuthoritiesChangedEvent;
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.domain.dto.UserListDto;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.slf4j.LoggerFactory;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith({MockitoExtension.class, I18nTestSupport.EnglishLocale.class})
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

    @Spy
    private MessageSource messageSource = I18nTestSupport.englishMessageSource();

    @Mock
    private UserRolePermissionRepository userRolePermissionRepository;

    @Mock
    private BridgeUserProfileRepository bridgeUserProfileRepository;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private LastAdministratorGuard lastAdministratorGuard;

    @InjectMocks
    private UserManagementServiceImpl service;

    @Nested
    @DisplayName("unlockUser")
    class UnlockUser {

        @AfterEach
        void clearSecurityContext() {
            SecurityContextHolder.clearContext();
        }

        @Test
        @DisplayName("lifts the lock and leaves in the audit who did it and for whom")
        void unlocked() {
            SecurityContextHolder.setContext(new SecurityContextImpl(new TestingAuthenticationToken("second-admin", "x")));
            when(userRepository.findById(5L)).thenReturn(Optional.of(buildUser(5L, "alice", "Alice")));
            when(userRepository.clearLock(5L)).thenReturn(1);

            assertThat(service.unlockUser(5L)).isTrue();

            ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
            verify(centralAuditFacade).recordAsync(record.capture());
            assertThat(record.getValue().getEventCategory()).isEqualTo(AuditEventCategory.USER_MODIFIED);
            assertThat(record.getValue().getAction()).isEqualTo("USER_UNLOCKED");
            assertThat(record.getValue().getPrincipalName()).isEqualTo("second-admin");
            assertThat(record.getValue().getResourceIdentifier()).isEqualTo("alice");
            assertThat(record.getValue().getOutcome()).isEqualTo("SUCCESS");
        }

        @Test
        @DisplayName("an account under no lock changes nothing and leaves no record")
        void notLocked() {
            when(userRepository.findById(5L)).thenReturn(Optional.of(buildUser(5L, "alice", "Alice")));
            when(userRepository.clearLock(5L)).thenReturn(0);

            assertThat(service.unlockUser(5L)).isFalse();

            verify(centralAuditFacade, never()).recordAsync(any());
        }

        @Test
        @DisplayName("an unknown account is an error, not a lock lifted")
        void unknown() {
            when(userRepository.findById(5L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.unlockUser(5L)).isInstanceOf(IllegalArgumentException.class);

            verify(userRepository, never()).clearLock(any());
        }

        @Test
        @DisplayName("an audit that fails does not bring the lock back")
        void anAuditThatFails() {
            when(userRepository.findById(5L)).thenReturn(Optional.of(buildUser(5L, "alice", "Alice")));
            when(userRepository.clearLock(5L)).thenReturn(1);
            doThrow(new IllegalStateException("audit down")).when(centralAuditFacade).recordAsync(any());

            assertThat(service.unlockUser(5L)).isTrue();
        }
    }

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

        /** PR-27: a copy is named by a hash; the administrator reads the name the application knows the user by. */
        @Test
        @DisplayName("a copy of an application user is listed under the application's name for it")
        void aBridgeCopyIsListedUnderTheApplicationsName() {
            Users copy = buildUser(3L, "brg_23aa0123456789abcdef", "Carol");
            copy.setBridgeManaged(true);
            copy.setExternalSubjectId("carol");
            when(userRepository.findAllWithDetails()).thenReturn(List.of(copy, buildUser(1L, "alice", "Alice")));
            when(modelMapper.map(any(Users.class), eq(UserListDto.class)))
                    .thenAnswer(inv -> {
                        Users u = inv.getArgument(0);
                        return buildUserListDto(u.getId(), u.getName(), u.getUsername());
                    });

            List<UserListDto> result = service.getUsers();

            assertThat(result).extracting(UserListDto::getUsername).containsExactly("carol", "alice");
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
        @DisplayName("should not log an ordinary lookup as an error")
        void shouldNotLogAnOrdinaryLookupAsAnError() {
            Users user = buildUser(1L, "alice", "Alice");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(modelMapper.map(user, UserDto.class)).thenReturn(buildUserDto(1L, "alice", "Alice"));
            Logger logger = (Logger) LoggerFactory.getLogger(UserManagementServiceImpl.class);
            ListAppender<ILoggingEvent> logged = new ListAppender<>();
            logged.start();
            logger.addAppender(logged);

            try {
                service.getUser(1L);
            } finally {
                logger.detachAppender(logged);
            }

            assertThat(logged.list).noneMatch(event -> event.getLevel() == Level.ERROR);
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
    // modifyUser (Q-14: what reaches the sessions that are open)
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
        @DisplayName("Q-14: a disabled account's open sessions end")
        void disablingEndsTheSessions() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(true);
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setEnabled(false);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            service.modifyUser(dto);

            verify(eventPublisher).publishEvent(new UserAccountDisabledEvent("alice"));
        }

        @Test
        @DisplayName("Q-14: an account already disabled tells nobody again")
        void savingADisabledAccountEndsNothing() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(false);
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setEnabled(false);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            service.modifyUser(dto);

            verify(eventPublisher, never()).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("a password an administrator sets ends what the old one opened, and dates the account")
        void aNewPasswordEndsTheSessions() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(true);
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setEnabled(true);
            dto.setPassword("New-Pass-1");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(passwordPolicyService.validatePassword("New-Pass-1")).thenReturn(List.of());
            when(passwordEncoder.encode("New-Pass-1")).thenReturn("{hash}new");

            service.modifyUser(dto);

            assertThat(user.getPassword()).isEqualTo("{hash}new");
            assertThat(user.getPasswordChangedAt()).isNotNull();
            InOrder order = inOrder(userRepository, eventPublisher);
            order.verify(userRepository).save(user);
            order.verify(eventPublisher).publishEvent(new UserPasswordChangedEvent("alice"));
        }

        @Test
        @DisplayName("a form saved without a password ends nothing, and the date of the account stays")
        void noNewPasswordEndsNothing() {
            LocalDateTime changedAt = LocalDateTime.of(2026, 11, 1, 9, 0);
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(true);
            user.setPasswordChangedAt(changedAt);
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setEnabled(true);
            dto.setPassword(" ");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            service.modifyUser(dto);

            assertThat(user.getPasswordChangedAt()).isEqualTo(changedAt);
            verify(eventPublisher, never()).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("a password refused by the policy ends nothing")
        void aRefusedPasswordEndsNothing() {
            Users user = buildUser(1L, "alice", "Alice");
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setPassword("weak");
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(passwordPolicyService.validatePassword("weak")).thenReturn(List.of("Too short"));

            assertThatThrownBy(() -> service.modifyUser(dto)).isInstanceOf(IllegalArgumentException.class);

            verify(eventPublisher, never()).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("a new password and a new group both reach what is open")
        void aNewPasswordAndANewGroup() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(true);
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setEnabled(true);
            dto.setPassword("New-Pass-1");
            dto.setSelectedGroupIds(List.of(7L));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(passwordPolicyService.validatePassword("New-Pass-1")).thenReturn(List.of());
            when(groupRepository.findById(7L)).thenReturn(Optional.of(Group.builder().id(7L).build()));

            service.modifyUser(dto);

            verify(eventPublisher).publishEvent(new UserPasswordChangedEvent("alice"));
            verify(eventPublisher).publishEvent(new UserAuthoritiesChangedEvent());
        }

        @Test
        @DisplayName("Q-14: a group given or taken away reaches the open sessions")
        void groupsReachTheSessions() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(true);
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setEnabled(true);
            dto.setSelectedGroupIds(List.of(7L));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(groupRepository.findById(7L)).thenReturn(Optional.of(Group.builder().id(7L).build()));

            service.modifyUser(dto);

            verify(eventPublisher).publishEvent(new UserAuthoritiesChangedEvent());
        }

        @Test
        @DisplayName("Q-14: a name changed reaches nobody")
        void otherFieldsReachNobody() {
            Users user = buildUser(1L, "alice", "Alice");
            user.setEnabled(true);
            UserDto dto = buildUserDto(1L, "alice", "Alice Updated");
            dto.setEnabled(true);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            service.modifyUser(dto);

            verify(eventPublisher, never()).publishEvent(any(Object.class));
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
        @DisplayName("a group the account keeps stays the row it is: only the groups dropped and the new ones change")
        void keptGroupsStayTheRowsTheyAre() {
            Users user = buildUser(1L, "alice", "Alice");
            UserGroup keptRow = UserGroup.builder().user(user).group(buildGroup(10L, "kept")).build();
            user.getUserGroups().add(keptRow);
            user.getUserGroups().add(UserGroup.builder().user(user).group(buildGroup(11L, "dropped")).build());
            UserDto dto = buildUserDto(1L, "alice", "Alice");
            dto.setSelectedGroupIds(List.of(10L, 12L));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(groupRepository.findById(12L)).thenReturn(Optional.of(buildGroup(12L, "added")));

            service.modifyUser(dto);

            assertThat(user.getUserGroups()).hasSize(2).anySatisfy(row -> assertThat(row).isSameAs(keptRow));
            assertThat(user.getUserGroups()).extracting(row -> row.getGroup().getId())
                    .containsExactlyInAnyOrder(10L, 12L);
            verify(groupRepository, never()).findById(10L);
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

        @Test
        @DisplayName("should remove rows that block the deletion and announce the deleted account")
        void shouldRemoveDependentRowsAndPublishDeletion() {
            Users user = buildUser(1L, "alice", "Alice");
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(bridgeUserProfileRepository.existsById(1L)).thenReturn(true);

            service.deleteUser(1L);

            InOrder order = inOrder(userRolePermissionRepository, bridgeUserProfileRepository, userRepository,
                    eventPublisher);
            order.verify(userRolePermissionRepository).deleteByUserId(1L);
            order.verify(bridgeUserProfileRepository).deleteById(1L);
            order.verify(userRepository).deleteById(1L);
            order.verify(eventPublisher).publishEvent(new UserAccountDeletedEvent(1L, "alice"));
        }

        @Test
        @DisplayName("should not announce a deletion of an unknown account")
        void shouldNotPublishForUnknownAccount() {
            when(userRepository.findById(9L)).thenReturn(Optional.empty());

            service.deleteUser(9L);

            verify(eventPublisher, never()).publishEvent(any(Object.class));
        }
    }
}
