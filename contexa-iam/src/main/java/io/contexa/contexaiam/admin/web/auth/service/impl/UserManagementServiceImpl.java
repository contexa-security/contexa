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

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.security.UserAccountDeletedEvent;
import io.contexa.contexacommon.security.UserAccountDisabledEvent;
import io.contexa.contexacommon.security.UserAuthoritiesChangedEvent;
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexaiam.admin.web.agent.service.AgentSponsorship;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class UserManagementServiceImpl implements UserManagementService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;
    private final CentralAuditFacade centralAuditFacade;
    private final PasswordPolicyService passwordPolicyService;
    private final SystemSettingsService systemSettingsService;
    private final MessageSource messageSource;
    private final UserRolePermissionRepository userRolePermissionRepository;
    private final BridgeUserProfileRepository bridgeUserProfileRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final LastAdministratorGuard lastAdministratorGuard;
    private AgentSponsorship agentSponsorship;

    /** IAM-D57: an account that sponsors agents in service is not deleted; null where agents are not registered. */
    public void setAgentSponsorship(AgentSponsorship agentSponsorship) {
        this.agentSponsorship = agentSponsorship;
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void createUser(UserDto userDto) {
        if (userRepository.findByUsername(userDto.getUsername()).isPresent()) {
            throw new IllegalArgumentException(msg("msg.user.username.exists", userDto.getUsername()));
        }

        if (!StringUtils.hasText(userDto.getPassword())) {
            throw new IllegalArgumentException(msg("msg.user.password.required"));
        }

        List<String> violations = passwordPolicyService.validatePassword(userDto.getPassword());
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException(msg("msg.user.password.policy.violation", String.join(", ", violations)));
        }

        Users users = new Users();
        users.setUsername(userDto.getUsername());
        users.setPassword(passwordEncoder.encode(userDto.getPassword()));
        users.setName(userDto.getName());
        users.setEmail(userDto.getEmail());
        users.setPhone(userDto.getPhone());
        users.setDepartment(userDto.getDepartment());
        users.setPosition(userDto.getPosition());
        users.setEnabled(userDto.isEnabled());
        users.setMfaEnabled(userDto.isMfaEnabled());
        users.setLocale(userDto.getLocale());
        users.setTimezone(userDto.getTimezone());
        users.setPasswordChangedAt(LocalDateTime.now());

        Set<Long> desiredGroupIds = userDto.getSelectedGroupIds() != null
                ? new HashSet<>(userDto.getSelectedGroupIds())
                : new HashSet<>();

        for (Long groupId : desiredGroupIds) {
            Group group = groupRepository.findById(groupId)
                    .orElseThrow(() -> new IllegalArgumentException(msg("msg.group.not.found.id", groupId)));
            UserGroup userGroup = UserGroup.builder()
                    .user(users)
                    .group(group)
                    .build();
            users.getUserGroups().add(userGroup);
        }

        // Assign default role from system settings
        try {
            String defaultRoleName = systemSettingsService.getSettings().getDefaultRole();
            if (StringUtils.hasText(defaultRoleName)) {
                roleRepository.findByRoleName(defaultRoleName).ifPresent(role -> {
                    UserRole userRole = UserRole.builder()
                            .user(users).role(role).build();
                    users.getUserRoles().add(userRole);
                });
            }
        } catch (Exception e) {
            log.error("Failed to assign default role to user: {}", users.getUsername(), e);
        }

        userRepository.save(users);

        try {
            String admin = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) admin = auth.getName();

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.USER_CREATED)
                    .principalName(admin)
                    .resourceIdentifier(users.getUsername() != null ? users.getUsername() : "")
                    .eventSource("IAM")
                    .action("USER_CREATED")
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of(
                            "userId", users.getId() != null ? users.getId() : 0L,
                            "username", users.getUsername() != null ? users.getUsername() : ""))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit user creation: {}", users.getUsername(), e);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Override
//    @Protectable
    public void modifyUser(@ModelAttribute UserDto userDto) {
        // First in the transaction: a change of who administers the console waits for the one before it.
        lastAdministratorGuard.serializeChanges();
        log.debug("[UserManagementService.modifyUser] findByIdWithGroupsRolesAndPermissions id={}", userDto.getId());
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(userDto.getId())
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.user.not.found.id", userDto.getId())));

        boolean disabled = users.isEnabled() && !userDto.isEnabled();
        boolean passwordChanged = StringUtils.hasText(userDto.getPassword());
        boolean wasActiveAdministrator = lastAdministratorGuard.activeAdministrator(users);
        Set<Long> previousGroupIds = users.getUserGroups().stream()
                .map(userGroup -> userGroup.getGroup().getId())
                .collect(Collectors.toSet());

        users.setName(userDto.getName());
        users.setEmail(userDto.getEmail());
        users.setPhone(userDto.getPhone());
        users.setDepartment(userDto.getDepartment());
        users.setPosition(userDto.getPosition());
        users.setEnabled(userDto.isEnabled());
        users.setMfaEnabled(userDto.isMfaEnabled());
        users.setPreferredMfaFactor(userDto.getPreferredMfaFactor());
        users.setLocale(userDto.getLocale());
        users.setTimezone(userDto.getTimezone());
        if (passwordChanged) {
            List<String> violations = passwordPolicyService.validatePassword(userDto.getPassword());
            if (!violations.isEmpty()) {
                throw new IllegalArgumentException(msg("msg.user.password.policy.violation", String.join(", ", violations)));
            }
            users.setPassword(passwordEncoder.encode(userDto.getPassword()));
            users.setPasswordChangedAt(LocalDateTime.now());
        }

        Set<Long> desiredGroupIds = userDto.getSelectedGroupIds() != null
                ? new HashSet<>(userDto.getSelectedGroupIds())
                : new HashSet<>();

        // A group the user keeps stays the row it is. Dropped and made again under the same key, it would meet itself in
        // the session as soon as a query flushes, and the check of the last administrator below runs one.
        users.getUserGroups().removeIf(userGroup -> !desiredGroupIds.contains(userGroup.getGroup().getId()));
        Set<Long> keptGroupIds = users.getUserGroups().stream()
                .map(userGroup -> userGroup.getGroup().getId())
                .collect(Collectors.toSet());

        for (Long groupId : desiredGroupIds) {
            if (keptGroupIds.contains(groupId)) {
                continue;
            }
            Group group = groupRepository.findById(groupId)
                    .orElseThrow(() -> new IllegalArgumentException(msg("msg.group.not.found.id", groupId)));
            UserGroup userGroup = UserGroup.builder()
                    .user(users)
                    .group(group)
                    .build();
            users.getUserGroups().add(userGroup);
        }
        lastAdministratorGuard.refuseLosingTheLast(users, wasActiveAdministrator);

        userRepository.save(users);

        // The listeners run after the commit, so a change that rolls back reaches no session (Q-14).
        if (passwordChanged) {
            eventPublisher.publishEvent(new UserPasswordChangedEvent(users.getUsername()));
        }
        if (disabled) {
            eventPublisher.publishEvent(new UserAccountDisabledEvent(users.getUsername()));
        } else if (!previousGroupIds.equals(desiredGroupIds)) {
            eventPublisher.publishEvent(new UserAuthoritiesChangedEvent());
        }

        try {
            String admin = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) admin = auth.getName();

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.USER_MODIFIED)
                    .principalName(admin)
                    .resourceIdentifier(users.getUsername() != null ? users.getUsername() : "")
                    .eventSource("IAM")
                    .action("USER_MODIFIED")
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of(
                            "userId", users.getId() != null ? users.getId() : 0L,
                            "username", users.getUsername() != null ? users.getUsername() : "",
                            "passwordChanged", passwordChanged))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit user modification: {}", users.getUsername(), e);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
//    @Protectable
    public UserDto getUser(Long id) {
        log.debug("[UserManagementService.getUser] findByIdWithGroupsRolesAndPermissions id={}", id);
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + id));
        UserDto userDto = modelMapper.map(users, UserDto.class);
        List<String> roles = users.getRoleNames();
        List<String> permissions = users.getPermissionNames();

        userDto.setRoles(roles);
        userDto.setPermissions(permissions);
        if (users.getUserGroups() != null) {
            userDto.setSelectedGroupIds(users.getUserGroups().stream()
                    .map(ug -> ug.getGroup().getId())
                    .collect(Collectors.toList()));
        } else {
            userDto.setSelectedGroupIds(List.of());
        }

        return userDto;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Protectable(verificationRequired = false)
    public List<UserListDto> getUsers() {
        return userRepository.findAllWithDetails().stream()
                .map(this::toUserListDto)
                .toList();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Protectable(verificationRequired = false)
    public Page<UserListDto> getUsers(String keyword, Pageable pageable) {
        Page<Users> users = StringUtils.hasText(keyword)
                ? userRepository.findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase(
                        keyword.trim(), keyword.trim(), pageable)
                : userRepository.findAll(pageable);
        return users.map(this::toUserListDto);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    @Protectable(verificationRequired = false)
    public boolean unlockUser(Long id) {
        Users user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.user.not.found.id", id)));
        if (userRepository.clearLock(id) == 0) {
            return false;
        }
        try {
            var auth = SecurityContextHolder.getContext().getAuthentication();
            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.USER_MODIFIED)
                    .principalName(auth != null && auth.getName() != null ? auth.getName() : "SYSTEM")
                    .resourceIdentifier(user.getUsername() != null ? user.getUsername() : "")
                    .eventSource("IAM")
                    .action("USER_UNLOCKED")
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of("userId", id, "username", user.getUsername() != null ? user.getUsername() : ""))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit the release of a lock: {}", user.getUsername(), e);
        }
        return true;
    }

    private UserListDto toUserListDto(Users user) {
        UserListDto dto = modelMapper.map(user, UserListDto.class);
        // PR-27: a copy of an application's user is named by a hash; the application's name for the user is what reads.
        if (user.isBridgeManaged() && StringUtils.hasText(user.getExternalSubjectId())) {
            dto.setUsername(user.getExternalSubjectId());
        }
        dto.setGroupCount(user.getUserGroups() != null ? user.getUserGroups().size() : 0);
        long roleCount = user.getRoleNames().stream().distinct().count();
        dto.setRoleCount((int) roleCount);
        return dto;
    }
    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    @Protectable(verificationRequired = false)
    public void deleteUser(Long id) {
        lastAdministratorGuard.serializeChanges();
        Optional<Users> target = userRepository.findById(id);
        target.ifPresent(lastAdministratorGuard::refuseDeletingTheLast);
        if (agentSponsorship != null) {
            target.map(Users::getUsername).ifPresent(agentSponsorship::refuseRemovingTheSponsor);
        }
        try {
            String admin = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) admin = auth.getName();
            final String auditAdmin = admin;

            target.ifPresent(user ->
                    centralAuditFacade.recordAsync(AuditRecord.builder()
                            .eventCategory(AuditEventCategory.USER_DELETED)
                            .principalName(auditAdmin)
                            .resourceIdentifier(user.getUsername() != null ? user.getUsername() : "")
                            .eventSource("IAM")
                            .action("USER_DELETED")
                            .decision("SUCCESS")
                            .outcome("SUCCESS")
                            .details(Map.of(
                                    "userId", user.getId() != null ? user.getId() : 0L,
                                    "username", user.getUsername() != null ? user.getUsername() : ""))
                            .build()));
        } catch (Exception e) {
            log.error("Failed to audit user deletion: id={}", id, e);
        }
        // These rows reference the account without cascade, so the deletion would otherwise fail.
        userRolePermissionRepository.deleteByUserId(id);
        if (bridgeUserProfileRepository.existsById(id)) {
            bridgeUserProfileRepository.deleteById(id);
        }
        userRepository.deleteById(id);
        target.map(Users::getUsername)
                .ifPresent(username -> eventPublisher.publishEvent(new UserAccountDeletedEvent(id, username)));
    }
}
