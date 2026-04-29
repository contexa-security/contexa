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
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
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
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
//    @Protectable
    public void modifyUser(@ModelAttribute UserDto userDto) {
        log.error("[UserManagementService.modifyUser] findByIdWithGroupsRolesAndPermissions id={}", userDto.getId());
        Users users = userRepository.findByIdWithGroupsRolesAndPermissions(userDto.getId())
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.user.not.found.id", userDto.getId())));

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
        if (StringUtils.hasText(userDto.getPassword())) {
            List<String> violations = passwordPolicyService.validatePassword(userDto.getPassword());
            if (!violations.isEmpty()) {
                throw new IllegalArgumentException(msg("msg.user.password.policy.violation", String.join(", ", violations)));
            }
            users.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        Set<Long> desiredGroupIds = userDto.getSelectedGroupIds() != null
                ? new HashSet<>(userDto.getSelectedGroupIds())
                : new HashSet<>();

        users.getUserGroups().clear();

        for (Long groupId : desiredGroupIds) {
            Group group = groupRepository.findById(groupId)
                    .orElseThrow(() -> new IllegalArgumentException(msg("msg.group.not.found.id", groupId)));
            UserGroup userGroup = UserGroup.builder()
                    .user(users)
                    .group(group)
                    .build();
            users.getUserGroups().add(userGroup);
        }

        userRepository.save(users);

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
                            "passwordChanged", StringUtils.hasText(userDto.getPassword())))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit user modification: {}", users.getUsername(), e);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
//    @Protectable
    public UserDto getUser(Long id) {
        log.error("[UserManagementService.getUser] findByIdWithGroupsRolesAndPermissions id={}", id);
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
//    @Protectable
    public List<UserListDto> getUsers() {
        return userRepository.findAllWithDetails().stream()
                .map(user -> {
                    UserListDto dto = modelMapper.map(user, UserListDto.class);
                    dto.setGroupCount(user.getUserGroups() != null ? user.getUserGroups().size() : 0);
                    long roleCount = user.getRoleNames().stream().distinct().count();
                    dto.setRoleCount((int) roleCount);
                    return dto;
                })
                .toList();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    @Protectable(ownerField = "username")
    public void deleteUser(Long id) {
        try {
            String admin = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) admin = auth.getName();
            final String auditAdmin = admin;

            userRepository.findById(id).ifPresent(user ->
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
        userRepository.deleteById(id);
    }
}
