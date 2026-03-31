package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * sandbox 전용 사용자 fixture.
 *
 * 실제 HTTP/MFA 흐름을 여러 번 반복하려면 매 실행마다 독립적인 사용자를 만들 수 있어야 한다.
 * 이 provisioner는 sandbox schema 안에서만 최소 역할/권한을 갖춘 사용자를 생성한다.
 */
public class SandboxPromptUserProvisioner {

    static final String ROLE_ADMIN = "ADMIN";
    static final String PERMISSION_SENSITIVE_READ = "SECURITY_TEST_SENSITIVE_READ";
    static final String PERMISSION_CRITICAL_READ = "SECURITY_TEST_CRITICAL_READ";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordPolicyRepository passwordPolicyRepository;
    private final PasswordEncoder passwordEncoder;
    private final TransactionTemplate transactionTemplate;

    public SandboxPromptUserProvisioner(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            PasswordPolicyRepository passwordPolicyRepository,
            PasswordEncoder passwordEncoder,
            TransactionTemplate transactionTemplate) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.passwordPolicyRepository = passwordPolicyRepository;
        this.passwordEncoder = passwordEncoder;
        this.transactionTemplate = transactionTemplate;
    }

    public Users ensurePromptAdminUser(String username, String rawPassword) {
        return transactionTemplate.execute(status -> {
            ensurePasswordPolicy();

            Permission sensitiveReadPermission = permissionRepository.findByName(PERMISSION_SENSITIVE_READ)
                    .orElseGet(() -> permissionRepository.save(Permission.builder()
                            .name(PERMISSION_SENSITIVE_READ)
                            .friendlyName("Sandbox Sensitive Resource Read")
                            .description("sandbox full-stack prompt test sensitive resource permission")
                            .targetType("HTTP_ENDPOINT")
                            .actionType("READ")
                            .build()));

            Permission criticalReadPermission = permissionRepository.findByName(PERMISSION_CRITICAL_READ)
                    .orElseGet(() -> permissionRepository.save(Permission.builder()
                            .name(PERMISSION_CRITICAL_READ)
                            .friendlyName("Sandbox Critical Resource Read")
                            .description("sandbox full-stack prompt test critical resource permission")
                            .targetType("HTTP_ENDPOINT")
                            .actionType("READ")
                            .build()));

            Role adminRole = roleRepository.findByRoleName(ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(createRole(
                            ROLE_ADMIN,
                            "sandbox full-stack administrator role",
                            Set.of(sensitiveReadPermission, criticalReadPermission))));

            return userRepository.findByUsername(username)
                    .orElseGet(() -> {
                        Users sandboxAdmin = Users.builder()
                                .username(username)
                                .email(username)
                                .password(passwordEncoder.encode(rawPassword))
                                .name("Sandbox Prompt Admin")
                                .department("Security Engineering")
                                .position("Administrator")
                                .enabled(true)
                                .accountLocked(false)
                                .credentialsExpired(false)
                                .failedLoginAttempts(0)
                                .mfaEnabled(true)
                                .preferredMfaFactor("MFA_OTT")
                                .lastUsedMfaFactor("MFA_OTT")
                                .locale("ko")
                                .timezone("Asia/Seoul")
                                .bridgeManaged(true)
                                .externalAuthOnly(false)
                                .authenticationSource("LOCAL")
                                .principalType("USER")
                                .organizationId("sandbox")
                                .bridgeSubjectKey("sandbox:" + username)
                                .build();

                        UserRole adminAssignment = UserRole.builder()
                                .user(sandboxAdmin)
                                .role(adminRole)
                                .assignedBy("sandbox-test")
                                .build();

                        sandboxAdmin.getUserRoles().add(adminAssignment);
                        return userRepository.save(sandboxAdmin);
                    });
        });
    }

    private void ensurePasswordPolicy() {
        if (passwordPolicyRepository.count() == 0) {
            passwordPolicyRepository.save(PasswordPolicy.builder()
                    .minLength(4)
                    .maxLength(128)
                    .requireUppercase(false)
                    .requireLowercase(false)
                    .requireDigit(false)
                    .requireSpecialChar(false)
                    .maxFailedAttempts(5)
                    .lockoutDurationMinutes(30)
                    .passwordExpiryDays(90)
                    .historyCount(1)
                    .build());
        }
    }

    private Role createRole(String roleName, String description, Set<Permission> permissions) {
        Role role = Role.builder()
                .roleName(roleName)
                .roleDesc(description)
                .enabled(true)
                .expression(false)
                .createdBy("sandbox-test")
                .build();

        Set<RolePermission> assignments = new LinkedHashSet<>();
        for (Permission permission : permissions) {
            assignments.add(RolePermission.builder()
                    .role(role)
                    .permission(permission)
                    .assignedBy("sandbox-test")
                    .build());
        }
        role.setRolePermissions(assignments);
        return role;
    }
}
