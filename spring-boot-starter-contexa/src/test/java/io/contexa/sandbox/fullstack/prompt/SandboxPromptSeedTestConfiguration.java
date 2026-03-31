package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * sandbox full-stack prompt 검증용 seed 구성.
 *
 * 기본 smoke 사용자를 자동 생성하고, 반복 벤치마크에서는 같은 provisioner로
 * 추가 사용자를 계속 만들 수 있게 구성한다.
 */
@TestConfiguration(proxyBeanMethods = false)
public class SandboxPromptSeedTestConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SandboxPromptSeedTestConfiguration.class);

    @Bean
    public SandboxPromptUserProvisioner sandboxPromptUserProvisioner(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            PasswordPolicyRepository passwordPolicyRepository,
            PasswordEncoder passwordEncoder,
            TransactionTemplate transactionTemplate) {
        return new SandboxPromptUserProvisioner(
                userRepository,
                roleRepository,
                permissionRepository,
                passwordPolicyRepository,
                passwordEncoder,
                transactionTemplate);
    }

    @Bean
    public ApplicationRunner sandboxPromptSeedDataInitializer(
            SandboxPromptUserProvisioner sandboxPromptUserProvisioner,
            @Value("${sandbox.prompt.username}") String username,
            @Value("${sandbox.prompt.password}") String rawPassword) {

        return arguments -> {
            sandboxPromptUserProvisioner.ensurePromptAdminUser(username, rawPassword);
            log.info("[SandboxPromptSeed] Seeded sandbox user={}, roles=[{}], permissions=[{}, {}]",
                    username,
                    SandboxPromptUserProvisioner.ROLE_ADMIN,
                    SandboxPromptUserProvisioner.PERMISSION_SENSITIVE_READ,
                    SandboxPromptUserProvisioner.PERMISSION_CRITICAL_READ);
        };
    }
}
