package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordChangeController;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordPolicyController;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@AutoConfiguration
public class IamAdminPasswordPolicyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicyService passwordPolicyService(PasswordPolicyRepository passwordPolicyRepository) {
        return new PasswordPolicyService(passwordPolicyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicyController passwordPolicyController(PasswordPolicyService passwordPolicyService) {
        return new PasswordPolicyController(passwordPolicyService);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordChangeController passwordChangeController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicyService) {
        return new PasswordChangeController(userRepository, passwordEncoder, passwordPolicyService);
    }
}
