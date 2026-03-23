package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordPolicyController;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

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
}
