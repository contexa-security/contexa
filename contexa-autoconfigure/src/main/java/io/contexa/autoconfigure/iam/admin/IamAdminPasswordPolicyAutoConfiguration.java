package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.PasswordHistoryRepository;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordChangeController;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordPolicyController;
import io.contexa.contexaiam.admin.web.auth.controller.SystemSettingsController;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@AutoConfiguration
public class IamAdminPasswordPolicyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicyService passwordPolicyService(
            PasswordPolicyRepository passwordPolicyRepository,
            PasswordHistoryRepository passwordHistoryRepository,
            PasswordEncoder passwordEncoder) {
        return new PasswordPolicyService(passwordPolicyRepository, passwordHistoryRepository, passwordEncoder);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicyController passwordPolicyController(PasswordPolicyService passwordPolicyService, MessageSource messageSource) {
        return new PasswordPolicyController(passwordPolicyService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordChangeController passwordChangeController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicyService,
            MessageSource messageSource) {
        return new PasswordChangeController(userRepository, passwordEncoder, passwordPolicyService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public SystemSettingsService systemSettingsService(SystemSettingsRepository systemSettingsRepository) {
        return new SystemSettingsService(systemSettingsRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public SystemSettingsController systemSettingsController(
            SystemSettingsService systemSettingsService,
            MessageSource messageSource,
            org.springframework.beans.factory.ObjectProvider<io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager> authManagerProvider) {
        return new SystemSettingsController(systemSettingsService, messageSource, authManagerProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexaiam.admin.web.auth.service.AuditLogRetentionScheduler auditLogRetentionScheduler(
            io.contexa.contexacommon.repository.AuditLogRepository auditLogRepository,
            SystemSettingsService systemSettingsService) {
        return new io.contexa.contexaiam.admin.web.auth.service.AuditLogRetentionScheduler(auditLogRepository, systemSettingsService);
    }
}
