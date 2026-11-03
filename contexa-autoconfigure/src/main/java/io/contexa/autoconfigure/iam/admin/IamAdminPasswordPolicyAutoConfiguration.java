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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.PasswordHistoryRepository;
import io.contexa.contexacommon.repository.PasswordPolicyRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordChangeController;
import io.contexa.contexaiam.admin.web.auth.controller.PasswordPolicyController;
import io.contexa.contexaiam.admin.web.auth.controller.SystemSettingsController;
import io.contexa.contexaiam.admin.web.auth.service.AuditLogRetentionScheduler;
import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@AutoConfiguration
public class IamAdminPasswordPolicyAutoConfiguration {

    @Bean(name = "contexaPasswordPolicyService")
    @ConditionalOnMissingBean
    public PasswordPolicyService passwordPolicyService(
            PasswordPolicyRepository passwordPolicyRepository,
            PasswordHistoryRepository passwordHistoryRepository,
            PasswordEncoder passwordEncoder) {
        return new PasswordPolicyService(passwordPolicyRepository, passwordHistoryRepository, passwordEncoder);
    }

    @Bean(name = "contexaPasswordPolicyController")
    @ConditionalOnMissingBean
    public PasswordPolicyController passwordPolicyController(PasswordPolicyService contexaPasswordPolicyService, MessageSource messageSource) {
        return new PasswordPolicyController(contexaPasswordPolicyService, messageSource);
    }

    @Bean(name = "contexaPasswordChangeService")
    @ConditionalOnMissingBean
    public PasswordChangeService passwordChangeService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService contexaPasswordPolicyService) {
        return new PasswordChangeService(userRepository, passwordEncoder, contexaPasswordPolicyService);
    }

    @Bean(name = "contexaPasswordChangeController")
    @ConditionalOnMissingBean
    public PasswordChangeController passwordChangeController(
            PasswordChangeService contexaPasswordChangeService,
            PasswordPolicyService contexaPasswordPolicyService,
            MessageSource messageSource) {
        return new PasswordChangeController(contexaPasswordChangeService, contexaPasswordPolicyService, messageSource);
    }

    @Bean(name = "contexaSystemRuntimeSettingsService")
    @ConditionalOnMissingBean
    public SystemRuntimeSettingsService systemRuntimeSettingsService(SystemSettingsRepository systemSettingsRepository) {
        return new SystemRuntimeSettingsService(systemSettingsRepository);
    }

    @Bean(name = "contexaSystemSettingsRuntimeApplier")
    @ConditionalOnMissingBean
    public SystemSettingsRuntimeApplier systemSettingsRuntimeApplier(
            SystemRuntimeSettingsService contexaSystemRuntimeSettingsService,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider,
            ObjectProvider<PolicyCombiningProperties> policyCombiningPropertiesProvider,
            ObjectProvider<CustomDynamicAuthorizationManager> authorizationManagerProvider) {
        return new SystemSettingsRuntimeApplier(contexaSystemRuntimeSettingsService, zeroTrustPropertiesProvider,
                policyCombiningPropertiesProvider, authorizationManagerProvider);
    }

    @Bean(name = "contexaSystemSettingsService")
    @ConditionalOnMissingBean
    public SystemSettingsService systemSettingsService(
            SystemSettingsRepository systemSettingsRepository,
            RoleRepository roleRepository) {
        return new SystemSettingsService(systemSettingsRepository, roleRepository);
    }

    @Bean(name = "contexaSystemSettingsController")
    @ConditionalOnMissingBean
    public SystemSettingsController systemSettingsController(
            PolicyCombiningProperties policyCombiningProperties,
            SystemSettingsService contexaSystemSettingsService,
            MessageSource messageSource,
            ObjectProvider<CustomDynamicAuthorizationManager> authManagerProvider,
            ObjectProvider<SystemSettingsRuntimeApplier> runtimeApplierProvider,
            ObjectProvider<PolicyReloadBroadcaster> policyReloadBroadcasterProvider,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider) {
        SystemSettingsController controller = new SystemSettingsController(contexaSystemSettingsService,
                policyCombiningProperties, messageSource, authManagerProvider.getIfAvailable(),
                runtimeApplierProvider.getIfAvailable());
        policyReloadBroadcasterProvider.ifAvailable(controller::setPolicyReloadBroadcaster);
        zeroTrustPropertiesProvider.ifAvailable(controller::setZeroTrustProperties);
        return controller;
    }

    @Bean(name = "contexaAuditLogRetentionScheduler")
    @ConditionalOnMissingBean
    public AuditLogRetentionScheduler auditLogRetentionScheduler(
            AuditLogRepository auditLogRepository,
            SystemSettingsService contexaSystemSettingsService) {
        return new AuditLogRetentionScheduler(auditLogRepository, contexaSystemSettingsService);
    }
}
