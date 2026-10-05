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
package io.contexa.contexaiam.admin.web.auth.dto;

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import lombok.Data;
import org.springframework.util.StringUtils;

/**
 * Form-binding DTOs for the {@code /contexa/admin/system-settings} screen.
 *
 * <p>Binding the form straight onto the {@link SystemSettings} entity exposes a
 * mass-assignment surface. Restricting the bindable fields to this DTO keeps the
 * contract explicit and ignores any other form parameter submitted by a client.</p>
 */
public final class SystemSettingsDtos {

    private SystemSettingsDtos() {
    }

    @Data
    public static class SystemSettingsForm {
        private int auditLogRetentionDays = 90;
        private String defaultRole = "ROLE_USER";
        private String policyCombiningAlgorithm = SystemRuntimeSettingsService.DEFAULT_POLICY_COMBINING_ALGORITHM.name();
        private String noMatchingUrlPolicyDecision = SystemRuntimeSettingsService.DEFAULT_NO_POLICY_DECISION.name();
        private String missingMethodPolicyDecision = SystemRuntimeSettingsService.DEFAULT_NO_POLICY_DECISION.name();
        private boolean registrationEnabled = false;
        private String securityZeroTrustMode = SystemRuntimeSettingsService.DEFAULT_SECURITY_ZEROTRUST_MODE.name();
        private String mvcResourceScannerBasePackages = SystemRuntimeSettingsService.DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES;

        public static SystemSettingsForm from(SystemSettings entity) {
            return from(entity, null);
        }

        /**
         * Builds the form from the stored settings.
         *
         * @param effectiveZeroTrustMode the zero trust mode in effect, shown when no mode is stored
         */
        public static SystemSettingsForm from(SystemSettings entity,
                                              SecurityZeroTrustProperties.SecurityMode effectiveZeroTrustMode) {
            SystemSettings source = entity == null ? SystemRuntimeSettingsService.defaultSettings() : entity;
            SystemSettingsForm form = new SystemSettingsForm();
            form.setAuditLogRetentionDays(source.getAuditLogRetentionDays());
            form.setDefaultRole(source.getDefaultRole());
            form.setPolicyCombiningAlgorithm(source.getPolicyCombiningAlgorithm());
            form.setNoMatchingUrlPolicyDecision(valueOrDefault(source.getNoMatchingUrlPolicyDecision(),
                    SystemRuntimeSettingsService.DEFAULT_NO_POLICY_DECISION.name()));
            form.setMissingMethodPolicyDecision(valueOrDefault(source.getMissingMethodPolicyDecision(),
                    SystemRuntimeSettingsService.DEFAULT_NO_POLICY_DECISION.name()));
            form.setRegistrationEnabled(source.isRegistrationEnabled());
            String storedZeroTrustMode = source.getSecurityZeroTrustMode();
            form.setSecurityZeroTrustMode(!StringUtils.hasText(storedZeroTrustMode) && effectiveZeroTrustMode != null
                    ? effectiveZeroTrustMode.name()
                    : SystemRuntimeSettingsService.normalizeSecurityZeroTrustModeForStorage(storedZeroTrustMode));
            form.setMvcResourceScannerBasePackages(
                    SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(source.getMvcResourceScannerBasePackages()));
            return form;
        }

        private static String valueOrDefault(String value, String defaultValue) {
            return value == null || value.isBlank() ? defaultValue : value;
        }
    }

    /**
     * Single role option rendered in the default-role drop-down. {@code value} is the
     * canonical role name persisted in {@link SystemSettings#getDefaultRole()}; {@code label}
     * is the human-readable text shown to the operator.
     */
    public record RoleOption(String value, String label) {
        public static RoleOption of(String roleName, String roleDesc) {
            String label = (roleDesc == null || roleDesc.isBlank())
                    ? roleName
                    : roleDesc + " (" + roleName + ")";
            return new RoleOption(roleName, label);
        }
    }
}
