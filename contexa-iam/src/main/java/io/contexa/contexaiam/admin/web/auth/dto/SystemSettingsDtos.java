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
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import lombok.Data;

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
        private String policyCombiningAlgorithm = "FIRST_APPLICABLE";
        private boolean registrationEnabled = false;
        private int hcadMediumRiskScore = SystemRuntimeSettingsService.DEFAULT_HCAD_MEDIUM_RISK_SCORE;
        private int hcadHighRiskScore = SystemRuntimeSettingsService.DEFAULT_HCAD_HIGH_RISK_SCORE;
        private int hcadRedlineScore = SystemRuntimeSettingsService.DEFAULT_HCAD_REDLINE_SCORE;
        private int hcadFailedLoginBurstThreshold = SystemRuntimeSettingsService.DEFAULT_HCAD_FAILED_LOGIN_BURST_THRESHOLD;
        private int hcadRequestBurstThreshold = SystemRuntimeSettingsService.DEFAULT_HCAD_REQUEST_BURST_THRESHOLD;
        private double hcadSemanticRiskSimilarityThreshold = SystemRuntimeSettingsService.DEFAULT_HCAD_SEMANTIC_RISK_SIMILARITY_THRESHOLD;
        private double hcadSemanticNormalSimilarityThreshold = SystemRuntimeSettingsService.DEFAULT_HCAD_SEMANTIC_NORMAL_SIMILARITY_THRESHOLD;
        private String hcadPreTriggerMode = SystemRuntimeSettingsService.DEFAULT_HCAD_PRE_TRIGGER_MODE.name();
        private String securityZeroTrustMode = SystemRuntimeSettingsService.DEFAULT_SECURITY_ZEROTRUST_MODE.name();
        private String mvcResourceScannerBasePackages = SystemRuntimeSettingsService.DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES;

        public static SystemSettingsForm from(SystemSettings entity) {
            SystemSettings source = entity == null ? SystemRuntimeSettingsService.defaultSettings() : entity;
            SystemSettingsForm form = new SystemSettingsForm();
            form.setAuditLogRetentionDays(source.getAuditLogRetentionDays());
            form.setDefaultRole(source.getDefaultRole());
            form.setPolicyCombiningAlgorithm(source.getPolicyCombiningAlgorithm());
            form.setRegistrationEnabled(source.isRegistrationEnabled());
            form.setHcadMediumRiskScore(source.getHcadMediumRiskScore());
            form.setHcadHighRiskScore(source.getHcadHighRiskScore());
            form.setHcadRedlineScore(source.getHcadRedlineScore());
            form.setHcadFailedLoginBurstThreshold(source.getHcadFailedLoginBurstThreshold());
            form.setHcadRequestBurstThreshold(source.getHcadRequestBurstThreshold());
            form.setHcadSemanticRiskSimilarityThreshold(source.getHcadSemanticRiskSimilarityThreshold());
            form.setHcadSemanticNormalSimilarityThreshold(source.getHcadSemanticNormalSimilarityThreshold());
            form.setHcadPreTriggerMode(SystemRuntimeSettingsService.normalizeHcadPreTriggerModeForStorage(source.getHcadPreTriggerMode()));
            form.setSecurityZeroTrustMode(SystemRuntimeSettingsService.normalizeSecurityZeroTrustModeForStorage(source.getSecurityZeroTrustMode()));
            form.setMvcResourceScannerBasePackages(
                    SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(source.getMvcResourceScannerBasePackages()));
            return form;
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