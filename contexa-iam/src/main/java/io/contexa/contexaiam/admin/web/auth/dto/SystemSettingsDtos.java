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
import lombok.Data;

/**
 * Form-binding DTOs for the {@code /admin/system-settings} screen.
 *
 * <p>Binding the form straight onto the {@link SystemSettings} entity exposes a
 * mass-assignment surface (the client could submit {@code id}, {@code createdAt},
 * {@code updatedAt}, or any future entity field that gains a setter). Restricting the
 * bindable fields to this DTO keeps the contract explicit: only the four operator-editable
 * settings are accepted, and any other form parameter is ignored by Spring's data binder.</p>
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

        public static SystemSettingsForm from(SystemSettings entity) {
            SystemSettingsForm form = new SystemSettingsForm();
            form.setAuditLogRetentionDays(entity.getAuditLogRetentionDays());
            form.setDefaultRole(entity.getDefaultRole());
            form.setPolicyCombiningAlgorithm(entity.getPolicyCombiningAlgorithm());
            form.setRegistrationEnabled(entity.isRegistrationEnabled());
            return form;
        }
    }

    /**
     * Single role option rendered in the default-role drop-down. {@code value} is the
     * canonical role name persisted in {@link SystemSettings#getDefaultRole()}; {@code label}
     * is the human-readable text shown to the operator (role description with the canonical
     * name in parentheses, falling back to the canonical name when no description exists).
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
