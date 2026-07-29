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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.RoleOption;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;

/**
 * Manages the singleton {@link SystemSettings} row.
 *
 * <p>The singleton row is seeded by {@code schema.sql} at boot, so {@link #getSettings()}
 * is purely read-only and cannot race a concurrent INSERT. The {@link SystemSettings#builder()}
 * fallback covers the unlikely case where the seed is missing without creating a duplicate row.</p>
 *
 * <p>Defence-in-depth: a method-level {@code @PreAuthorize} guard runs in addition to the
 * URL-pattern protection on {@code /contexa/admin/**}.</p>
 */
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class SystemSettingsService {

    private final SystemSettingsRepository repository;
    private final RoleRepository roleRepository;

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public SystemSettings getSettings() {
        return repository.findAll().stream()
                .findFirst()
                .orElseGet(SystemRuntimeSettingsService::defaultSettings);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<RoleOption> getDefaultRoleOptions() {
        return roleRepository.findAllRolesWithoutExpression().stream()
                .filter(Role::isEnabled)
                .sorted(Comparator.comparing(Role::getRoleName, String.CASE_INSENSITIVE_ORDER))
                .map(role -> RoleOption.of(role.getRoleName(), role.getRoleDesc()))
                .toList();
    }

    /**
     * Persists operator-supplied values onto the singleton row. Only fields carried by
     * {@link SystemSettingsForm} are written; entity identifiers and timestamps remain JPA-managed.
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateSettings(SystemSettingsForm form) {
        validate(form);
        SystemSettings existing = repository.findAll().stream()
                .findFirst()
                .orElseGet(() -> repository.save(SystemRuntimeSettingsService.defaultSettings()));
        existing.setAuditLogRetentionDays(form.getAuditLogRetentionDays());
        existing.setDefaultRole(form.getDefaultRole());
        existing.setPolicyCombiningAlgorithm(form.getPolicyCombiningAlgorithm());
        existing.setRegistrationEnabled(form.isRegistrationEnabled());
        existing.setSecurityZeroTrustMode(SystemRuntimeSettingsService.normalizeSecurityZeroTrustModeForStorage(form.getSecurityZeroTrustMode()));
        existing.setMvcResourceScannerBasePackages(
                SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(form.getMvcResourceScannerBasePackages()));
        repository.save(existing);
    }

    private void validate(SystemSettingsForm form) {
        if (form == null) {
            throw new IllegalArgumentException("Settings form is required.");
        }
        validateRange("auditLogRetentionDays", form.getAuditLogRetentionDays(), 0, 3650);
        SystemRuntimeSettingsService.normalizeSecurityZeroTrustModeForStorage(form.getSecurityZeroTrustMode());
        SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(form.getMvcResourceScannerBasePackages());
    }

    private void validateRange(String field, int value, int min, int max) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(field + " must be between " + min + " and " + max + ".");
        }
    }

}
