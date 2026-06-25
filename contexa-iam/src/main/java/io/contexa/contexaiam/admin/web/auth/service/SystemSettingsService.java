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
 * fallback covers the unlikely case where the seed is missing (e.g. a manual TRUNCATE during
 * testing) without creating a duplicate row.</p>
 *
 * <p>Defence-in-depth: a method-level {@code @PreAuthorize} guard runs in addition to the
 * URL-pattern protection on {@code /contexa/admin/**}. If the SecurityFilterChain rule is ever
 * misconfigured, the service still rejects unauthenticated callers.</p>
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
                .orElseGet(() -> SystemSettings.builder().build());
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
     * Persists the operator-supplied values onto the singleton row. Only the four fields
     * carried by {@link SystemSettingsForm} are written; the entity's {@code id},
     * {@code createdAt}, and {@code updatedAt} are managed by JPA and never touched here.
     */
    @Transactional(transactionManager = "contexaTransactionManager")
    public void updateSettings(SystemSettingsForm form) {
        SystemSettings existing = repository.findAll().stream()
                .findFirst()
                .orElseGet(() -> repository.save(SystemSettings.builder().build()));
        existing.setAuditLogRetentionDays(form.getAuditLogRetentionDays());
        existing.setDefaultRole(form.getDefaultRole());
        existing.setPolicyCombiningAlgorithm(form.getPolicyCombiningAlgorithm());
        existing.setRegistrationEnabled(form.isRegistrationEnabled());
        repository.save(existing);
    }
}