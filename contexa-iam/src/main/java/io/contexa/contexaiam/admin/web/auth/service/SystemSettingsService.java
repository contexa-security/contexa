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
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.RoleOption;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

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
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
@RequiredArgsConstructor
public class SystemSettingsService {

    private final SystemSettingsRepository repository;
    private final RoleRepository roleRepository;
    private SecurityZeroTrustProperties zeroTrustProperties;

    /** The mode in effect, which the form shows while no mode is stored; without it a submitted mode is stored. */
    public void setZeroTrustProperties(SecurityZeroTrustProperties zeroTrustProperties) {
        this.zeroTrustProperties = zeroTrustProperties;
    }

    private PolicyCombiningProperties policyCombiningProperties;

    /**
     * The decision for URLs no policy names in effect, which the form shows while no decision is stored; without it a
     * submitted decision is stored.
     */
    public void setPolicyCombiningProperties(PolicyCombiningProperties policyCombiningProperties) {
        this.policyCombiningProperties = policyCombiningProperties;
    }

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
        NoPolicyDecision chosenUrlDecision = chosenNoMatchingUrlDecision(existing, form);
        existing.setAuditLogRetentionDays(form.getAuditLogRetentionDays());
        existing.setDefaultRole(form.getDefaultRole());
        existing.setPolicyCombiningAlgorithm(
                SystemRuntimeSettingsService.parseCombiningAlgorithm(form.getPolicyCombiningAlgorithm()).name());
        if (chosenUrlDecision != null) {
            existing.setNoMatchingUrlPolicyDecision(chosenUrlDecision.name());
        }
        existing.setMissingMethodPolicyDecision(SystemRuntimeSettingsService.parseMissingMethodPolicyDecision(
                form.getMissingMethodPolicyDecision()).name());
        existing.setRegistrationEnabled(form.isRegistrationEnabled());
        if (operatorChoseMode(existing, form)) {
            existing.setSecurityZeroTrustMode(
                    SystemRuntimeSettingsService.normalizeSecurityZeroTrustModeForStorage(form.getSecurityZeroTrustMode()));
        }
        existing.setMvcResourceScannerBasePackages(
                SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(form.getMvcResourceScannerBasePackages()));
        repository.save(existing);
    }

    /**
     * While no mode is stored {@code contexa.security.zerotrust.mode} applies, and the form shows that mode. A save
     * of any other setting sends it back, and storing it would freeze the mode: the setting of the next deployment would
     * no longer apply, without a word. So a form that names no mode, or the mode in effect, chose nothing. Choosing the
     * mode in effect on purpose looks the same; the setting keeps deciding then, which is what the operator sees.
     */
    private boolean operatorChoseMode(SystemSettings existing, SystemSettingsForm form) {
        if (StringUtils.hasText(existing.getSecurityZeroTrustMode()) || zeroTrustProperties == null) {
            return true;
        }
        return StringUtils.hasText(form.getSecurityZeroTrustMode())
                && SystemRuntimeSettingsService.normalizeSecurityZeroTrustMode(form.getSecurityZeroTrustMode())
                != zeroTrustProperties.getMode();
    }

    /**
     * While no decision is stored, {@code contexa.policy.no-matching-url-policy-decision} applies and the form shows the
     * decision in effect. A save of any other setting sends it back, and storing it would freeze the decision: the setting
     * of the next deployment would no longer apply, without a word. So a form that names no decision, or the decision in
     * effect, chose nothing (null here). A decision already stored follows the form, which must name one. Choosing the
     * decision in effect on purpose looks the same as choosing nothing; the setting keeps deciding then, which is what the
     * operator sees.
     *
     * @return the decision to store, null when the form chose none
     * @throws IllegalArgumentException when the decision is not a {@link NoPolicyDecision}, or is missing where one is stored
     */
    private NoPolicyDecision chosenNoMatchingUrlDecision(SystemSettings existing, SystemSettingsForm form) {
        boolean stored = StringUtils.hasText(existing.getNoMatchingUrlPolicyDecision());
        boolean inEffectKnown = policyCombiningProperties != null;
        if (!stored && inEffectKnown && !StringUtils.hasText(form.getNoMatchingUrlPolicyDecision())) {
            return null;
        }
        NoPolicyDecision submitted = SystemRuntimeSettingsService.parseNoPolicyDecision(
                "noMatchingUrlPolicyDecision", form.getNoMatchingUrlPolicyDecision());
        if (stored || !inEffectKnown) {
            return submitted;
        }
        return submitted != policyCombiningProperties.getNoMatchingUrlPolicyDecision() ? submitted : null;
    }

    private void validate(SystemSettingsForm form) {
        if (form == null) {
            throw new IllegalArgumentException("Settings form is required.");
        }
        validateRange("auditLogRetentionDays", form.getAuditLogRetentionDays(), 0, 3650);
        SystemRuntimeSettingsService.parseCombiningAlgorithm(form.getPolicyCombiningAlgorithm());
        if (StringUtils.hasText(form.getNoMatchingUrlPolicyDecision())) {
            SystemRuntimeSettingsService.parseNoPolicyDecision(
                    "noMatchingUrlPolicyDecision", form.getNoMatchingUrlPolicyDecision());
        }
        SystemRuntimeSettingsService.parseMissingMethodPolicyDecision(form.getMissingMethodPolicyDecision());
        SystemRuntimeSettingsService.normalizeSecurityZeroTrustModeForStorage(form.getSecurityZeroTrustMode());
        SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(form.getMvcResourceScannerBasePackages());
    }

    private void validateRange(String field, int value, int min, int max) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(field + " must be between " + min + " and " + max + ".");
        }
    }

}
