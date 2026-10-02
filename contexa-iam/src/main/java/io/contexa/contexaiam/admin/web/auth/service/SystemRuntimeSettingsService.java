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

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class SystemRuntimeSettingsService {

    public static final SecurityZeroTrustProperties.SecurityMode DEFAULT_SECURITY_ZEROTRUST_MODE = SecurityZeroTrustProperties.SecurityMode.SHADOW;
    public static final String DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES = "io.contexa.contexaiam.";
    public static final CombiningAlgorithm DEFAULT_POLICY_COMBINING_ALGORITHM = CombiningAlgorithm.FIRST_APPLICABLE;
    public static final NoPolicyDecision DEFAULT_NO_POLICY_DECISION = NoPolicyDecision.PERMIT;

    private final SystemSettingsRepository repository;

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public SystemSettings getSettings() {
        return repository.findAll().stream()
                .findFirst()
                .orElseGet(SystemRuntimeSettingsService::defaultSettings);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public SecurityZeroTrustProperties.SecurityMode getSecurityZeroTrustMode() {
        return normalizeSecurityZeroTrustMode(getSettings().getSecurityZeroTrustMode());
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<String> getMvcResourceScannerBasePackages() {
        return getResourceScannerBasePackages();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<String> getResourceScannerBasePackages() {
        return normalizePackagePrefixes(getSettings().getMvcResourceScannerBasePackages());
    }

    /**
     * Returns the policy decision settings stored in the singleton row, or empty when the row does
     * not exist yet so that the {@code contexa.policy.*} property values stay in effect.
     *
     * @throws IllegalArgumentException when a stored value is not a valid enum constant
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<PolicyDecisionSettings> findPolicyDecisionSettings() {
        return repository.findAll().stream()
                .findFirst()
                .map(settings -> new PolicyDecisionSettings(
                        parseCombiningAlgorithm(settings.getPolicyCombiningAlgorithm()),
                        parseNoPolicyDecision("noMatchingUrlPolicyDecision", settings.getNoMatchingUrlPolicyDecision()),
                        parseNoPolicyDecision("missingMethodPolicyDecision", settings.getMissingMethodPolicyDecision())));
    }

    public static SystemSettings defaultSettings() {
        return SystemSettings.builder()
                .policyCombiningAlgorithm(DEFAULT_POLICY_COMBINING_ALGORITHM.name())
                .noMatchingUrlPolicyDecision(DEFAULT_NO_POLICY_DECISION.name())
                .missingMethodPolicyDecision(DEFAULT_NO_POLICY_DECISION.name())
                .securityZeroTrustMode(DEFAULT_SECURITY_ZEROTRUST_MODE.name())
                .mvcResourceScannerBasePackages(DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES)
                .build();
    }

    /**
     * Parses a combining algorithm. Only exact enum constant names are accepted.
     *
     * @throws IllegalArgumentException when the value is blank or not a {@link CombiningAlgorithm}
     */
    public static CombiningAlgorithm parseCombiningAlgorithm(String rawValue) {
        return parseEnum(CombiningAlgorithm.class, "policyCombiningAlgorithm", rawValue);
    }

    /**
     * Parses a no-matching-policy decision. Only exact enum constant names are accepted.
     *
     * @throws IllegalArgumentException when the value is blank or not a {@link NoPolicyDecision}
     */
    public static NoPolicyDecision parseNoPolicyDecision(String field, String rawValue) {
        return parseEnum(NoPolicyDecision.class, field, rawValue);
    }

    private static <E extends Enum<E>> E parseEnum(Class<E> type, String field, String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            throw new IllegalArgumentException(field + " is required.");
        }
        for (E constant : type.getEnumConstants()) {
            if (constant.name().equals(rawValue.trim())) {
                return constant;
            }
        }
        throw new IllegalArgumentException(field + " has an unsupported value: " + rawValue);
    }

    public static SecurityZeroTrustProperties.SecurityMode normalizeSecurityZeroTrustMode(String rawValue) {
        String value = StringUtils.hasText(rawValue) ? rawValue.trim() : DEFAULT_SECURITY_ZEROTRUST_MODE.name();
        return SecurityZeroTrustProperties.SecurityMode.valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
    }

    public static String normalizeSecurityZeroTrustModeForStorage(String rawValue) {
        return normalizeSecurityZeroTrustMode(rawValue).name();
    }

    public static List<String> normalizePackagePrefixes(String rawValue) {
        String value = StringUtils.hasText(rawValue) ? rawValue : DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES;
        Set<String> normalized = Arrays.stream(value.split("[,\\r\\n]+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .map(SystemRuntimeSettingsService::normalizePackagePrefix)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (normalized.isEmpty()) {
            return List.of(DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES);
        }
        return List.copyOf(normalized);
    }

    public static String normalizePackagePrefixesForStorage(String rawValue) {
        return String.join("\n", normalizePackagePrefixes(rawValue));
    }

    private static String normalizePackagePrefix(String candidate) {
        String normalized = candidate.trim();
        while (normalized.endsWith("..")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.endsWith(".") ? normalized : normalized + ".";
    }

    /**
     * Operator-controlled policy decision settings persisted in {@code system_settings}.
     */
    public record PolicyDecisionSettings(
            CombiningAlgorithm combiningAlgorithm,
            NoPolicyDecision noMatchingUrlPolicyDecision,
            NoPolicyDecision missingMethodPolicyDecision) {
    }

}
