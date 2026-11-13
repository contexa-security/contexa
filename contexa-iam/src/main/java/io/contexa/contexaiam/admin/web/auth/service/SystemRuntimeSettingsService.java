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

    public static final SecurityZeroTrustProperties.EnforcementMode DEFAULT_SECURITY_ZEROTRUST_MODE = SecurityZeroTrustProperties.EnforcementMode.SHADOW;
    public static final String DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES = "io.contexa.contexaiam.";
    public static final CombiningAlgorithm DEFAULT_POLICY_COMBINING_ALGORITHM = CombiningAlgorithm.FIRST_APPLICABLE;
    /** What applies to a URL no policy names while no operator chose a decision and no property says otherwise. */
    public static final NoPolicyDecision DEFAULT_NO_MATCHING_URL_POLICY_DECISION = NoPolicyDecision.AUTHENTICATED;
    public static final NoPolicyDecision DEFAULT_MISSING_METHOD_POLICY_DECISION = NoPolicyDecision.PERMIT;

    private final SystemSettingsRepository repository;

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public SystemSettings getSettings() {
        return repository.findAll().stream()
                .findFirst()
                .orElseGet(SystemRuntimeSettingsService::defaultSettings);
    }

    /**
     * Returns the zero trust mode saved by an operator, or empty when the settings row does not
     * exist or its mode is not set so that the {@code contexa.security.zerotrust.mode} property
     * value stays in effect.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<SecurityZeroTrustProperties.EnforcementMode> findSecurityZeroTrustMode() {
        return repository.findAll().stream()
                .findFirst()
                .map(SystemSettings::getSecurityZeroTrustMode)
                .filter(StringUtils::hasText)
                .map(SystemRuntimeSettingsService::normalizeSecurityZeroTrustMode);
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
     * not exist yet so that the {@code contexa.policy.*} property values stay in effect. The decision for
     * URLs no policy names is {@code null} while no operator saved one, and the property value stays in
     * effect for it.
     *
     * @throws IllegalArgumentException when a stored value is not a valid enum constant
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<PolicyDecisionSettings> findPolicyDecisionSettings() {
        return repository.findAll().stream()
                .findFirst()
                .map(settings -> new PolicyDecisionSettings(
                        parseCombiningAlgorithm(settings.getPolicyCombiningAlgorithm()),
                        parseChosenNoMatchingUrlPolicyDecision(settings.getNoMatchingUrlPolicyDecision()),
                        parseMissingMethodPolicyDecision(settings.getMissingMethodPolicyDecision())));
    }

    public static SystemSettings defaultSettings() {
        return SystemSettings.builder()
                .policyCombiningAlgorithm(DEFAULT_POLICY_COMBINING_ALGORITHM.name())
                .missingMethodPolicyDecision(DEFAULT_MISSING_METHOD_POLICY_DECISION.name())
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

    /**
     * Parses the decision for URLs no policy names that an operator saved: {@code null} when none was saved (the column
     * holds NULL or blank), so that nothing but a saved value ever replaces the configured decision.
     *
     * @throws IllegalArgumentException when a stored value is not a {@link NoPolicyDecision}
     */
    public static NoPolicyDecision parseChosenNoMatchingUrlPolicyDecision(String storedValue) {
        return StringUtils.hasText(storedValue) ? parseNoPolicyDecision("noMatchingUrlPolicyDecision", storedValue) : null;
    }

    /**
     * Parses the decision for methods without a policy: PERMIT or DENY. AUTHENTICATED is a decision for URL requests
     * and is refused here like any other unsupported value.
     *
     * @throws IllegalArgumentException when the value is blank, not a {@link NoPolicyDecision} or AUTHENTICATED
     */
    public static NoPolicyDecision parseMissingMethodPolicyDecision(String rawValue) {
        NoPolicyDecision decision = parseNoPolicyDecision("missingMethodPolicyDecision", rawValue);
        if (decision == NoPolicyDecision.AUTHENTICATED) {
            throw new IllegalArgumentException("missingMethodPolicyDecision has an unsupported value: " + rawValue);
        }
        return decision;
    }

    /** The decisions an operator may choose for methods without a policy. */
    public static List<NoPolicyDecision> missingMethodPolicyDecisionOptions() {
        return List.of(NoPolicyDecision.PERMIT, NoPolicyDecision.DENY);
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

    /**
     * Parses a zero trust mode, in any case and with '-' for '_'; a blank value is the default mode.
     *
     * @throws IllegalArgumentException when the value names no mode, with the field and the value (not the JDK's text of
     *                                  a failed enum lookup, which names the class)
     */
    public static SecurityZeroTrustProperties.EnforcementMode normalizeSecurityZeroTrustMode(String rawValue) {
        String value = StringUtils.hasText(rawValue) ? rawValue.trim() : DEFAULT_SECURITY_ZEROTRUST_MODE.name();
        String name = value.replace('-', '_').toUpperCase(Locale.ROOT);
        for (SecurityZeroTrustProperties.EnforcementMode mode : SecurityZeroTrustProperties.EnforcementMode.values()) {
            if (mode.name().equals(name)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("securityZeroTrustMode has an unsupported value: " + rawValue);
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

    /**
     * The packages a scan covers: the ones set in the console and the application's own, so that the methods and
     * controllers of an application are found without anyone naming its package. The setting only adds to them.
     */
    public static List<String> withApplicationPackages(List<String> configured, List<String> applicationPackages) {
        Set<String> packages = new LinkedHashSet<>(configured);
        for (String applicationPackage : applicationPackages) {
            // the default package is no prefix: it would turn the scan into a scan of every bean
            if (StringUtils.hasText(applicationPackage)) {
                packages.add(normalizePackagePrefix(applicationPackage));
            }
        }
        return List.copyOf(packages);
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
     * Operator-controlled policy decision settings persisted in {@code ctxa_system_settings}.
     * {@code noMatchingUrlPolicyDecision} is {@code null} while no operator saved one.
     */
    public record PolicyDecisionSettings(
            CombiningAlgorithm combiningAlgorithm,
            NoPolicyDecision noMatchingUrlPolicyDecision,
            NoPolicyDecision missingMethodPolicyDecision) {
    }

}
