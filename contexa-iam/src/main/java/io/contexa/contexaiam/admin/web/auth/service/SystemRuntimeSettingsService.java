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
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class SystemRuntimeSettingsService {

    public static final SecurityZeroTrustProperties.SecurityMode DEFAULT_SECURITY_ZEROTRUST_MODE = SecurityZeroTrustProperties.SecurityMode.SHADOW;
    public static final String DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES = "io.contexa.contexaiam.";

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

    public static SystemSettings defaultSettings() {
        return SystemSettings.builder()
                .securityZeroTrustMode(DEFAULT_SECURITY_ZEROTRUST_MODE.name())
                .mvcResourceScannerBasePackages(DEFAULT_MVC_RESOURCE_SCANNER_BASE_PACKAGES)
                .build();
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

}
