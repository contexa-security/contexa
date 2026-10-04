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

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService.PolicyDecisionSettings;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

import java.util.Optional;

/**
 * Applies operator settings stored in {@code system_settings} to runtime components.
 *
 * <p>Policy decision settings (combining algorithm, no-matching URL policy decision and missing
 * method policy decision) are applied once all singletons exist, before the web server accepts
 * requests, and again when the application is ready and after every settings save. The URL policy
 * enforcement point keeps its own copy of the URL values; method policy plans read the shared
 * {@link PolicyCombiningProperties} bean on every invocation.</p>
 */
@Slf4j
public class SystemSettingsRuntimeApplier
        implements ApplicationListener<ApplicationReadyEvent>, SmartInitializingSingleton {

    private final SystemRuntimeSettingsService runtimeSettingsService;
    private final ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider;
    private final ObjectProvider<PolicyCombiningProperties> policyCombiningPropertiesProvider;
    private final ObjectProvider<CustomDynamicAuthorizationManager> authorizationManagerProvider;

    public SystemSettingsRuntimeApplier(
            SystemRuntimeSettingsService runtimeSettingsService,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider) {
        this(runtimeSettingsService, zeroTrustPropertiesProvider, null, null);
    }

    public SystemSettingsRuntimeApplier(
            SystemRuntimeSettingsService runtimeSettingsService,
            ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider,
            ObjectProvider<PolicyCombiningProperties> policyCombiningPropertiesProvider,
            ObjectProvider<CustomDynamicAuthorizationManager> authorizationManagerProvider) {
        this.runtimeSettingsService = runtimeSettingsService;
        this.zeroTrustPropertiesProvider = zeroTrustPropertiesProvider;
        this.policyCombiningPropertiesProvider = policyCombiningPropertiesProvider;
        this.authorizationManagerProvider = authorizationManagerProvider;
    }

    @Override
    public void afterSingletonsInstantiated() {
        applyPolicyDecisionSettings();
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        apply();
    }

    /**
     * Applies all stored settings. A zero trust mode saved by an operator replaces the configured
     * {@code contexa.security.zerotrust.mode}; when no mode is stored the configured value stays
     * in effect.
     */
    public void apply() {
        SecurityZeroTrustProperties zeroTrustProperties = zeroTrustPropertiesProvider.getIfAvailable();
        if (zeroTrustProperties != null) {
            runtimeSettingsService.findSecurityZeroTrustMode()
                    .ifPresent(mode -> applyZeroTrustSettings(zeroTrustProperties, mode));
        }
        applyPolicyDecisionSettings();
    }

    /**
     * Reads the stored policy decision settings and applies them. When the settings row does not
     * exist the configured {@code contexa.policy.*} values stay in effect. When a stored value is
     * invalid the current runtime values are kept.
     */
    public void applyPolicyDecisionSettings() {
        Optional<PolicyDecisionSettings> settings;
        try {
            settings = runtimeSettingsService.findPolicyDecisionSettings();
        } catch (RuntimeException e) {
            log.error("Failed to load policy decision settings from system settings, current values are kept", e);
            return;
        }
        settings.ifPresent(value -> applyPolicyDecisionSettings(
                policyCombiningPropertiesProvider != null ? policyCombiningPropertiesProvider.getIfAvailable() : null,
                authorizationManagerProvider != null ? authorizationManagerProvider.getIfAvailable() : null,
                value));
    }

    public static void applyPolicyDecisionSettings(
            PolicyCombiningProperties policyCombiningProperties,
            CustomDynamicAuthorizationManager authorizationManager,
            PolicyDecisionSettings settings) {
        if (settings == null) {
            return;
        }
        if (policyCombiningProperties != null) {
            policyCombiningProperties.setCombiningAlgorithm(settings.combiningAlgorithm());
            policyCombiningProperties.setNoMatchingUrlPolicyDecision(settings.noMatchingUrlPolicyDecision());
            policyCombiningProperties.setMissingMethodPolicyDecision(settings.missingMethodPolicyDecision());
        }
        if (authorizationManager != null) {
            authorizationManager.setCombiningAlgorithm(settings.combiningAlgorithm());
            authorizationManager.setNoMatchingUrlPolicyDecision(settings.noMatchingUrlPolicyDecision());
        }
    }

    public static void applyZeroTrustSettings(
            SecurityZeroTrustProperties zeroTrustProperties,
            SecurityZeroTrustProperties.SecurityMode mode) {
        if (zeroTrustProperties == null || mode == null) {
            return;
        }
        zeroTrustProperties.setMode(mode);
        log.info("System runtime settings applied to AI decision mode: {}", mode);
    }

}
