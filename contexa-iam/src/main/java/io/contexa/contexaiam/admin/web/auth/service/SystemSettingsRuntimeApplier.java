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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

@Slf4j
@RequiredArgsConstructor
public class SystemSettingsRuntimeApplier implements ApplicationListener<ApplicationReadyEvent> {

    private final SystemRuntimeSettingsService runtimeSettingsService;
    private final ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        apply();
    }

    public void apply() {
        SecurityZeroTrustProperties zeroTrustProperties = zeroTrustPropertiesProvider.getIfAvailable();
        if (zeroTrustProperties != null) {
            applyZeroTrustSettings(zeroTrustProperties, runtimeSettingsService.getSecurityZeroTrustMode());
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
