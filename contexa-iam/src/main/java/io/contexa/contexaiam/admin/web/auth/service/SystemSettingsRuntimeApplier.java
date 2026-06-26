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

import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService.HcadRuntimeSettings;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

@Slf4j
@RequiredArgsConstructor
public class SystemSettingsRuntimeApplier implements ApplicationListener<ApplicationReadyEvent> {

    private final SystemRuntimeSettingsService runtimeSettingsService;
    private final ObjectProvider<HcadProperties> hcadPropertiesProvider;
    private final ObjectProvider<SecurityZeroTrustProperties> zeroTrustPropertiesProvider;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        apply();
    }

    public void apply() {
        HcadRuntimeSettings settings = runtimeSettingsService.getHcadRuntimeSettings();
        HcadProperties hcadProperties = hcadPropertiesProvider.getIfAvailable();
        if (hcadProperties != null) {
            applyHcadSettings(hcadProperties, settings);
        }
        SecurityZeroTrustProperties zeroTrustProperties = zeroTrustPropertiesProvider.getIfAvailable();
        if (zeroTrustProperties != null) {
            applyZeroTrustSettings(zeroTrustProperties, runtimeSettingsService.getSecurityZeroTrustMode());
        }
    }

    public static void applyHcadSettings(HcadProperties hcadProperties, HcadRuntimeSettings settings) {
        if (hcadProperties == null || settings == null) {
            return;
        }
        hcadProperties.getPreTrigger().setMode(settings.preTriggerMode());
        hcadProperties.getPreTrigger().setMediumRiskScore(settings.mediumRiskScore());
        hcadProperties.getPreTrigger().setHighRiskScore(settings.highRiskScore());
        hcadProperties.getPreTrigger().setRedlineScore(settings.redlineScore());
        hcadProperties.getPreTrigger().setFailedLoginBurstThreshold(settings.failedLoginBurstThreshold());
        hcadProperties.getPreTrigger().setRequestBurstThreshold(settings.requestBurstThreshold());
        hcadProperties.getSemanticEvidence().setRiskSimilarityThreshold(settings.semanticRiskSimilarityThreshold());
        hcadProperties.getSemanticEvidence().setNormalSimilarityThreshold(settings.semanticNormalSimilarityThreshold());
        log.info("System runtime settings applied to HCAD: mode={}, medium={}, high={}, redline={}",
                settings.preTriggerMode(), settings.mediumRiskScore(), settings.highRiskScore(), settings.redlineScore());
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