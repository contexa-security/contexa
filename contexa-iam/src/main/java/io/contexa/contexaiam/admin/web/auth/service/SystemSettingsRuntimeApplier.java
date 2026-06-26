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

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        apply();
    }

    public void apply() {
        HcadProperties hcadProperties = hcadPropertiesProvider.getIfAvailable();
        if (hcadProperties == null) {
            return;
        }
        HcadRuntimeSettings settings = runtimeSettingsService.getHcadRuntimeSettings();
        applyHcadSettings(hcadProperties, settings);
    }

    public static void applyHcadSettings(HcadProperties hcadProperties, HcadRuntimeSettings settings) {
        if (hcadProperties == null || settings == null) {
            return;
        }
        hcadProperties.getPreTrigger().setMediumRiskScore(settings.mediumRiskScore());
        hcadProperties.getPreTrigger().setHighRiskScore(settings.highRiskScore());
        hcadProperties.getPreTrigger().setRedlineScore(settings.redlineScore());
        hcadProperties.getPreTrigger().setFailedLoginBurstThreshold(settings.failedLoginBurstThreshold());
        hcadProperties.getPreTrigger().setRequestBurstThreshold(settings.requestBurstThreshold());
        hcadProperties.getSemanticEvidence().setRiskSimilarityThreshold(settings.semanticRiskSimilarityThreshold());
        hcadProperties.getSemanticEvidence().setNormalSimilarityThreshold(settings.semanticNormalSimilarityThreshold());
        log.info("System runtime settings applied to HCAD thresholds: medium={}, high={}, redline={}",
                settings.mediumRiskScore(), settings.highRiskScore(), settings.redlineScore());
    }
}