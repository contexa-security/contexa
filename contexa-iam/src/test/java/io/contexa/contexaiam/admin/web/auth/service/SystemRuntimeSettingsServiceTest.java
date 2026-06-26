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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SystemRuntimeSettingsService")
class SystemRuntimeSettingsServiceTest {

    @Test
    @DisplayName("should normalize blank package prefixes to default")
    void defaultPackagePrefixes() {
        List<String> prefixes = SystemRuntimeSettingsService.normalizePackagePrefixes("  ");

        assertThat(prefixes).containsExactly("io.contexa.contexaiam.");
    }

    @Test
    @DisplayName("should normalize comma and line separated package prefixes")
    void normalizePackagePrefixes() {
        String raw = "io.contexa.contexaiam,\nio.contexa.contexaiamenterprise.\nio.contexa.contexaiam";

        List<String> prefixes = SystemRuntimeSettingsService.normalizePackagePrefixes(raw);

        assertThat(prefixes).containsExactly("io.contexa.contexaiam.", "io.contexa.contexaiamenterprise.");
        assertThat(SystemRuntimeSettingsService.normalizePackagePrefixesForStorage(raw))
                .isEqualTo("io.contexa.contexaiam.\nio.contexa.contexaiamenterprise.");
    }

    @Test
    @DisplayName("should apply HCAD runtime settings to mutable properties")
    void applyHcadRuntimeSettings() {
        HcadProperties properties = new HcadProperties();
        HcadRuntimeSettings settings = new HcadRuntimeSettings(31, 52, 73, 4, 18, 0.81d, 0.91d);

        SystemSettingsRuntimeApplier.applyHcadSettings(properties, settings);

        assertThat(properties.getPreTrigger().getMediumRiskScore()).isEqualTo(31);
        assertThat(properties.getPreTrigger().getHighRiskScore()).isEqualTo(52);
        assertThat(properties.getPreTrigger().getRedlineScore()).isEqualTo(73);
        assertThat(properties.getPreTrigger().getFailedLoginBurstThreshold()).isEqualTo(4);
        assertThat(properties.getPreTrigger().getRequestBurstThreshold()).isEqualTo(18);
        assertThat(properties.getSemanticEvidence().getRiskSimilarityThreshold()).isEqualTo(0.81d);
        assertThat(properties.getSemanticEvidence().getNormalSimilarityThreshold()).isEqualTo(0.91d);
    }
}