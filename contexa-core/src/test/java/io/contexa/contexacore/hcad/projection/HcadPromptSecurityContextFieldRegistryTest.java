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
package io.contexa.contexacore.hcad.projection;

import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionSignal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HcadPromptSecurityContextFieldRegistryTest {

    @Test
    @DisplayName("scoring is allowed only for registered prompt-standard trusted fields")
    void isScoringAllowed_registeredTrustedFieldsOnly() {
        assertThat(HcadPromptSecurityContextFieldRegistry.isScoringAllowed(
                "impossibleTravel",
                HcadTrustedSource.STORE_DERIVED)).isTrue();
        assertThat(HcadPromptSecurityContextFieldRegistry.isScoringAllowed(
                "authorizationPrivileged",
                HcadTrustedSource.BRIDGE_VERIFIED)).isTrue();
        assertThat(HcadPromptSecurityContextFieldRegistry.isScoringAllowed(
                "baselineComparison",
                HcadTrustedSource.STORE_DERIVED)).isTrue();

        assertThat(HcadPromptSecurityContextFieldRegistry.isScoringAllowed(
                "baselineConfidence",
                HcadTrustedSource.STORE_DERIVED)).isFalse();
        assertThat(HcadPromptSecurityContextFieldRegistry.isScoringAllowed(
                "contextBindingHash",
                HcadTrustedSource.TRUSTED_SERVER)).isFalse();
        assertThat(HcadPromptSecurityContextFieldRegistry.isScoringAllowed(
                "header.X-Contexa-Resource-Sensitivity",
                HcadTrustedSource.UNTRUSTED_IGNORED)).isFalse();
    }

    @Test
    @DisplayName("contract snapshot marks unknown and monitor-only fields as excluded from scoring")
    void scoringSnapshot_unknownAndMonitorOnlyFields_areExcluded() {
        Map<String, HcadFieldProvenance> provenance = Map.of(
                "baselineConfidence", HcadFieldProvenance.present(
                        "baselineConfidence",
                        HcadTrustedSource.STORE_DERIVED,
                        "monitor only"),
                "header.X-Contexa-Business-Impact", HcadFieldProvenance.ignored(
                        "header.X-Contexa-Business-Impact",
                        "client override"),
                "requestBurst", HcadFieldProvenance.present(
                        "requestBurst",
                        HcadTrustedSource.STORE_DERIVED,
                        "store"));

        Map<String, Object> snapshot = HcadPromptSecurityContextFieldRegistry.scoringSnapshot(provenance);

        assertThat(snapshot).containsEntry("contractVersion", HcadPromptSecurityContextFieldRegistry.version());
        assertThat(snapshot.get("excludedFields").toString())
                .contains("baselineConfidence")
                .contains("header.X-Contexa-Business-Impact");
        assertThat(snapshot.get("fields").toString())
                .contains("requestBurst")
                .contains("scoringAllowed=true");
    }

    @Test
    @DisplayName("every HCAD promotion signal is backed by scoring-allowed contract fields")
    void promotionSignals_allRequiredFieldsHaveScoringContracts() {
        for (HcadPreProtectablePromotionSignal signal : HcadPreProtectablePromotionSignal.values()) {
            assertThat(signal.requiredContractFields())
                    .as(signal.name())
                    .isNotEmpty();
            for (String field : signal.requiredContractFields()) {
                HcadPromptSecurityContextFieldContract contract =
                        HcadPromptSecurityContextFieldRegistry.contract(field);
                assertThat(contract)
                        .as(signal.name() + " -> " + field)
                        .isNotNull();
                assertThat(contract.scoringAllowed())
                        .as(signal.name() + " -> " + field)
                        .isTrue();
            }
        }
    }
}
