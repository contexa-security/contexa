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
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService.PolicyDecisionSettings;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    @DisplayName("should read stored policy decision settings")
    void readsPolicyDecisionSettings() {
        SystemSettingsRepository repository = mock(SystemSettingsRepository.class);
        when(repository.findAll()).thenReturn(List.of(SystemSettings.builder()
                .policyCombiningAlgorithm("DENY_UNLESS_PERMIT")
                .noMatchingUrlPolicyDecision("DENY")
                .missingMethodPolicyDecision("PERMIT")
                .build()));

        Optional<PolicyDecisionSettings> settings =
                new SystemRuntimeSettingsService(repository).findPolicyDecisionSettings();

        assertThat(settings).contains(new PolicyDecisionSettings(
                CombiningAlgorithm.DENY_UNLESS_PERMIT, NoPolicyDecision.DENY, NoPolicyDecision.PERMIT));
    }

    @Test
    @DisplayName("should return empty policy decision settings when the settings row does not exist")
    void emptyWithoutSettingsRow() {
        SystemSettingsRepository repository = mock(SystemSettingsRepository.class);
        when(repository.findAll()).thenReturn(List.of());

        assertThat(new SystemRuntimeSettingsService(repository).findPolicyDecisionSettings()).isEmpty();
    }

    @Test
    @DisplayName("should default new policy decision columns to PERMIT")
    void defaultsArePermit() {
        SystemSettings defaults = SystemRuntimeSettingsService.defaultSettings();

        assertThat(defaults.getNoMatchingUrlPolicyDecision()).isEqualTo("PERMIT");
        assertThat(defaults.getMissingMethodPolicyDecision()).isEqualTo("PERMIT");
        assertThat(defaults.getPolicyCombiningAlgorithm()).isEqualTo("FIRST_APPLICABLE");
    }

    @Test
    @DisplayName("should accept only exact enum constant names")
    void parsesOnlyEnumNames() {
        assertThat(SystemRuntimeSettingsService.parseNoPolicyDecision("field", "DENY")).isEqualTo(NoPolicyDecision.DENY);
        assertThat(SystemRuntimeSettingsService.parseCombiningAlgorithm("PERMIT_OVERRIDES"))
                .isEqualTo(CombiningAlgorithm.PERMIT_OVERRIDES);
        assertThatThrownBy(() -> SystemRuntimeSettingsService.parseNoPolicyDecision("field", "deny"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SystemRuntimeSettingsService.parseNoPolicyDecision("field", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SystemRuntimeSettingsService.parseCombiningAlgorithm("T(java.lang.Runtime)"))
                .isInstanceOf(IllegalArgumentException.class);
    }

}
