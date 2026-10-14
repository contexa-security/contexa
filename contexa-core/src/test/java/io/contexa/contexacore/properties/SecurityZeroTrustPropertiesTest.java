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
package io.contexa.contexacore.properties;

import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityZeroTrustPropertiesTest {

    /** W4-4: the minimum-action rules start observing with the dictionary's defaults and bind their keys. */
    @Test
    void theMinimumActionRulesStartObservingWithTheDictionaryDefaults() {
        SecurityZeroTrustProperties defaults = new SecurityZeroTrustProperties();

        assertThat(defaults.getMinimumAction().getMode()).isEqualTo(SecurityZeroTrustProperties.MinimumActionMode.OBSERVE);
        assertThat(defaults.getMinimumAction().toRules()).isEqualTo(MinimumActionRules.Settings.DEFAULTS);

        SecurityZeroTrustProperties bound = new Binder(new MapConfigurationPropertySource(Map.of(
                "contexa.security.zerotrust.minimum-action.mode", "ENFORCE",
                "contexa.security.zerotrust.minimum-action.identity.min-deviations", "3",
                "contexa.security.zerotrust.minimum-action.policy-satisfaction.enabled", "false")))
                .bind("contexa.security.zerotrust", SecurityZeroTrustProperties.class).get();

        assertThat(bound.getMinimumAction().getMode()).isEqualTo(SecurityZeroTrustProperties.MinimumActionMode.ENFORCE);
        assertThat(bound.getMinimumAction().toRules())
                .isEqualTo(new MinimumActionRules.Settings(true, 3, "SENSITIVE", true, false));
    }

    @Test
    @DisplayName("DISABLED and OBSERVE must not allow AI decision analysis")
    void disabledAndObserve_shouldNotAllowLlmAnalysis() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();

        properties.setMode(SecurityZeroTrustProperties.SecurityMode.DISABLED);
        assertThat(properties.allowsLlmAnalysis()).isFalse();
        assertThat(properties.isEnforcementEnabled()).isFalse();

        properties.setMode(SecurityZeroTrustProperties.SecurityMode.OBSERVE);
        assertThat(properties.allowsLlmAnalysis()).isFalse();
        assertThat(properties.isEnforcementEnabled()).isFalse();
    }

    @Test
    @DisplayName("SHADOW and ENFORCE allow AI decision analysis, but only ENFORCE applies actions")
    void shadowAndEnforce_shouldSeparateAnalysisFromActionApplication() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();

        properties.setMode(SecurityZeroTrustProperties.SecurityMode.SHADOW);
        assertThat(properties.allowsLlmAnalysis()).isTrue();
        assertThat(properties.isEnforcementEnabled()).isFalse();

        properties.setMode(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
        assertThat(properties.allowsLlmAnalysis()).isTrue();
        assertThat(properties.isEnforcementEnabled()).isTrue();
    }
}
