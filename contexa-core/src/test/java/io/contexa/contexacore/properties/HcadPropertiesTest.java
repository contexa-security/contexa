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

import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class HcadPropertiesTest {

    @Test
    @DisplayName("HCAD pre-trigger mode defaults to shadow")
    void preTriggerMode_shouldDefaultToShadow() {
        HcadProperties properties = new HcadProperties();

        assertThat(properties.getPreTrigger().getMode()).isEqualTo(HcadPreTriggerMode.SHADOW);
        assertThat(properties.getPreTrigger().effectiveMode()).isEqualTo(HcadPreTriggerMode.SHADOW);
        assertThat(properties.getPreTrigger().shouldPublishLlmEvent()).isTrue();
        assertThat(properties.getPreTrigger().getQualification().getShadowMinPrecision()).isEqualTo(0.80);
        assertThat(properties.getPreTrigger().getQualification().getLimitedEnforceMinPrecision()).isEqualTo(0.90);
        assertThat(properties.getPreTrigger().getQualification().getDefaultEnforceMinPrecision()).isEqualTo(0.95);
        assertThat(properties.getPreTrigger().getQualification().getMinimumSampleSize()).isEqualTo(100);
        assertThat(properties.getPreTrigger().getLlmRateLimit().isEnabled()).isTrue();
        assertThat(properties.getPreTrigger().getLlmRateLimit().getMaxTriggersPerWindow()).isEqualTo(120);
        assertThat(properties.getPreTrigger().getLlmRateLimit().getWindowSeconds()).isEqualTo(60);
        assertThat(properties.getPreTrigger().getLlmRateLimit().getScope()).isEqualTo("GLOBAL");
    }

    @Test
    @DisplayName("pre-trigger.enabled=false forces disabled mode")
    void disabledFlag_shouldForceDisabledMode() {
        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().setEnabled(false);
        properties.getPreTrigger().setMode(HcadPreTriggerMode.ENFORCE);

        assertThat(properties.getPreTrigger().effectiveMode()).isEqualTo(HcadPreTriggerMode.DISABLED);
        assertThat(properties.getPreTrigger().shouldEvaluate()).isFalse();
        assertThat(properties.getPreTrigger().shouldPublishLlmEvent()).isFalse();
    }

    @Test
    @DisplayName("pre-trigger mode and qualification thresholds bind from configuration")
    void preTriggerMode_shouldBindFromConfiguration() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.hcad.pre-trigger.mode", "observe")
                .withProperty("contexa.hcad.pre-trigger.qualification.shadow-min-precision", "0.81")
                .withProperty("contexa.hcad.pre-trigger.qualification.limited-enforce-min-precision", "0.91")
                .withProperty("contexa.hcad.pre-trigger.qualification.default-enforce-min-precision", "0.96")
                .withProperty("contexa.hcad.pre-trigger.qualification.minimum-sample-size", "150")
                .withProperty("contexa.hcad.pre-trigger.llm-rate-limit.enabled", "true")
                .withProperty("contexa.hcad.pre-trigger.llm-rate-limit.max-triggers-per-window", "17")
                .withProperty("contexa.hcad.pre-trigger.llm-rate-limit.window-seconds", "30")
                .withProperty("contexa.hcad.pre-trigger.llm-rate-limit.scope", "USER");

        HcadProperties properties = Binder.get(environment)
                .bind("contexa.hcad", Bindable.of(HcadProperties.class))
                .orElseThrow(IllegalStateException::new);

        assertThat(properties.getPreTrigger().effectiveMode()).isEqualTo(HcadPreTriggerMode.OBSERVE);
        assertThat(properties.getPreTrigger().shouldEvaluate()).isTrue();
        assertThat(properties.getPreTrigger().shouldPublishLlmEvent()).isFalse();
        assertThat(properties.getPreTrigger().getQualification().getShadowMinPrecision()).isEqualTo(0.81);
        assertThat(properties.getPreTrigger().getQualification().getLimitedEnforceMinPrecision()).isEqualTo(0.91);
        assertThat(properties.getPreTrigger().getQualification().getDefaultEnforceMinPrecision()).isEqualTo(0.96);
        assertThat(properties.getPreTrigger().getQualification().getMinimumSampleSize()).isEqualTo(150);
        assertThat(properties.getPreTrigger().getLlmRateLimit().getMaxTriggersPerWindow()).isEqualTo(17);
        assertThat(properties.getPreTrigger().getLlmRateLimit().getWindowSeconds()).isEqualTo(30);
        assertThat(properties.getPreTrigger().getLlmRateLimit().getScope()).isEqualTo("USER");
    }
}
