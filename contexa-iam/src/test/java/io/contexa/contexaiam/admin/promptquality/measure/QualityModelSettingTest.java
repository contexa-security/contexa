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
package io.contexa.contexaiam.admin.promptquality.measure;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.3, K196: the model setting names the model each layer asks, its own else the primary chat model's,
 * and never the absence of a layer's own as a model; the time zone of the server is no setting (P24), since a case is
 * drawn in the time zone it fixes.
 */
class QualityModelSettingTest {

    @Test
    void aLayerWithNoModelOfItsOwnNamesThePrimaryChatModel() {
        TieredLLMProperties models = new TieredLLMProperties();

        Map<String, String> settings = QualityModelSetting.settings(new TieredStrategyProperties(), models,
                new SecurityZeroTrustProperties(), " qwen3:8b ");

        assertThat(settings).containsEntry(QualityModelSetting.FIRST_MODEL, "qwen3:8b")
                .containsEntry(QualityModelSetting.SECOND_MODEL, "qwen3:8b").doesNotContainKey("timeZone");
        assertThat(settings.values()).doesNotContain("qwen3:8b ");

        // A layer's own model comes before the primary chat model's.
        models.getLayer1().setModel("model-one");
        assertThat(QualityModelSetting.settings(new TieredStrategyProperties(), models, null, "qwen3:8b"))
                .containsEntry(QualityModelSetting.FIRST_MODEL, "model-one")
                .containsEntry(QualityModelSetting.SECOND_MODEL, "qwen3:8b");
    }

    @Test
    void aModelNamedNowhereIsLeftOutAndAnotherPrimaryModelIsAnotherSetting() {
        Map<String, String> none = QualityModelSetting.settings(new TieredStrategyProperties(),
                new TieredLLMProperties(), null);
        Map<String, String> qwen = QualityModelSetting.settings(new TieredStrategyProperties(),
                new TieredLLMProperties(), null, "qwen3:8b");
        Map<String, String> other = QualityModelSetting.settings(new TieredStrategyProperties(),
                new TieredLLMProperties(), null, "llama3.1:8b");

        assertThat(none).doesNotContainKeys(QualityModelSetting.FIRST_MODEL, QualityModelSetting.SECOND_MODEL);
        // A primary chat model changed under layers with no model of their own makes the measurements before stale.
        assertThat(QualityModelSetting.hash(qwen)).isNotEqualTo(QualityModelSetting.hash(other))
                .isNotEqualTo(QualityModelSetting.hash(none));
    }
}
