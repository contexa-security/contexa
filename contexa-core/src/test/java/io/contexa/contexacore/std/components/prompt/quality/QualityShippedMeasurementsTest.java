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
package io.contexa.contexacore.std.components.prompt.quality;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.4: the measurements Contexa shipped of its versions are read from their document and used only for the same
 * version content, case set version and server settings; without the resource there is none.
 */
class QualityShippedMeasurementsTest {

    private static final String DOCUMENT = """
            {"format": 1, "measurements": [{
              "prompt": "cortex.security-decision", "release": "2026.11.18-v1.0",
              "versionContentHash": "content-a", "caseSetVersion": "set-a", "settingsHash": "settings-a",
              "modelSetting": "settings=settings-a;models=qwen3:8b", "repeats": 2,
              "measuredAt": "2026-11-30T00:00:00Z",
              "answers": [
                {"caseKey": "case-1", "run": 1, "firstAction": "BLOCK", "finalAction": "BLOCK", "reasked": false,
                 "decidedWithoutModel": false, "citedFacts": 3, "accurateCitedFacts": 2, "decisionMillis": 7000,
                 "answerTokens": 120, "measurementFailed": false, "failureReason": null},
                {"caseKey": "case-1", "run": 2, "firstAction": "ESCALATE", "finalAction": null,
                 "measurementFailed": true, "failureReason": "busy"}]}]}
            """;

    private static QualityShippedMeasurements read(String document) throws Exception {
        return QualityShippedMeasurements.read(new ByteArrayInputStream(document.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aShippedMeasurementIsReadWithItsAnswersAndItsModelSetting() throws Exception {
        QualityShippedMeasurements.Shipped shipped = read(DOCUMENT).all().get(0);

        assertThat(shipped.release()).isEqualTo("2026.11.18-v1.0");
        assertThat(shipped.repeats()).isEqualTo(2);
        assertThat(shipped.measuredAt()).isEqualTo(Instant.parse("2026-11-30T00:00:00Z"));
        assertThat(shipped.answers()).hasSize(2);
        assertThat(shipped.answers().get(0)).isEqualTo(new QualityAnswer("case-1", 1, QualityAction.BLOCK,
                QualityAction.BLOCK, false, false, 3, 2, 7000L, 120, false, null));
        assertThat(shipped.answers().get(1).measurementFailed()).isTrue();
        QualityMeasurement measurement = shipped.measurement("v1.0");
        assertThat(measurement.promptVersion()).isEqualTo("v1.0");
        assertThat(measurement.modelSetting()).isEqualTo("settings=settings-a;models=qwen3:8b");
        assertThat(measurement.caseSetVersion()).isEqualTo("set-a");
    }

    @Test
    void itIsUsedOnlyForTheSameContentCaseSetVersionAndSettings() throws Exception {
        QualityShippedMeasurements shipped = read(DOCUMENT);

        assertThat(shipped.find("cortex.security-decision", "content-a", "set-a", "settings-a")).isPresent();
        assertThat(shipped.find("cortex.security-decision", "content-b", "set-a", "settings-a")).isEmpty();
        assertThat(shipped.find("cortex.security-decision", "content-a", "set-b", "settings-a")).isEmpty();
        assertThat(shipped.find("cortex.security-decision", "content-a", "set-a", "settings-b")).isEmpty();
        assertThat(shipped.find("other.prompt", "content-a", "set-a", "settings-a")).isEmpty();
    }

    /**
     * Quality supplement P-1: the product ships the measurement of release v1.1.0 taken the product's way, on the
     * default case set this build ships, three runs of every case; it is of the content the build draws for v1.1.0.
     */
    @Test
    void theProductShipsTheMeasurementOfItsLatestReleaseOnTheDefaultSet() {
        AssembledPrompt release = SecurityDecisionPromptDocument.product();
        QualityCaseSet defaults = QualityCaseSetReader.contexaDefault();

        List<QualityShippedMeasurements.Shipped> shipped = QualityShippedMeasurements.contexa().all();

        assertThat(release.release()).isEqualTo("v1.1.0");
        assertThat(shipped).hasSize(1);
        QualityShippedMeasurements.Shipped measured = shipped.get(0);
        assertThat(measured.prompt()).isEqualTo(SecurityDecisionPromptDocument.PROMPT);
        assertThat(measured.release()).isEqualTo("v1.1.0");
        assertThat(measured.versionContentHash()).isEqualTo(release.contentHash());
        assertThat(measured.caseSetVersion()).isEqualTo(defaults.version());
        assertThat(measured.repeats()).isEqualTo(3);
        assertThat(measured.answers()).hasSize(210)
                .noneMatch(QualityAnswer::measurementFailed);
        assertThat(measured.modelSetting()).startsWith("settings=" + measured.settingsHash() + ";");
        Set<String> keys = defaults.cases().stream().map(QualityCase::key).collect(Collectors.toSet());
        assertThat(measured.answers().stream().map(answer -> answer.caseKey() + "#" + answer.run())
                .collect(Collectors.toSet())).hasSize(210);
        assertThat(measured.answers()).allSatisfy(answer -> {
            assertThat(keys).contains(answer.caseKey());
            assertThat(answer.run()).isBetween(1, 3);
        });
        assertThat(QualityShippedMeasurements.contexa().find(SecurityDecisionPromptDocument.PROMPT,
                release.contentHash(), defaults.version(), measured.settingsHash())).isPresent();
    }

    @Test
    void withoutTheResourceThereIsNoneAndADocumentOfAnotherFormatIsRefused() {
        assertThat(QualityShippedMeasurements.fromResource("prompt-quality/no-such-measurements.json").all())
                .isEmpty();
        assertThat(QualityShippedMeasurements.none().all()).isEmpty();
        // The product resource reads whether or not the release ships measurements.
        assertThat(QualityShippedMeasurements.contexa()).isNotNull();
        assertThatThrownBy(() -> read("{\"format\": 2, \"measurements\": []}"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
