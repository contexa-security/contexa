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
package io.contexa.contexacore.std.components.prompt;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-6 (P6-CHANGE-4): every layer that called the model leaves one stage in the event: the prompt hashes it sent and
 * the answers it got (the first answer, the corrective retry and its reason, the answer it kept). The next layer
 * clears its own telemetry but not the stages before it.
 */
class ModelCallStagesTest {

    @Test
    void eachLayerLeavesItsOwnStage() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userPromptHash", "sha256:first");
        metadata.put("systemPromptHash", "sha256:system");
        metadata.put("securityDecisionInitialRawOutput", "{\"action\":\"ALLOW\"}");
        metadata.put("securityDecisionOutputRetryAttempted", true);
        metadata.put("securityDecisionOutputRetryReason", "REASON_CODE_MISMATCH");
        metadata.put("securityDecisionRawOutput", "{\"action\":\"ESCALATE\"}");

        PromptRuntimeTelemetrySupport.appendModelCallStage(metadata, "Layer1");
        // The second layer clears the first layer's telemetry and records its own call.
        PromptRuntimeTelemetrySupport.modelOutputRecordKeys().forEach(metadata::remove);
        metadata.put("userPromptHash", "sha256:first");
        metadata.put("securityDecisionRawOutput", "{\"action\":\"CHALLENGE\"}");
        PromptRuntimeTelemetrySupport.appendModelCallStage(metadata, "Layer2");

        List<?> stages = (List<?>) metadata.get(PromptRuntimeTelemetrySupport.MODEL_CALL_STAGES);
        assertThat(stages).hasSize(2);
        assertThat(map(stages.get(0))).containsEntry("layer", "Layer1")
                .containsEntry("userPromptHash", "sha256:first").containsEntry("systemPromptHash", "sha256:system")
                .containsEntry("securityDecisionInitialRawOutput", "{\"action\":\"ALLOW\"}")
                .containsEntry("securityDecisionOutputRetryReason", "REASON_CODE_MISMATCH")
                .containsEntry("securityDecisionRawOutput", "{\"action\":\"ESCALATE\"}");
        assertThat(map(stages.get(1))).containsEntry("layer", "Layer2")
                .containsEntry("securityDecisionRawOutput", "{\"action\":\"CHALLENGE\"}")
                .doesNotContainKey("securityDecisionOutputRetryReason");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value) {
        return (List<Object>) value;
    }
}
