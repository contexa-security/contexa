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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.PromptEvidenceComposer;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * N-L2-1: the second pass reads the first prompt the pipeline drew for the event, not a key a test puts by hand. The
 * composer keeps the first prompt of the event; the second analysis drawing again does not replace it.
 */
class FirstPassPromptHandOverTest {

    @Test
    void theSecondPassReadsTheFirstPromptTheComposerKept() {
        SecurityEvent event = SecurityEvent.builder().eventId("n-l2-1").userId("user-1")
                .metadata(new LinkedHashMap<>()).build();
        PromptGenerator generator = mock(PromptGenerator.class);
        when(generator.generatePrompt(any(), any(), any())).thenReturn(drawn("FIRST PROMPT"), drawn("SECOND PROMPT"));
        PromptEvidenceComposer composer = new PromptEvidenceComposer(generator);

        composer.compose(request(event), new PipelineExecutionContext("n-l2-1-first"));
        event.getMetadata().put("layer1Assessment", Map.of("llmAction", "ESCALATE", "llmDecisionPresent", true,
                "technicalFallbackApplied", false, "reasoning", "Business intent remains uncertain."));

        Layer2SecondPass.FirstPass first = Layer2SecondPass.FirstPass.of(event);
        assertThat(first.userPrompt()).isEqualTo("FIRST PROMPT");
        assertThat(first.givesASecondPass()).isTrue();

        composer.compose(request(event), new PipelineExecutionContext("n-l2-1-second"));

        assertThat(Layer2SecondPass.FirstPass.of(event).userPrompt()).isEqualTo("FIRST PROMPT");
    }

    private static PromptGenerationResult drawn(String userPrompt) {
        return new PromptGenerationResult(null, "SYSTEM", userPrompt,
                Map.of("userPromptLayoutVersion", Layer2SecondPass.V20_LAYOUT), null);
    }

    private static SecurityDecisionRequest request(SecurityEvent event) {
        return new SecurityDecisionRequest(new SecurityDecisionContext(event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of()));
    }
}
