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
package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * W6-9 (P6-CHANGE-6): after the decision, the cold path runs the shadow bundle on its copy of the event as it came,
 * and the decision's own result is the one it returns.
 */
class ColdPathShadowRunTest {

    @Test
    void theShadowRunAnalysesTheCopyAfterTheDecisionAndTheDecisionStays() {
        Layer1ContextualStrategy layer1 = mock(Layer1ContextualStrategy.class);
        when(layer1.evaluate(any())).thenReturn(ThreatAssessment.builder().riskScore(0.1).confidence(0.9)
                .action(ZeroTrustAction.ALLOW.name()).reasoning("Normal").shouldEscalate(false).build());
        LlmAnalysisEventListener listener = mock(LlmAnalysisEventListener.class);
        ColdPathEventProcessor processor = new ColdPathEventProcessor(layer1, mock(Layer2ExpertStrategy.class),
                listener);
        List<SecurityEvent> sealed = new ArrayList<>();
        PromptBundleSelector selector = new PromptBundleSelector() {
            @Override
            public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
                return PromptBundleSelection.none();
            }

            @Override
            public PromptBundleSelection shadow(PromptGovernanceResolutionContext context, String subjectKey) {
                return new PromptBundleSelection(SecurityDecisionPromptBundles.DEFAULT.version(),
                        PromptBundleSelectionSource.SHADOW);
            }
        };
        processor.setShadowRunner(new PromptShadowRunner(selector, event -> new PromptGovernanceResolutionContext(
                "PLATFORM_GLOBAL", "cortex.security-decision", "SecurityDecisionStandard", null, null, null, null,
                Map.of()), Runnable::run, (copy, result) -> sealed.add(copy), 100, 10, Clock.systemUTC()));
        SecurityEvent event = SecurityEvent.builder().eventId("evt-cold").userId("user-1").build();
        event.addMetadata("requestPath", "/api/test");

        ProcessingResult result = processor.processEvent(event, 0.1);

        assertThat(result.getAction()).isEqualTo(ZeroTrustAction.ALLOW.name());
        ArgumentCaptor<SecurityEvent> analysed = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(layer1, times(2)).evaluate(analysed.capture());
        assertThat(analysed.getAllValues().get(0)).isSameAs(event);
        assertThat(analysed.getAllValues().get(1).getEventId()).isEqualTo("evt-cold:shadow");
        assertThat(sealed).hasSize(1);
        assertThat(event.getMetadata()).doesNotContainKey(PromptShadowRunner.SHADOW_RUN);
        // The live analysis of the user shows only the decision: the copy publishes nothing.
        verify(listener, times(1)).onContextCollected(eq("user-1"), eq("/api/test"), any());
        verify(listener, times(1)).onDecisionApplied(eq("user-1"), any(), eq("LAYER1"), eq("/api/test"), any());
    }
}
