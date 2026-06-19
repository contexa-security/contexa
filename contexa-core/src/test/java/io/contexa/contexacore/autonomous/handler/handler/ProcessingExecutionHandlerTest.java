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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProcessingExecutionHandlerTest {

    @Mock
    private ProcessingStrategy aiAnalysisStrategy;

    private ProcessingExecutionHandler handler;

    @BeforeEach
    void setUp() {
        when(aiAnalysisStrategy.supports(ProcessingMode.AI_ANALYSIS)).thenReturn(true);
        when(aiAnalysisStrategy.getSupportedMode()).thenReturn(ProcessingMode.AI_ANALYSIS);
        handler = new ProcessingExecutionHandler(List.of(aiAnalysisStrategy));
    }

    @Test
    @DisplayName("Should select matching strategy and execute processing")
    void shouldSelectStrategyAndExecute() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-1")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        context.addMetadata("processingMode", ProcessingMode.AI_ANALYSIS);

        ProcessingResult expectedResult = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .build();
        when(aiAnalysisStrategy.process(any(SecurityEventContext.class))).thenReturn(expectedResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(aiAnalysisStrategy).process(context);
        assertThat(context.getMetadata().get("processingResult")).isEqualTo(expectedResult);
    }

    @Test
    @DisplayName("Null processing mode should default to AI_ANALYSIS")
    void nullMode_shouldDefaultToAiAnalysis() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-2")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        // processingMode not set -> null

        ProcessingResult expectedResult = ProcessingResult.builder()
                .success(true)
                .build();
        when(aiAnalysisStrategy.process(any(SecurityEventContext.class))).thenReturn(expectedResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        assertThat(context.getMetadata().get("processingMode")).isEqualTo(ProcessingMode.AI_ANALYSIS);
    }

    @Test
    @DisplayName("Failed processing result should continue to decision observation handlers")
    void failedProcessingResult_shouldContinueToDecisionObservationHandlers() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-failure")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult failedResult = ProcessingResult.builder()
                .success(false)
                .message("LLM execution failed")
                .build();
        when(aiAnalysisStrategy.process(any(SecurityEventContext.class))).thenReturn(failedResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        assertThat(context.getMetadata().get("processingResult")).isEqualTo(failedResult);
        assertThat(context.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
    }

    @Test
    @DisplayName("Processing exception should continue to decision observation handlers with failed result")
    void processingException_shouldContinueToDecisionObservationHandlersWithFailedResult() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-exception")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        when(aiAnalysisStrategy.process(any(SecurityEventContext.class)))
                .thenThrow(new IllegalStateException("No runtime LLM client is configured"));

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        assertThat(context.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
        assertThat(context.getMetadata().get("processingExceptionType"))
                .isEqualTo(IllegalStateException.class.getName());
        assertThat(context.getMetadata().get("processingResult"))
                .isInstanceOfSatisfying(ProcessingResult.class, failedResult -> {
                    assertThat(failedResult.isSuccess()).isFalse();
                    assertThat(failedResult.getErrorMessage()).contains("No runtime LLM client");
                    assertThat(failedResult.getStatus()).isEqualTo(ProcessingResult.ProcessingStatus.FAILED);
                });
    }

    @Test
    @DisplayName("No matching strategy should mark context as failed")
    void noMatchingStrategy_shouldFail() {
        // given
        ProcessingStrategy soarStrategy = new ProcessingStrategy() {
            @Override
            public ProcessingResult process(SecurityEventContext context) {
                return ProcessingResult.builder().success(true).build();
            }

            @Override
            public ProcessingMode getSupportedMode() {
                return ProcessingMode.SOAR_ORCHESTRATION;
            }

            @Override
            public boolean supports(ProcessingMode mode) {
                return mode == ProcessingMode.SOAR_ORCHESTRATION;
            }
        };

        ProcessingExecutionHandler handlerWithNoMatch = new ProcessingExecutionHandler(List.of(soarStrategy));

        SecurityEvent event = SecurityEvent.builder()
                .userId("user-3")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        context.addMetadata("processingMode", ProcessingMode.AI_ANALYSIS);

        // when
        boolean result = handlerWithNoMatch.handle(context);

        // then
        assertThat(result).isFalse();
        assertThat(context.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
    }

    @Test
    @DisplayName("getOrder should return 50")
    void getOrder_shouldReturn50() {
        // when
        int order = handler.getOrder();

        // then
        assertThat(order).isEqualTo(50);
    }
}
