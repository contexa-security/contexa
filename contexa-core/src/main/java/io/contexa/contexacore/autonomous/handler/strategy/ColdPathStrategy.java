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
package io.contexa.contexacore.autonomous.handler.strategy;

import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class ColdPathStrategy implements ProcessingStrategy {

    private final ColdPathEventProcessor coldPathProcessor;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        try {
            return coldPathProcessor.processEvent(context.getSecurityEvent(), 0.0);
        } catch (Exception e) {
            log.error("[ColdPathStrategy] Error processing event, defaulting to ESCALATE: {}", context.getSecurityEvent().getEventId(), e);
            return ProcessingResult.builder()
                .success(false)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .message("AI analysis processing failed")
                .build();
        }
    }

    @Override
    public ProcessingMode getSupportedMode() {
        return ProcessingMode.AI_ANALYSIS;
    }

    @Override
    public boolean supports(ProcessingMode mode) {
        return mode == ProcessingMode.AI_ANALYSIS;
    }
}
