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
package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
public class PreprocessingStep implements PipelineStep {
    
    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        long stepStartTime = System.currentTimeMillis();
        return Mono.fromCallable(() -> {
            String systemMetadata = buildSystemMetadata(request);
            context.addStepResult(PipelineConfiguration.PipelineStep.PREPROCESSING, systemMetadata);
            return systemMetadata;
        }).cast(Object.class).doFinally(signalType -> {
            long elapsedMs = System.currentTimeMillis() - stepStartTime;
            context.addMetadata("preprocessingMs", elapsedMs);
            log.info("[PIPELINE-STEP] Preprocessing completed - Request: {}, Signal: {}, Duration: {}ms",
                    request.getRequestId(), signalType, elapsedMs);
        });
    }
    protected <T extends DomainContext> String buildSystemMetadata(AIRequest<T> request) {
        return "";
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.PREPROCESSING;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && request.getRequestId() != null;
    }
    
    @Override
    public int getOrder() {
        return 2; 
    }
} 
