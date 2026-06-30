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

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class PromptGenerationStep implements PipelineStep {

    private final PromptEvidenceComposer promptEvidenceComposer;

    public PromptGenerationStep(PromptGenerator promptGenerator) {
        this(promptGenerator, new TieredStrategyProperties());
    }

    public PromptGenerationStep(PromptGenerator promptGenerator, TieredStrategyProperties tieredStrategyProperties) {
        this.promptEvidenceComposer = new PromptEvidenceComposer(promptGenerator, tieredStrategyProperties);
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request,
            PipelineExecutionContext context) {

        long stepStartTime = System.currentTimeMillis();
        return Mono.fromCallable(() -> promptEvidenceComposer.compose(request, context).promptResult())
                .cast(Object.class)
                .doFinally(signalType -> {
                    long elapsedMs = System.currentTimeMillis() - stepStartTime;
                    context.addMetadata("pipelinePromptGenerationMs", elapsedMs);
                    log.info("[PIPELINE-STEP] Prompt generation completed - Request: {}, Signal: {}, Duration: {}ms",
                            request.getRequestId(), signalType, elapsedMs);
                });
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.PROMPT_GENERATION;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && promptEvidenceComposer.canCompose();
    }

    @Override
    public int getOrder() {
        return 3;
    }
}
