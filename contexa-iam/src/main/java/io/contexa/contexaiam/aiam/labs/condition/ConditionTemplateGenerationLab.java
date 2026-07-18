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
package io.contexa.contexaiam.aiam.labs.condition;

import java.util.Objects;

import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;


@Slf4j
public class ConditionTemplateGenerationLab
        extends AbstractIAMLab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> {

    private final PipelineOrchestrator orchestrator;

    public ConditionTemplateGenerationLab(PipelineOrchestrator orchestrator) {
        super("ConditionTemplateGeneration", "2.0", LabSpecialization.RECOMMENDATION_SYSTEM);
        this.orchestrator = orchestrator;
    }

    @Override
    protected ConditionTemplateGenerationResponse doProcess(ConditionTemplateGenerationRequest request) {
        return processConditionTemplateAsync(request).block();
    }

    @Override
    protected Mono<ConditionTemplateGenerationResponse> doProcessAsync(
            ConditionTemplateGenerationRequest request) {
        return processConditionTemplateAsync(request);
    }

    private Mono<ConditionTemplateGenerationResponse> processConditionTemplateAsync(ConditionTemplateGenerationRequest request) {
        return orchestrator.execute(request, PipelineConfiguration.createPipelineConfig(), ConditionTemplateGenerationResponse.class)
                .map(response -> {
                    return Objects.requireNonNullElseGet(response, () -> createFailureResponse(request));
                })
                .onErrorResume(error -> {
                    log.error("Condition template async generation failed", error);
                    return Mono.just(createFailureResponse(request));
                });
    }

    private ConditionTemplateGenerationResponse createFailureResponse(
            ConditionTemplateGenerationRequest request) {
        String templateType = request.getContext().getTemplateType();
        String resourceId = request.getContext().getResourceIdentifier();
        return ConditionTemplateGenerationResponse.failure(
                templateType, resourceId, "Pipeline returned null or failed");
    }
}
