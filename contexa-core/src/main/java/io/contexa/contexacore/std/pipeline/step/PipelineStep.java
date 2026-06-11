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
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import reactor.core.publisher.Mono;

public interface PipelineStep {

    <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context);

    /**
     * Returns the corresponding PipelineConfiguration.PipelineStep for this step.
     * Used for configuration matching without string-based switch statements.
     */
    PipelineConfiguration.PipelineStep getConfigStep();

    /**
     * Returns the step name derived from the config step enum.
     * Default implementation uses getConfigStep().name() to avoid duplication.
     */
    default String getStepName() {
        return getConfigStep().name();
    }

    default <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null;
    }

    default int getOrder() {
        return 100;
    }
} 