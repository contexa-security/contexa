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
package io.contexa.contexacore.std.pipeline.executor;

import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface PipelineExecutor {

    <T extends DomainContext, R extends AIResponse> Mono<R> execute(
            AIRequest<T> request,
            PipelineConfiguration configuration,
            Class<R> responseType);

    <T extends DomainContext> Flux<String> executeStream(
            AIRequest<T> request, 
            PipelineConfiguration configuration);

    String getSupportedDomain();

    <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration configuration);

    default int getPriority() {
        return 100;
    }

    /**
     * Indicates whether this executor supports streaming operations.
     * Used by PipelineOrchestrator to select the appropriate executor
     * based on PipelineConfiguration.enableStreaming setting.
     *
     * @return true if this executor supports streaming, false otherwise
     */
    default boolean supportsStreaming() {
        return false;
    }
} 