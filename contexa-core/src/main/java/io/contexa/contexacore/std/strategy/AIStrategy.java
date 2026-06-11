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
package io.contexa.contexacore.std.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AIStrategy<T extends DomainContext, R extends AIResponse> {

    DiagnosisType getSupportedType();

    int getPriority();

    R execute(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    Mono<R> executeAsync(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    Flux<String> executeStream(AIRequest<T> request, Class<R> responseType) throws DiagnosisException;

    default boolean supportsStreaming() {
        return false;
    }
}
