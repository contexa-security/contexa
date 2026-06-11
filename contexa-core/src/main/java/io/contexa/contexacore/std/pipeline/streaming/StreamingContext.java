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
package io.contexa.contexacore.std.pipeline.streaming;

import io.contexa.contexacore.utils.SentenceBuffer;
import lombok.Getter;

/**
 * Complete streaming context with sentence buffering support.
 * Extends BaseStreamingContext and integrates SentenceBuffer for converting
 * LLM chunk output into complete sentences for streaming to clients.
 *
 * <p>This class is the primary entry point for custom streaming implementations.
 * It provides all functionality needed to handle LLM streaming responses,
 * including chunk accumulation, marker detection, and sentence-level buffering.</p>
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * StreamingProperties properties = ...; // injected via Spring
 * StreamingContext context = new StreamingContext(properties);
 *
 * return aiProcessor.processStream(request)
 *     .flatMap(chunk -> {
 *         context.appendChunk(chunk);
 *         if (context.isFinalResponseStarted()) {
 *             return Flux.empty();
 *         }
 *         return context.getSentenceBuffer().processChunk(chunk)
 *             .map(sentence -> ServerSentEvent.builder().data(sentence).build());
 *     });
 * }</pre>
 */
@Getter
public class StreamingContext extends BaseStreamingContext {

    private final SentenceBuffer sentenceBuffer;

    public StreamingContext(StreamingProperties properties) {
        super(properties);
        this.sentenceBuffer = new SentenceBuffer();
    }

}
