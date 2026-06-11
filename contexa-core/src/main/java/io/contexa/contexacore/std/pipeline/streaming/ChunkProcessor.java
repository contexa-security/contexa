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

import reactor.core.publisher.Flux;

/**
 * Interface for processing streaming chunks.
 * Implementations transform raw streaming data into processed output.
 */
public interface ChunkProcessor {

    /**
     * Processes the upstream flux of chunks.
     *
     * @param upstream the source flux of raw chunks
     * @return processed flux of chunks
     */
    Flux<String> process(Flux<String> upstream);

    /**
     * Returns the processor type identifier.
     *
     * @return the processor type string
     */
    String getProcessorType();
}
