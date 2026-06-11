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
package io.contexa.contexacore.std.labs;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AILab<Req, Res> {

    String getLabId();

    String getLabName();

    Res process(Req request);

    Mono<Res> processAsync(Req request);

    Flux<String> processStream(Req request);

    default boolean supportsStreaming() {
        return false;
    }

    default boolean isActive() {
        return true;
    }

    default boolean canProcess(Req request) {
        return request != null && isActive();
    }
}