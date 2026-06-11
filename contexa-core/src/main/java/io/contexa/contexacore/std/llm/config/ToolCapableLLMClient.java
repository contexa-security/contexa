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
package io.contexa.contexacore.std.llm.config;

import io.contexa.contexacore.std.llm.config.LLMClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

public interface ToolCapableLLMClient extends LLMClient {

    Mono<String> callTools(Prompt prompt, List<Object> toolProviders);
    Mono<String> callToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks);

    Mono<ChatResponse> callToolsResponse(Prompt prompt, List<Object> toolProviders);
    Mono<ChatResponse> callToolCallbacksResponse(Prompt prompt, ToolCallback[] toolCallbacks);

    Flux<String> streamTools(Prompt prompt, List<Object> toolProviders);
    Flux<String> streamToolCallbacks(Prompt prompt, ToolCallback[] toolCallbacks);
}
