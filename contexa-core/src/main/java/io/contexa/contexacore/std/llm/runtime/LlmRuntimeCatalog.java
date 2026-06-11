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
package io.contexa.contexacore.std.llm.runtime;

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;

import java.util.List;
import java.util.Optional;

public interface LlmRuntimeCatalog {

    List<LlmRuntimeBinding> getChatBindings();

    List<LlmRuntimeBinding> getEmbeddingBindings();

    Optional<LlmRuntimeBinding> findChatBinding(String selector);

    Optional<LlmRuntimeBinding> findEmbeddingBinding(String selector);

    ChatModel resolveChatModel(String selector);

    EmbeddingModel resolveEmbeddingModel(String selector);

    Optional<ChatModel> resolvePrimaryChatModel(String priorityConfig);

    Optional<EmbeddingModel> resolvePrimaryEmbeddingModel(String priorityConfig);

    Optional<ChatModel> resolveSpringPrimaryChatModel();

    Optional<EmbeddingModel> resolveSpringPrimaryEmbeddingModel();
}