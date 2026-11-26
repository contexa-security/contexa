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
package io.contexa.autoconfigure.ownership;

import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.Embedding;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.List;

/**
 * What every application of the grid has: a chat model and an embedding model that never leave the machine (the decisions
 * are off in the grid, so no model is asked anything; a model only has to exist for Contexa to start), and the host's
 * pages.
 */
abstract class GridModels {

    static final int DIMENSIONS = 128;

    @Bean
    ChatModel gridChatModel() {
        return new ChatModel() {
            @Override
            public ChatResponse call(Prompt prompt) {
                return new ChatResponse(List.of(new Generation(new AssistantMessage(
                        "{\"riskScore\":0.05,\"confidence\":0.95,\"action\":\"ALLOW\",\"reasoning\":\"grid\"}"))));
            }

            @Override
            public ChatOptions getDefaultOptions() {
                return ChatOptions.builder().build();
            }
        };
    }

    @Bean
    EmbeddingModel gridEmbeddingModel() {
        return new EmbeddingModel() {
            @Override
            public EmbeddingResponse call(EmbeddingRequest request) {
                List<Embedding> embeddings = new ArrayList<>();
                for (int index = 0; index < request.getInstructions().size(); index++) {
                    embeddings.add(new Embedding(unit(), index));
                }
                return new EmbeddingResponse(embeddings);
            }

            @Override
            public float[] embed(Document document) {
                return unit();
            }

            @Override
            public int dimensions() {
                return DIMENSIONS;
            }
        };
    }

    @Bean
    GridController gridController() {
        return new GridController();
    }

    private static float[] unit() {
        float[] vector = new float[DIMENSIONS];
        vector[0] = 1f;
        return vector;
    }
}
