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
package io.contexa.contexacore.std.components.prompt;

import org.springframework.ai.chat.prompt.Prompt;

import java.util.Map;

public class PromptGenerationResult {

    private final Prompt prompt;
    private final String systemPrompt;
    private final String userPrompt;
    private final String rawSystemPrompt;
    private final String rawUserPrompt;
    private final Map<String, Object> metadata;
    private final PromptExecutionMetadata promptExecutionMetadata;

    public PromptGenerationResult(
            Prompt prompt,
            String systemPrompt,
            String userPrompt,
            String rawSystemPrompt,
            String rawUserPrompt,
            Map<String, Object> metadata,
            PromptExecutionMetadata promptExecutionMetadata) {
        this.prompt = prompt;
        this.systemPrompt = systemPrompt;
        this.userPrompt = userPrompt;
        this.rawSystemPrompt = rawSystemPrompt;
        this.rawUserPrompt = rawUserPrompt;
        this.metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
        this.promptExecutionMetadata = promptExecutionMetadata;
    }

    public PromptGenerationResult(
            Prompt prompt,
            String systemPrompt,
            String userPrompt,
            Map<String, Object> metadata,
            PromptExecutionMetadata promptExecutionMetadata) {
        this(prompt, systemPrompt, userPrompt, systemPrompt, userPrompt, metadata, promptExecutionMetadata);
    }

    public Prompt getPrompt() {
        return prompt;
    }

    public String getSystemPrompt() {
        return systemPrompt;
    }

    public String getUserPrompt() {
        return userPrompt;
    }

    public String getRawSystemPrompt() {
        return rawSystemPrompt;
    }

    public String getRawUserPrompt() {
        return rawUserPrompt;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public PromptExecutionMetadata getPromptExecutionMetadata() {
        return promptExecutionMetadata;
    }
}