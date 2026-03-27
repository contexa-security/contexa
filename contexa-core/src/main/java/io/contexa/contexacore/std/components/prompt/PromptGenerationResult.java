package io.contexa.contexacore.std.components.prompt;

import org.springframework.ai.chat.prompt.Prompt;

import java.util.Map;

public class PromptGenerationResult {

    private final Prompt prompt;
    private final String systemPrompt;
    private final String userPrompt;
    private final Map<String, Object> metadata;
    private final PromptExecutionMetadata promptExecutionMetadata;

    public PromptGenerationResult(
            Prompt prompt,
            String systemPrompt,
            String userPrompt,
            Map<String, Object> metadata,
            PromptExecutionMetadata promptExecutionMetadata) {
        this.prompt = prompt;
        this.systemPrompt = systemPrompt;
        this.userPrompt = userPrompt;
        this.metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
        this.promptExecutionMetadata = promptExecutionMetadata;
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

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public PromptExecutionMetadata getPromptExecutionMetadata() {
        return promptExecutionMetadata;
    }
}
