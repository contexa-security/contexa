package io.contexa.contexacore.std.components.prompt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PromptGenerationResult {
    private String systemPrompt;
    private String userPrompt;
    private String metadata;
}
