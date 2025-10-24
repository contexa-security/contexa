package io.contexa.contexacore.std.components.prompt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 프롬프트 생성 결과
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PromptGenerationResult {
    private String systemPrompt;
    private String userPrompt;
    private String metadata;
}
