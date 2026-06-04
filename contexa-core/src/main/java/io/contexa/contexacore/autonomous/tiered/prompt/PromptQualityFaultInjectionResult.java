package io.contexa.contexacore.autonomous.tiered.prompt;

import java.util.Map;

record PromptQualityFaultInjectionResult(String userPrompt, Map<String, Object> metadata) {
}
