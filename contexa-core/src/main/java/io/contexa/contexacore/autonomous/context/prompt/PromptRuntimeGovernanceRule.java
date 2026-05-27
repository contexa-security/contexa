package io.contexa.contexacore.autonomous.context.prompt;

import java.util.Map;

public record PromptRuntimeGovernanceRule(
        String ruleId,
        String sourceActionId,
        String promptKey,
        String slotKey,
        String ruleType,
        int priority,
        Map<String, Object> payload) {

    public String payloadText(String key) {
        Object value = payload == null || key == null ? null : payload.get(key);
        return value == null ? null : String.valueOf(value);
    }
}
