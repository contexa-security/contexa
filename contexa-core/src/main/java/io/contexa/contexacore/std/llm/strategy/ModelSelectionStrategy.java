package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import org.springframework.ai.chat.model.ChatModel;

public interface ModelSelectionStrategy {

    ChatModel selectModel(ExecutionContext context);

    java.util.Set<String> getSupportedModels();

    boolean isModelAvailable(String modelName);

    void recordModelPerformance(String modelName, long responseTime, boolean success);
}