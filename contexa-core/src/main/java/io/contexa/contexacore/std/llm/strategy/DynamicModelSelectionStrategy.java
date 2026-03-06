package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class DynamicModelSelectionStrategy implements ModelSelectionStrategy {

    private final DynamicModelRegistry modelRegistry;
    private final TieredLLMProperties tieredLLMProperties;
    private final ChatModel primaryChatModel;

    public DynamicModelSelectionStrategy(
            DynamicModelRegistry modelRegistry,
            TieredLLMProperties tieredLLMProperties,
            ChatModel primaryChatModel) {
        this.modelRegistry = modelRegistry;
        this.tieredLLMProperties = tieredLLMProperties;
        this.primaryChatModel = primaryChatModel;
    }

    @Override
    public ChatModel selectModel(ExecutionContext context) {
        try {
            // 1. Tier-based model selection
            if (context.getTier() != null) {
                String modelName = tieredLLMProperties.getModelNameForTier(context.getTier());
                if (modelName != null) {
                    ChatModel model = tryGetModel(modelName);
                    if (model != null) {
                        return model;
                    }

                    // Try backup model
                    String backupModel = tieredLLMProperties.getBackupModelNameForTier(context.getTier());
                    if (backupModel != null) {
                        model = tryGetModel(backupModel);
                        if (model != null) {
                            return model;
                        }
                    }
                }
            }

            // 2. Preferred model (if specified)
            if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
                ChatModel model = tryGetModel(context.getPreferredModel());
                if (model != null) {
                    return model;
                }
                log.error("Preferred model {} not available, falling back", context.getPreferredModel());
            }

            // 3. primaryChatModel fallback (auto-inheritance)
            if (primaryChatModel != null) {
                return primaryChatModel;
            }

            log.error("No model available - RequestId: {}. LLM features disabled.", context.getRequestId());
            return null;

        } catch (Exception e) {
            log.error("Model selection failed - RequestId: {}", context.getRequestId(), e);
            throw new ModelSelectionException("Error during model selection: " + e.getMessage(), e);
        }
    }

    private ChatModel tryGetModel(String modelId) {
        try {
            return modelRegistry.getModel(modelId);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Set<String> getSupportedModels() {
        return modelRegistry.getAllModels().stream()
                .map(ModelDescriptor::getModelId)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isModelAvailable(String modelName) {
        try {
            ChatModel model = modelRegistry.getModel(modelName);
            return model != null;
        } catch (Exception e) {
            return false;
        }
    }

    public void refreshModels() {
        modelRegistry.refreshModels();
    }
}
