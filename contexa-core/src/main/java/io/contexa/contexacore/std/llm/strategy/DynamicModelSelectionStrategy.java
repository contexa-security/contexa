package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.metrics.ModelPerformanceMetric;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class DynamicModelSelectionStrategy implements ModelSelectionStrategy {

    private final DynamicModelRegistry modelRegistry;
    private final TieredLLMProperties tieredLLMProperties;
    private final ChatModel primaryChatModel;

    private final Map<String, ModelPerformanceMetric> modelPerformance = new ConcurrentHashMap<>();

    public DynamicModelSelectionStrategy(
            DynamicModelRegistry modelRegistry,
            TieredLLMProperties tieredLLMProperties,
            ChatModel primaryChatModel) {
        this.modelRegistry = modelRegistry;
        this.tieredLLMProperties = tieredLLMProperties;
        this.primaryChatModel = primaryChatModel;
        log.info("DynamicModelSelectionStrategy initialized with primaryChatModel: {}",
                primaryChatModel != null ? primaryChatModel.getClass().getSimpleName() : "null");
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
                        log.debug("Tier {} using configured model: {}", context.getTier(), modelName);
                        return model;
                    }

                    // Try backup model
                    String backupModel = tieredLLMProperties.getBackupModelNameForTier(context.getTier());
                    if (backupModel != null) {
                        model = tryGetModel(backupModel);
                        if (model != null) {
                            log.debug("Tier {} using backup model: {}", context.getTier(), backupModel);
                            return model;
                        }
                    }
                }
            }

            // 2. Preferred model (if specified)
            if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
                ChatModel model = tryGetModel(context.getPreferredModel());
                if (model != null) {
                    log.debug("Using preferred model: {}", context.getPreferredModel());
                    return model;
                }
                log.warn("Preferred model {} not available, falling back", context.getPreferredModel());
            }

            // 3. primaryChatModel fallback (auto-inheritance)
            if (primaryChatModel != null) {
                log.debug("Using primaryChatModel fallback: {}", primaryChatModel.getClass().getSimpleName());
                return primaryChatModel;
            }

            log.warn("No model available - RequestId: {}. LLM features disabled.", context.getRequestId());
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
            log.debug("Model {} not available: {}", modelId, e.getMessage());
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

    @Override
    public void recordModelPerformance(String modelName, long responseTime, boolean success) {
        ModelPerformanceMetric metric = modelPerformance.computeIfAbsent(modelName,
                k -> new ModelPerformanceMetric());

        metric.recordExecution(responseTime, success);

        if (metric.getSuccessRate() < 0.3 && metric.getTotalExecutions() > 10) {
            log.warn("Model {} disabled due to poor performance: success rate {}%",
                    modelName, metric.getSuccessRate() * 100);
            modelRegistry.updateModelStatus(modelName, ModelDescriptor.ModelStatus.UNAVAILABLE);
        }
    }

    public void refreshModels() {
        modelRegistry.refreshModels();
    }
}
