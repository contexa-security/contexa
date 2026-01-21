package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.dynamic.AIModelManager;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.metrics.ModelPerformanceMetric;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Primary
@RequiredArgsConstructor
public class DynamicModelSelectionStrategy implements ModelSelectionStrategy {

    private final DynamicModelRegistry modelRegistry;
    private final TieredLLMProperties tieredLLMProperties;
    private final AIModelManager aiModelManager;

    private final Map<String, ModelPerformanceMetric> modelPerformance = new ConcurrentHashMap<>();

    @Override
    public ChatModel selectModel(ExecutionContext context) {
        
        try {
            
            if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
                ChatModel model = tryGetModel(context.getPreferredModel());
                if (model != null) {
                                        return model;
                }
            }

            if (context.getAnalysisLevel() != null) {
                ChatModel model = selectByAnalysisLevel(context);
                if (model != null) {
                    return model;
                }
            }

            if (context.getTier() != null) {
                ChatModel model = selectByTier(context);
                if (model != null) {
                    return model;
                }
            }

            if (context.getSecurityTaskType() != null) {
                ChatModel model = selectBySecurityTaskType(context.getSecurityTaskType());
                if (model != null) {
                    return model;
                }
            }

            ChatModel model = selectByPerformanceRequirements(context);
            if (model != null) {
                return model;
            }

            return selectDefaultModel();

        } catch (Exception e) {
            log.error("모델 선택 실패 - RequestId: {}", context.getRequestId(), e);
            throw new ModelSelectionException("모델 선택 중 오류 발생: " + e.getMessage(), e);
        }
    }

    private ChatModel selectByAnalysisLevel(ExecutionContext context) {
        int tier = context.getAnalysisLevel().getDefaultTier();

        String modelName = tieredLLMProperties.getModelNameForTier(tier);
        ChatModel model = tryGetModelWithFallback(modelName, tier);

        if (model != null) {
                    }

        return model;
    }

    private ChatModel selectByTier(ExecutionContext context) {
        int tier = context.getTier();

        String primaryModelName = tieredLLMProperties.getModelNameForTier(tier);
        ChatModel model = tryGetModelWithFallback(primaryModelName, tier);

        if (model != null) {
                        return model;
        }

        List<ModelDescriptor> tierModels = modelRegistry.getModelsByTier(tier);
        for (ModelDescriptor descriptor : tierModels) {
            if (descriptor.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                model = tryGetModel(descriptor.getModelId());
                if (model != null) {
                                        return model;
                }
            }
        }

        log.warn("Tier {}에 사용 가능한 모델이 없습니다", tier);
        return null;
    }

    private ChatModel selectBySecurityTaskType(ExecutionContext.SecurityTaskType taskType) {
        int tier = taskType.getDefaultTier();
        String modelName = tieredLLMProperties.getModelNameForTier(tier);

        ChatModel model = tryGetModelWithFallback(modelName, tier);
        if (model != null) {
                    }

        return model;
    }

    private ChatModel selectByPerformanceRequirements(ExecutionContext context) {
        Collection<ModelDescriptor> allModels = modelRegistry.getAllModels();

        if (Boolean.TRUE.equals(context.getRequireFastResponse())) {
            ModelDescriptor fastModel = allModels.stream()
                .filter(m -> m.isFastResponse())
                .filter(m -> m.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .min(Comparator.comparing(m -> m.getPerformance().getLatency()))
                .orElse(null);

            if (fastModel != null) {
                ChatModel model = tryGetModel(fastModel.getModelId());
                if (model != null) {
                                        return model;
                }
            }
        }

        if (Boolean.TRUE.equals(context.getPreferLocalModel())) {
            ModelDescriptor localModel = allModels.stream()
                .filter(m -> "ollama".equals(m.getProvider()))
                .filter(m -> m.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .findFirst()
                .orElse(null);

            if (localModel != null) {
                ChatModel model = tryGetModel(localModel.getModelId());
                if (model != null) {
                                        return model;
                }
            }
        }

        if (Boolean.TRUE.equals(context.getPreferCloudModel())) {
            ModelDescriptor cloudModel = allModels.stream()
                .filter(m -> !"ollama".equals(m.getProvider()))
                .filter(m -> m.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .filter(m -> m.supportsAdvancedFeatures())
                .findFirst()
                .orElse(null);

            if (cloudModel != null) {
                ChatModel model = tryGetModel(cloudModel.getModelId());
                if (model != null) {
                                        return model;
                }
            }
        }

        return null;
    }

    private ChatModel selectDefaultModel() {
        
        String defaultModel = tieredLLMProperties.getModelNameForTier(2);
        ChatModel model = tryGetModelWithFallback(defaultModel, 2);

        if (model != null) {
                        return model;
        }

        Collection<ModelDescriptor> allModels = modelRegistry.getAllModels();
        for (ModelDescriptor descriptor : allModels) {
            if (descriptor.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                model = tryGetModel(descriptor.getModelId());
                if (model != null) {
                    log.warn("최종 폴백 모델 선택: {}", descriptor.getModelId());
                    return model;
                }
            }
        }

        throw new ModelSelectionException(
            "사용 가능한 모델이 없습니다. DynamicModelRegistry를 확인하세요. "
            + "등록된 모델 수: " + allModels.size());
    }

    private ChatModel tryGetModel(String modelId) {
        try {
            return modelRegistry.getModel(modelId);
        } catch (Exception e) {
                        return null;
        }
    }

    private ChatModel tryGetModelWithFallback(String modelId, int tier) {
        
        ChatModel model = tryGetModel(modelId);
        if (model != null) {
            return model;
        }

        String backupModelId = tieredLLMProperties.getBackupModelNameForTier(tier);
        if (backupModelId != null && !backupModelId.equals(modelId)) {
                        model = tryGetModel(backupModelId);
            if (model != null) {
                return model;
            }
        }

        return null;
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
            log.warn("모델 {} 성능 불량으로 비활성화: 성공률 {}%",
                modelName, metric.getSuccessRate() * 100);
            modelRegistry.updateModelStatus(modelName, ModelDescriptor.ModelStatus.UNAVAILABLE);
        }

            }

    public void refreshModels() {
        modelRegistry.refreshModels();
            }

}