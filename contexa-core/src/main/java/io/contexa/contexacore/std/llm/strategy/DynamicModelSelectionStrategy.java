package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.core.ExecutionContext;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.metrics.ModelPerformanceMetric;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class DynamicModelSelectionStrategy implements ModelSelectionStrategy {

    private final DynamicModelRegistry modelRegistry;
    private final TieredLLMProperties tieredLLMProperties;
    private final ChatModel primaryChatModel;  // 자동 상속 방식: provider 기본 모델

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
        // 자동 상속 방식: 모델 선택 우선순위
        // 1. tier (최우선) -> Layer 설정 모델 또는 primaryChatModel 자동 상속
        // 2. analysisLevel -> tier 변환 후 선택
        // 3. securityTaskType -> tier 변환 후 선택
        // 4. preferredModel (특수 케이스)
        // 5. performanceRequirements
        // 6. defaultModel

        try {
            // 1. tier 기반 선택 (최우선)
            if (context.getTier() != null) {
                ChatModel model = selectByTier(context);
                if (model != null) {
                    return model;
                }
            }

            // 2. AnalysisLevel -> tier 변환 후 선택
            if (context.getAnalysisLevel() != null) {
                ChatModel model = selectByAnalysisLevel(context);
                if (model != null) {
                    return model;
                }
            }

            // 3. SecurityTaskType -> tier 변환 후 선택
            if (context.getSecurityTaskType() != null) {
                ChatModel model = selectBySecurityTaskType(context.getSecurityTaskType());
                if (model != null) {
                    return model;
                }
            }

            // 4. preferredModel (특수 케이스: 명시적 모델 지정이 필요한 경우에만)
            if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
                ChatModel model = tryGetModel(context.getPreferredModel());
                if (model != null) {
                    log.debug("Using explicitly preferred model: {}", context.getPreferredModel());
                    return model;
                }
                log.warn("Preferred model {} not available, falling back", context.getPreferredModel());
            }

            // 5. 성능 요구사항 기반 선택
            ChatModel model = selectByPerformanceRequirements(context);
            if (model != null) {
                return model;
            }

            // 6. 기본 모델
            ChatModel defaultModel = selectDefaultModel();
            if (defaultModel == null) {
                log.warn("Model selection unavailable - RequestId: {}. LLM features disabled.", context.getRequestId());
            }
            return defaultModel;

        } catch (Exception e) {
            log.error("Model selection failed - RequestId: {}", context.getRequestId(), e);
            throw new ModelSelectionException("Error during model selection: " + e.getMessage(), e);
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

        // 1. layer 설정의 모델명 조회 (spring.ai.security.layer1.model 등)
        String primaryModelName = tieredLLMProperties.getModelNameForTier(tier);
        if (primaryModelName != null) {
            ChatModel model = tryGetModelWithFallback(primaryModelName, tier);
            if (model != null) {
                log.debug("Tier {} using configured model: {}", tier, primaryModelName);
                return model;
            }
        }

        // 2. Tier에 등록된 모델 중 검색
        List<ModelDescriptor> tierModels = modelRegistry.getModelsByTier(tier);
        for (ModelDescriptor descriptor : tierModels) {
            if (descriptor.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                ChatModel model = tryGetModel(descriptor.getModelId());
                if (model != null) {
                    log.debug("Tier {} using registry model: {}", tier, descriptor.getModelId());
                    return model;
                }
            }
        }

        // 3. Priority 순서대로 해당 tier의 모델 검색
        List<String> priorities = tieredLLMProperties.getProviderPriorityList();
        for (String provider : priorities) {
            List<ModelDescriptor> providerModels = modelRegistry.getModelsByProvider(provider);
            for (ModelDescriptor desc : providerModels) {
                Integer descTier = desc.getTier();
                if (descTier != null && descTier == tier &&
                        desc.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                    ChatModel model = tryGetModel(desc.getModelId());
                    if (model != null) {
                        log.debug("Tier {} using priority provider model: {} ({})", tier, desc.getModelId(), provider);
                        return model;
                    }
                }
            }
        }

        // 4. Priority 순서대로 아무 모델이나 검색 (tier 무관)
        for (String provider : priorities) {
            List<ModelDescriptor> providerModels = modelRegistry.getModelsByProvider(provider);
            for (ModelDescriptor desc : providerModels) {
                if (desc.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                    ChatModel model = tryGetModel(desc.getModelId());
                    if (model != null) {
                        log.debug("Tier {} using any available provider model: {} ({})", tier, desc.getModelId(), provider);
                        return model;
                    }
                }
            }
        }

        // 5. 자동 상속: primaryChatModel 사용 (provider 기본 모델)
        if (primaryChatModel != null) {
            log.info("Tier {} using primaryChatModel (auto-inheritance): {}",
                    tier, primaryChatModel.getClass().getSimpleName());
            return primaryChatModel;
        }

        log.warn("No available model for Tier {} and no primaryChatModel available", tier);
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
        // 1. Tier 2 설정 모델 시도
        String defaultModel = tieredLLMProperties.getModelNameForTier(2);
        if (defaultModel != null) {
            ChatModel model = tryGetModelWithFallback(defaultModel, 2);
            if (model != null) {
                return model;
            }
        }

        // 2. 등록된 모델 중 사용 가능한 것 검색
        Collection<ModelDescriptor> allModels = modelRegistry.getAllModels();
        for (ModelDescriptor descriptor : allModels) {
            if (descriptor.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                ChatModel model = tryGetModel(descriptor.getModelId());
                if (model != null) {
                    log.debug("Final fallback model selected: {}", descriptor.getModelId());
                    return model;
                }
            }
        }

        // 3. 자동 상속: primaryChatModel 사용 (provider 기본 모델)
        if (primaryChatModel != null) {
            log.info("Using primaryChatModel as default (auto-inheritance): {}",
                    primaryChatModel.getClass().getSimpleName());
            return primaryChatModel;
        }

        log.warn("No available models. LLM features disabled. " +
                "Registered models: {}. Check spring.ai.* settings.", allModels.size());
        return null;
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
            log.warn("Model {} disabled due to poor performance: success rate {}%",
                    modelName, metric.getSuccessRate() * 100);
            modelRegistry.updateModelStatus(modelName, ModelDescriptor.ModelStatus.UNAVAILABLE);
        }

    }

    public void refreshModels() {
        modelRegistry.refreshModels();
    }

}