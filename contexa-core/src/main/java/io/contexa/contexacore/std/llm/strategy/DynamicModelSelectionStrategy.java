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

/**
 * 동적 모델 선택 전략
 *
 * DynamicModelRegistry를 활용하여 런타임에 동적으로 모델을 선택합니다.
 * 설정 파일 변경만으로 새로운 모델을 추가할 수 있습니다.
 */
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
        log.debug("동적 모델 선택 시작 - RequestId: {}, Tier: {}, PreferredModel: {}",
            context.getRequestId(), context.getTier(), context.getPreferredModel());

        try {
            // 1. 명시적으로 지정된 모델이 있으면 우선 선택
            if (context.getPreferredModel() != null && !context.getPreferredModel().isEmpty()) {
                ChatModel model = tryGetModel(context.getPreferredModel());
                if (model != null) {
                    log.info("지정된 모델 선택: {}", context.getPreferredModel());
                    return model;
                }
            }

            // 2. AnalysisLevel 기반 선택
            if (context.getAnalysisLevel() != null) {
                ChatModel model = selectByAnalysisLevel(context);
                if (model != null) {
                    return model;
                }
            }

            // 3. Tier 기반 선택
            if (context.getTier() != null) {
                ChatModel model = selectByTier(context);
                if (model != null) {
                    return model;
                }
            }

            // 4. SecurityTaskType 기반 선택
            if (context.getSecurityTaskType() != null) {
                ChatModel model = selectBySecurityTaskType(context.getSecurityTaskType());
                if (model != null) {
                    return model;
                }
            }

            // 5. 성능 요구사항 기반 선택
            ChatModel model = selectByPerformanceRequirements(context);
            if (model != null) {
                return model;
            }

            // 6. 기본 모델 선택 (Layer 2)
            return selectDefaultModel();

        } catch (Exception e) {
            log.error("모델 선택 실패 - RequestId: {}", context.getRequestId(), e);
            throw new ModelSelectionException("모델 선택 중 오류 발생: " + e.getMessage(), e);
        }
    }

    /**
     * AnalysisLevel 기반 모델 선택
     */
    private ChatModel selectByAnalysisLevel(ExecutionContext context) {
        int tier = context.getAnalysisLevel().getDefaultTier();
        log.debug("AnalysisLevel {} -> Tier {} 로 매핑", context.getAnalysisLevel(), tier);

        // ExecutionContextFactory의 설정 사용
        String modelName = tieredLLMProperties.getModelNameForTier(tier);
        ChatModel model = tryGetModelWithFallback(modelName, tier);

        if (model != null) {
            log.info("AnalysisLevel 기반 모델 선택: {} ({})",
                modelName, context.getAnalysisLevel());
        }

        return model;
    }

    /**
     * Tier 기반 모델 선택
     */
    private ChatModel selectByTier(ExecutionContext context) {
        int tier = context.getTier();

        // 설정에서 해당 tier의 기본 모델 가져오기
        String primaryModelName = tieredLLMProperties.getModelNameForTier(tier);
        ChatModel model = tryGetModelWithFallback(primaryModelName, tier);

        if (model != null) {
            log.info("Tier {} 기반 모델 선택: {}", tier, primaryModelName);
            return model;
        }

        // Tier에 해당하는 다른 사용 가능한 모델 찾기
        List<ModelDescriptor> tierModels = modelRegistry.getModelsByTier(tier);
        for (ModelDescriptor descriptor : tierModels) {
            if (descriptor.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE) {
                model = tryGetModel(descriptor.getModelId());
                if (model != null) {
                    log.info("Tier {} 대체 모델 선택: {}", tier, descriptor.getModelId());
                    return model;
                }
            }
        }

        log.warn("Tier {}에 사용 가능한 모델이 없습니다", tier);
        return null;
    }

    /**
     * SecurityTaskType 기반 모델 선택
     */
    private ChatModel selectBySecurityTaskType(ExecutionContext.SecurityTaskType taskType) {
        int tier = taskType.getDefaultTier();
        String modelName = tieredLLMProperties.getModelNameForTier(tier);

        ChatModel model = tryGetModelWithFallback(modelName, tier);
        if (model != null) {
            log.info("SecurityTaskType {} -> Tier {} -> 모델 {}",
                taskType, tier, modelName);
        }

        return model;
    }

    /**
     * 성능 요구사항 기반 모델 선택
     */
    private ChatModel selectByPerformanceRequirements(ExecutionContext context) {
        Collection<ModelDescriptor> allModels = modelRegistry.getAllModels();

        // 빠른 응답 요구 시
        if (Boolean.TRUE.equals(context.getRequireFastResponse())) {
            ModelDescriptor fastModel = allModels.stream()
                .filter(m -> m.isFastResponse())
                .filter(m -> m.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .min(Comparator.comparing(m -> m.getPerformance().getLatency()))
                .orElse(null);

            if (fastModel != null) {
                ChatModel model = tryGetModel(fastModel.getModelId());
                if (model != null) {
                    log.info("빠른 응답 모델 선택: {}", fastModel.getModelId());
                    return model;
                }
            }
        }

        // 로컬 모델 선호
        if (Boolean.TRUE.equals(context.getPreferLocalModel())) {
            ModelDescriptor localModel = allModels.stream()
                .filter(m -> "ollama".equals(m.getProvider()))
                .filter(m -> m.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .findFirst()
                .orElse(null);

            if (localModel != null) {
                ChatModel model = tryGetModel(localModel.getModelId());
                if (model != null) {
                    log.info("로컬 모델 선택: {}", localModel.getModelId());
                    return model;
                }
            }
        }

        // 클라우드 모델 선호
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
                    log.info("클라우드 모델 선택: {}", cloudModel.getModelId());
                    return model;
                }
            }
        }

        return null;
    }

    /**
     * 기본 모델 선택
     */
    private ChatModel selectDefaultModel() {
        // Layer 2 모델을 기본으로
        String defaultModel = tieredLLMProperties.getModelNameForTier(2);
        ChatModel model = tryGetModelWithFallback(defaultModel, 2);

        if (model != null) {
            log.info("기본 모델 선택: {}", defaultModel);
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

    /**
     * 모델 가져오기 시도
     */
    private ChatModel tryGetModel(String modelId) {
        try {
            return modelRegistry.getModel(modelId);
        } catch (Exception e) {
            log.debug("모델 {} 로드 실패: {}", modelId, e.getMessage());
            return null;
        }
    }

    /**
     * 폴백과 함께 모델 가져오기
     */
    private ChatModel tryGetModelWithFallback(String modelId, int tier) {
        // 기본 모델 시도
        ChatModel model = tryGetModel(modelId);
        if (model != null) {
            return model;
        }

        // 백업 모델 시도
        String backupModelId = tieredLLMProperties.getBackupModelNameForTier(tier);
        if (backupModelId != null && !backupModelId.equals(modelId)) {
            log.info("백업 모델로 전환: {} -> {}", modelId, backupModelId);
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

        // 성능이 너무 나쁜 모델은 비활성화
        if (metric.getSuccessRate() < 0.3 && metric.getTotalExecutions() > 10) {
            log.warn("모델 {} 성능 불량으로 비활성화: 성공률 {}%",
                modelName, metric.getSuccessRate() * 100);
            modelRegistry.updateModelStatus(modelName, ModelDescriptor.ModelStatus.UNAVAILABLE);
        }

        log.debug("모델 성능 기록 - {}: {}ms, 성공: {}, 평균: {}ms, 성공률: {}%",
            modelName, responseTime, success,
            metric.getAverageResponseTime(), metric.getSuccessRate() * 100);
    }

    /**
     * 모델 등록 정보 새로고침
     */
    public void refreshModels() {
        modelRegistry.refreshModels();
        log.info("모델 목록 새로고침 완료");
    }

}