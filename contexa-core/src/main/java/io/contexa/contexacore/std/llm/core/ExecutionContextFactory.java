package io.contexa.contexacore.std.llm.core;

import io.contexa.contexacore.config.SecurityMappingProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.stereotype.Component;

/**
 * ExecutionContext 생성 팩토리
 * 설정 파일(TieredLLMProperties)을 기반으로 ExecutionContext를 생성
 * 하드코딩 제거 및 설정 기반 동작
 */
@Component
@RequiredArgsConstructor
public class ExecutionContextFactory {

    private final TieredLLMProperties tieredLLMProperties;
    private final SecurityMappingProperties securityMappingProperties;

    /**
     * AnalysisLevel 기반 컨텍스트 생성
     * 설정 파일의 값을 사용하여 하드코딩 제거
     */
    public ExecutionContext forAnalysisLevel(ExecutionContext.AnalysisLevel level, Prompt prompt) {
        int tier = level.getDefaultTier();
        String modelName = tieredLLMProperties.getModelNameForTier(tier);
        Integer timeout = tieredLLMProperties.getTimeoutForTier(tier);
        Double temperature = tieredLLMProperties.getTemperatureForTier(tier);

        ExecutionContext.ExecutionContextBuilder builder = ExecutionContext.builder()
                .prompt(prompt)
                .analysisLevel(level)
                .tier(tier)
                .preferredModel(modelName)
                .timeoutMs(timeout)
                .temperature(temperature)
                .advisorEnabled(true);

        // 분석 수준별 추가 설정
        switch (level) {
            case QUICK -> {
                builder.requireFastResponse(true)
                       .preferLocalModel(true);
            }
            case NORMAL -> {
                builder.preferLocalModel(true);
            }
            case DEEP -> {
                builder.preferCloudModel(tieredLLMProperties.isCloudModel(modelName))
                       .toolExecutionEnabled(tieredLLMProperties.getTiered().getLayer3().isEnableSoar());
            }
        }

        return builder.build();
    }

    /**
     * Tier 기반 컨텍스트 생성
     * 설정 파일의 값을 사용하여 하드코딩 제거
     */
    public ExecutionContext forTier(int tier, Prompt prompt) {
        String modelName = tieredLLMProperties.getModelNameForTier(tier);
        Integer timeout = tieredLLMProperties.getTimeoutForTier(tier);
        Double temperature = tieredLLMProperties.getTemperatureForTier(tier);

        ExecutionContext.ExecutionContextBuilder builder = ExecutionContext.builder()
                .prompt(prompt)
                .tier(tier)
                .preferredModel(modelName)
                .timeoutMs(timeout)
                .temperature(temperature)
                .advisorEnabled(true);

        // 계층별 추가 설정
        switch (tier) {
            case 1 -> {
                builder.securityTaskType(ExecutionContext.SecurityTaskType.THREAT_FILTERING)
                       .requireFastResponse(true)
                       .preferLocalModel(tieredLLMProperties.isOllamaModel(modelName));
            }
            case 2 -> {
                builder.securityTaskType(ExecutionContext.SecurityTaskType.CONTEXTUAL_ANALYSIS)
                       .preferLocalModel(tieredLLMProperties.isOllamaModel(modelName));
            }
            case 3 -> {
                builder.securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                       .preferCloudModel(tieredLLMProperties.isCloudModel(modelName))
                       .toolExecutionEnabled(tieredLLMProperties.getTiered().getLayer3().isEnableSoar());
            }
            default -> {
                // 유효하지 않은 tier인 경우 기본값 사용
                builder.tier(2)
                       .preferredModel(tieredLLMProperties.getModelNameForTier(2));
            }
        }

        return builder.build();
    }

    /**
     * SecurityTaskType 기반 컨텍스트 생성
     */
    public ExecutionContext forSecurityTask(ExecutionContext.SecurityTaskType taskType, Prompt prompt) {
        // SecurityMappingProperties를 사용하여 tier 결정
        int tier = securityMappingProperties.getTierForSecurityTask(taskType);
        String modelName = tieredLLMProperties.getModelNameForTier(tier);

        // TaskConfig 가져오기
        SecurityMappingProperties.TaskConfig taskConfig = securityMappingProperties.getTaskConfig(taskType);

        ExecutionContext.ExecutionContextBuilder builder = ExecutionContext.builder()
                .prompt(prompt)
                .securityTaskType(taskType)
                .tier(tier)
                .preferredModel(taskConfig.getPreferredModel() != null ?
                    taskConfig.getPreferredModel() : modelName)
                .timeoutMs(taskConfig.getTimeoutMs() != null ?
                    taskConfig.getTimeoutMs() : tieredLLMProperties.getTimeoutForTier(tier))
                .temperature(taskConfig.getTemperature() != null ?
                    taskConfig.getTemperature() : tieredLLMProperties.getTemperatureForTier(tier))
                .advisorEnabled(true);

        // TaskConfig에서 추가 설정 적용
        if (taskConfig.getToolExecutionEnabled() != null) {
            builder.toolExecutionEnabled(taskConfig.getToolExecutionEnabled());
        }
        if (taskConfig.getRequireFastResponse() != null) {
            builder.requireFastResponse(taskConfig.getRequireFastResponse());
        }
        if (taskConfig.getPreferLocalModel() != null) {
            builder.preferLocalModel(taskConfig.getPreferLocalModel());
        }
        if (taskConfig.getPreferCloudModel() != null) {
            builder.preferCloudModel(taskConfig.getPreferCloudModel());
        }

        return builder.build();
    }

    /**
     * 기본 컨텍스트 생성 (설정 기반)
     */
    public ExecutionContext createDefault(Prompt prompt) {
        // 기본값은 Layer 2 (균형)
        return forTier(2, prompt);
    }

    /**
     * 백업 모델을 고려한 컨텍스트 생성
     */
    public ExecutionContext withFallbackModel(ExecutionContext original) {
        if (original.getTier() == null) {
            return original;
        }

        String backupModel = tieredLLMProperties.getBackupModelNameForTier(original.getTier());
        if (backupModel != null && !backupModel.equals(original.getPreferredModel())) {
            // 백업 모델로 새 컨텍스트 생성
            return ExecutionContext.builder()
                    .prompt(original.getPrompt())
                    .tier(original.getTier())
                    .preferredModel(backupModel)
                    .analysisLevel(original.getAnalysisLevel())
                    .securityTaskType(original.getSecurityTaskType())
                    .timeoutMs(original.getTimeoutMs())
                    .temperature(original.getTemperature())
                    .advisorEnabled(original.getAdvisorEnabled())
                    .toolExecutionEnabled(original.getToolExecutionEnabled())
                    .build();
        }

        return original;
    }

}