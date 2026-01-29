package io.contexa.contexacore.std.llm.core;

import io.contexa.contexacore.properties.SecurityMappingProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.ai.chat.prompt.Prompt;

@RequiredArgsConstructor
public class ExecutionContextFactory {

    private final TieredLLMProperties tieredLLMProperties;
    private final SecurityMappingProperties securityMappingProperties;

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
                       .toolExecutionEnabled(tieredLLMProperties.getTiered().getLayer2().isEnableSoar());
            }
        }

        return builder.build();
    }

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

        switch (tier) {
            case 1 -> {
                
                builder.securityTaskType(ExecutionContext.SecurityTaskType.THREAT_FILTERING)
                       .requireFastResponse(true)
                       .preferLocalModel(tieredLLMProperties.isOllamaModel(modelName));
            }
            case 2 -> {
                
                builder.securityTaskType(ExecutionContext.SecurityTaskType.EXPERT_INVESTIGATION)
                       .preferCloudModel(tieredLLMProperties.isCloudModel(modelName))
                       .toolExecutionEnabled(tieredLLMProperties.getTiered().getLayer2().isEnableSoar());
            }
            default -> {
                
                builder.tier(1)
                       .preferredModel(tieredLLMProperties.getModelNameForTier(1));
            }
        }

        return builder.build();
    }

    public ExecutionContext forSecurityTask(ExecutionContext.SecurityTaskType taskType, Prompt prompt) {
        
        int tier = securityMappingProperties.getTierForSecurityTask(taskType);
        String modelName = tieredLLMProperties.getModelNameForTier(tier);

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

    public ExecutionContext createDefault(Prompt prompt) {
        
        return forTier(2, prompt);
    }

    public ExecutionContext withFallbackModel(ExecutionContext original) {
        if (original.getTier() == null) {
            return original;
        }

        String backupModel = tieredLLMProperties.getBackupModelNameForTier(original.getTier());
        if (backupModel != null && !backupModel.equals(original.getPreferredModel())) {
            
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