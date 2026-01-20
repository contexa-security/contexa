package io.contexa.contexacore.config;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;


@Slf4j
@Data
@ConfigurationProperties(prefix = "spring.ai.security.mapping")
public class SecurityMappingProperties {

    
    @NestedConfigurationProperty
    private Map<String, Integer> taskToTier = new HashMap<>();

    
    @NestedConfigurationProperty
    private Map<String, String> taskToAnalysisLevel = new HashMap<>();

    
    @NestedConfigurationProperty
    private Map<String, TaskConfig> taskConfigs = new HashMap<>();

    
    @NestedConfigurationProperty
    private DefaultMappings defaults = new DefaultMappings();

    
    @Data
    public static class TaskConfig {
        private Integer tier = 2;
        private String analysisLevel = "NORMAL";
        private Boolean toolExecutionEnabled = false;
        private Boolean requireFastResponse = false;
        private Boolean preferLocalModel = false;
        private Boolean preferCloudModel = false;
        private Double temperature;
        private Integer timeoutMs;
        private String preferredModel;
        private Map<String, Object> metadata = new HashMap<>();
    }

    
    @Data
    public static class DefaultMappings {
        
        private String[] tier1Tasks = {
            "THREAT_FILTERING",
            "QUICK_DETECTION"
        };

        
        private String[] tier2Tasks = {
            "CONTEXTUAL_ANALYSIS",
            "BEHAVIOR_ANALYSIS",
            "CORRELATION"
        };

        
        private String[] tier3Tasks = {
            "EXPERT_INVESTIGATION",
            "INCIDENT_RESPONSE",
            "FORENSIC_ANALYSIS",
            "SOAR_AUTOMATION",
            "APPROVAL_WORKFLOW"
        };

        
        private Integer defaultTier = 2;

        
        private String defaultAnalysisLevel = "NORMAL";
    }

    
    public int getTierForSecurityTask(ExecutionContext.SecurityTaskType taskType) {
        if (taskType == null) {
            return defaults.getDefaultTier();
        }

        String taskName = taskType.name();

        
        if (taskToTier.containsKey(taskName)) {
            return taskToTier.get(taskName);
        }

        
        if (taskConfigs.containsKey(taskName)) {
            TaskConfig config = taskConfigs.get(taskName);
            if (config.getTier() != null) {
                return config.getTier();
            }
        }

        
        for (String tier1Task : defaults.getTier1Tasks()) {
            if (tier1Task.equals(taskName)) {
                return 1;
            }
        }

        for (String tier2Task : defaults.getTier2Tasks()) {
            if (tier2Task.equals(taskName)) {
                return 2;
            }
        }

        for (String tier3Task : defaults.getTier3Tasks()) {
            if (tier3Task.equals(taskName)) {
                return 3;
            }
        }

        
        log.debug("SecurityTaskType {}에 대한 매핑을 찾을 수 없음. 기본값 {} 사용",
                taskName, defaults.getDefaultTier());
        return defaults.getDefaultTier();
    }

    
    public ExecutionContext.AnalysisLevel getAnalysisLevelForSecurityTask(ExecutionContext.SecurityTaskType taskType) {
        if (taskType == null) {
            return ExecutionContext.AnalysisLevel.valueOf(defaults.getDefaultAnalysisLevel());
        }

        String taskName = taskType.name();

        
        if (taskToAnalysisLevel.containsKey(taskName)) {
            String levelName = taskToAnalysisLevel.get(taskName);
            try {
                return ExecutionContext.AnalysisLevel.valueOf(levelName);
            } catch (IllegalArgumentException e) {
                log.warn("잘못된 AnalysisLevel: {}. 기본값 사용", levelName);
                return ExecutionContext.AnalysisLevel.valueOf(defaults.getDefaultAnalysisLevel());
            }
        }

        
        if (taskConfigs.containsKey(taskName)) {
            TaskConfig config = taskConfigs.get(taskName);
            if (config.getAnalysisLevel() != null) {
                try {
                    return ExecutionContext.AnalysisLevel.valueOf(config.getAnalysisLevel());
                } catch (IllegalArgumentException e) {
                    log.warn("잘못된 AnalysisLevel: {}. 기본값 사용", config.getAnalysisLevel());
                }
            }
        }

        
        int tier = getTierForSecurityTask(taskType);
        return switch (tier) {
            case 1 -> ExecutionContext.AnalysisLevel.QUICK;
            case 2 -> ExecutionContext.AnalysisLevel.NORMAL;
            case 3 -> ExecutionContext.AnalysisLevel.DEEP;
            default -> ExecutionContext.AnalysisLevel.valueOf(defaults.getDefaultAnalysisLevel());
        };
    }

    
    public TaskConfig getTaskConfig(ExecutionContext.SecurityTaskType taskType) {
        if (taskType == null) {
            return createDefaultTaskConfig();
        }

        String taskName = taskType.name();

        
        TaskConfig config = taskConfigs.get(taskName);
        if (config != null) {
            return config;
        }

        
        return createDefaultTaskConfig(taskType);
    }

    
    private TaskConfig createDefaultTaskConfig() {
        TaskConfig config = new TaskConfig();
        config.setTier(defaults.getDefaultTier());
        config.setAnalysisLevel(defaults.getDefaultAnalysisLevel());
        return config;
    }

    
    private TaskConfig createDefaultTaskConfig(ExecutionContext.SecurityTaskType taskType) {
        TaskConfig config = new TaskConfig();
        int tier = getTierForSecurityTask(taskType);
        config.setTier(tier);

        
        switch (tier) {
            case 1 -> {
                config.setAnalysisLevel("QUICK");
                config.setRequireFastResponse(true);
                config.setPreferLocalModel(true);
            }
            case 2 -> {
                config.setAnalysisLevel("NORMAL");
                config.setPreferLocalModel(true);
            }
            case 3 -> {
                config.setAnalysisLevel("DEEP");
                config.setPreferCloudModel(true);

                
                if (taskType == ExecutionContext.SecurityTaskType.SOAR_AUTOMATION ||
                    taskType == ExecutionContext.SecurityTaskType.APPROVAL_WORKFLOW) {
                    config.setToolExecutionEnabled(true);
                }
            }
        }

        return config;
    }

    
    @PostConstruct
    public void validateConfiguration() {
        log.info("보안 태스크 매핑 설정 검증 시작");

        
        if (!taskToTier.isEmpty()) {
            log.info("명시적 TaskType -> Tier 매핑: {} 개", taskToTier.size());
            for (Map.Entry<String, Integer> entry : taskToTier.entrySet()) {
                log.debug("  - {} -> Tier {}", entry.getKey(), entry.getValue());
            }
        }

        
        if (!taskConfigs.isEmpty()) {
            log.info("태스크별 상세 설정: {} 개", taskConfigs.size());
            for (Map.Entry<String, TaskConfig> entry : taskConfigs.entrySet()) {
                TaskConfig config = entry.getValue();
                log.debug("  - {}: tier={}, analysisLevel={}, toolExecution={}",
                        entry.getKey(), config.getTier(), config.getAnalysisLevel(),
                        config.getToolExecutionEnabled());
            }
        }

        
        log.info("기본 매핑 설정:");
        log.debug("  - Tier 1 태스크: {} 개", defaults.getTier1Tasks().length);
        log.debug("  - Tier 2 태스크: {} 개", defaults.getTier2Tasks().length);
        log.debug("  - Tier 3 태스크: {} 개", defaults.getTier3Tasks().length);
        log.debug("  - 기본 Tier: {}", defaults.getDefaultTier());
        log.debug("  - 기본 AnalysisLevel: {}", defaults.getDefaultAnalysisLevel());

        
        for (ExecutionContext.SecurityTaskType taskType : ExecutionContext.SecurityTaskType.values()) {
            int tier = getTierForSecurityTask(taskType);
            ExecutionContext.AnalysisLevel level = getAnalysisLevelForSecurityTask(taskType);
            log.debug("매핑 확인 - {}: Tier={}, AnalysisLevel={}",
                    taskType, tier, level);
        }

        log.info("보안 태스크 매핑 설정 검증 완료");
    }
}