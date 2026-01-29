package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.observation.ToolCallingObservationContext;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class RiskAssessment {

    private final Map<String, io.contexa.contexacommon.enums.RiskLevel> toolRiskMap = new HashMap<>();

    private static final Set<String> HIGH_RISK_KEYWORDS = Set.of(
        "delete", "remove", "kill", "terminate", "shutdown", "destroy",
        "format", "wipe", "purge", "quarantine", "isolate"
    );
    
    private static final Set<String> CRITICAL_KEYWORDS = Set.of(
        "system", "kernel", "root", "admin", "production", "critical"
    );

    public io.contexa.contexacommon.enums.RiskLevel assess(ToolCallback tool, Map<String, Object> context) {
        String toolName = tool.getToolDefinition().name();

        io.contexa.contexacommon.enums.RiskLevel annotationRisk = getAnnotationRiskLevel(tool);

        io.contexa.contexacommon.enums.RiskLevel nameRisk = assessByToolName(toolName);

        io.contexa.contexacommon.enums.RiskLevel contextRisk = assessByContext(context);

        io.contexa.contexacommon.enums.RiskLevel timeRisk = assessByTime();

        io.contexa.contexacommon.enums.RiskLevel finalRisk = getHighestRisk(
            annotationRisk, nameRisk, contextRisk, timeRisk
        );

        return finalRisk;
    }

    public io.contexa.contexacommon.enums.RiskLevel assess(ToolCallingObservationContext context) {
        
        String toolName = "unknown";

        io.contexa.contexacommon.enums.RiskLevel baseRisk = assessByToolName(toolName);
        
        return baseRisk;
    }

    public RiskAssessmentResult assessWithDetails(ToolCallback tool, Map<String, Object> context) {
        io.contexa.contexacommon.enums.RiskLevel riskLevel = assess(tool, context);
        
        return RiskAssessmentResult.builder()
            .toolName(tool.getToolDefinition().name())
            .riskLevel(riskLevel)
            .requiresApproval(requiresApproval(riskLevel))
            .assessmentFactors(getAssessmentFactors(tool, context))
            .recommendations(getRecommendations(riskLevel))
            .build();
    }

    public boolean requiresApproval(io.contexa.contexacommon.enums.RiskLevel riskLevel) {
        return riskLevel == io.contexa.contexacommon.enums.RiskLevel.HIGH || 
               riskLevel == io.contexa.contexacommon.enums.RiskLevel.CRITICAL;
    }

    public void setToolRiskLevel(String toolName, io.contexa.contexacommon.enums.RiskLevel level) {
        toolRiskMap.put(toolName, level);
            }

    private io.contexa.contexacommon.enums.RiskLevel getAnnotationRiskLevel(ToolCallback tool) {
        try {
            Class<?> toolClass = tool.getClass();
            SoarTool annotation = toolClass.getAnnotation(SoarTool.class);
            
            if (annotation != null) {
                return convertSoarRiskLevel(annotation.riskLevel());
            }
        } catch (Exception e) {
            log.warn("어노테이션 위험도 추출 실패 (Fail-Close 적용): {}", e.getMessage());
            
            return io.contexa.contexacommon.enums.RiskLevel.HIGH;
        }

        return io.contexa.contexacommon.enums.RiskLevel.LOW;
    }

    private io.contexa.contexacommon.enums.RiskLevel convertSoarRiskLevel(SoarTool.RiskLevel soarLevel) {
        return switch (soarLevel) {
            case LOW -> io.contexa.contexacommon.enums.RiskLevel.LOW;
            case MEDIUM -> io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
            case HIGH -> io.contexa.contexacommon.enums.RiskLevel.HIGH;
            case CRITICAL -> io.contexa.contexacommon.enums.RiskLevel.CRITICAL;
        };
    }

    private io.contexa.contexacommon.enums.RiskLevel assessByToolName(String toolName) {
        
        if (toolRiskMap.containsKey(toolName)) {
            return toolRiskMap.get(toolName);
        }
        
        String lowerName = toolName.toLowerCase();

        for (String keyword : CRITICAL_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                for (String highRisk : HIGH_RISK_KEYWORDS) {
                    if (lowerName.contains(highRisk)) {
                        return io.contexa.contexacommon.enums.RiskLevel.CRITICAL;
                    }
                }
            }
        }

        for (String keyword : HIGH_RISK_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                return io.contexa.contexacommon.enums.RiskLevel.HIGH;
            }
        }

        if (lowerName.contains("scan") || lowerName.contains("analysis") || 
            lowerName.contains("detect")) {
            return io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
        }

        if (lowerName.contains("read") || lowerName.contains("list") || 
            lowerName.contains("get") || lowerName.contains("view")) {
            return io.contexa.contexacommon.enums.RiskLevel.LOW;
        }
        
        return io.contexa.contexacommon.enums.RiskLevel.MEDIUM; 
    }

    private io.contexa.contexacommon.enums.RiskLevel assessByContext(Map<String, Object> context) {
        if (context == null) {
            return io.contexa.contexacommon.enums.RiskLevel.LOW;
        }

        if (Boolean.TRUE.equals(context.get("productionEnvironment"))) {
            return io.contexa.contexacommon.enums.RiskLevel.HIGH;
        }

        String target = (String) context.get("target");
        if (target != null) {
            if (target.contains("production") || target.contains("critical")) {
                return io.contexa.contexacommon.enums.RiskLevel.HIGH;
            }
        }

        String userId = (String) context.get("userId");
        if (userId != null && !userId.equals("admin")) {
            return io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
        }
        
        return io.contexa.contexacommon.enums.RiskLevel.LOW;
    }

    private io.contexa.contexacommon.enums.RiskLevel assessByTime() {
        LocalTime now = LocalTime.now();

        if (now.isAfter(LocalTime.of(22, 0)) || now.isBefore(LocalTime.of(6, 0))) {
            return io.contexa.contexacommon.enums.RiskLevel.HIGH;
        }

        if (now.isAfter(LocalTime.of(12, 0)) && now.isBefore(LocalTime.of(13, 0))) {
            return io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
        }
        
        return io.contexa.contexacommon.enums.RiskLevel.LOW;
    }

    private io.contexa.contexacommon.enums.RiskLevel getHighestRisk(io.contexa.contexacommon.enums.RiskLevel... levels) {
        io.contexa.contexacommon.enums.RiskLevel highest = io.contexa.contexacommon.enums.RiskLevel.LOW;
        
        for (io.contexa.contexacommon.enums.RiskLevel level : levels) {
            if (level.ordinal() > highest.ordinal()) {
                highest = level;
            }
        }
        
        return highest;
    }

    private Map<String, String> getAssessmentFactors(ToolCallback tool, Map<String, Object> context) {
        Map<String, String> factors = new HashMap<>();
        
        factors.put("toolName", tool.getToolDefinition().name());
        factors.put("toolDescription", tool.getToolDefinition().description());
        
        if (context != null) {
            factors.put("environment", String.valueOf(context.get("productionEnvironment")));
            factors.put("userId", String.valueOf(context.get("userId")));
        }
        
        factors.put("timeOfDay", LocalTime.now().toString());
        
        return factors;
    }

    private String getRecommendations(io.contexa.contexacommon.enums.RiskLevel level) {
        return switch (level) {
            case LOW -> "안전한 작업입니다. 실행 가능합니다.";
            case MEDIUM -> "주의가 필요한 작업입니다. 실행 전 확인하세요.";
            case HIGH -> "위험한 작업입니다. 승인이 필요합니다.";
            case CRITICAL -> "매우 위험한 작업입니다. 다단계 승인이 필요합니다.";
        };
    }

    @Data
    @Builder
    public static class RiskAssessmentResult {
        private String toolName;
        private io.contexa.contexacommon.enums.RiskLevel riskLevel;
        private boolean requiresApproval;
        private Map<String, String> assessmentFactors;
        private String recommendations;
    }
}