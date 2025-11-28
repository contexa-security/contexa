package io.contexa.contexacore.autonomous.authorization;
import io.contexa.contexacommon.enums.RiskLevel;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.observation.ToolCallingObservationContext;
import org.springframework.stereotype.Component;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * RiskAssessment
 * 
 * 도구 실행의 위험도를 평가합니다.
 * 도구 유형, 실행 컨텍스트, 시간대 등을 고려하여 위험도를 산정합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class RiskAssessment {
    
    // 도구별 기본 위험도 맵
    private final Map<String, io.contexa.contexacommon.enums.RiskLevel> toolRiskMap = new HashMap<>();
    
    // 위험 키워드들
    private static final Set<String> HIGH_RISK_KEYWORDS = Set.of(
        "delete", "remove", "kill", "terminate", "shutdown", "destroy",
        "format", "wipe", "purge", "quarantine", "isolate"
    );
    
    private static final Set<String> CRITICAL_KEYWORDS = Set.of(
        "system", "kernel", "root", "admin", "production", "critical"
    );
    
    /**
     * 도구 실행 위험도 평가
     */
    public io.contexa.contexacommon.enums.RiskLevel assess(ToolCallback tool, Map<String, Object> context) {
        String toolName = tool.getToolDefinition().name();
        
        log.debug("위험도 평가 시작: {}", toolName);
        
        // 1. 도구 어노테이션 기반 평가
        io.contexa.contexacommon.enums.RiskLevel annotationRisk = getAnnotationRiskLevel(tool);
        
        // 2. 도구 이름 기반 평가
        io.contexa.contexacommon.enums.RiskLevel nameRisk = assessByToolName(toolName);
        
        // 3. 컨텍스트 기반 평가
        io.contexa.contexacommon.enums.RiskLevel contextRisk = assessByContext(context);
        
        // 4. 시간대 기반 평가
        io.contexa.contexacommon.enums.RiskLevel timeRisk = assessByTime();
        
        // 최종 위험도 결정 (가장 높은 레벨 선택)
        io.contexa.contexacommon.enums.RiskLevel finalRisk = getHighestRisk(
            annotationRisk, nameRisk, contextRisk, timeRisk
        );
        
        log.info("위험도 평가 완료: {} -> {}", toolName, finalRisk);
        
        return finalRisk;
    }
    
    /**
     * ObservationContext를 사용한 위험도 평가
     */
    public io.contexa.contexacommon.enums.RiskLevel assess(ToolCallingObservationContext context) {
        // ObservationContext에서 도구 이름 추출
        String toolName = "unknown";
        
        // 도구 이름으로 기본 평가
        io.contexa.contexacommon.enums.RiskLevel baseRisk = assessByToolName(toolName);
        
        return baseRisk;
    }
    
    /**
     * 위험도 평가 결과
     */
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
    
    /**
     * 승인 필요 여부
     */
    public boolean requiresApproval(io.contexa.contexacommon.enums.RiskLevel riskLevel) {
        return riskLevel == io.contexa.contexacommon.enums.RiskLevel.HIGH || 
               riskLevel == io.contexa.contexacommon.enums.RiskLevel.CRITICAL;
    }
    
    /**
     * 도구별 위험도 설정
     */
    public void setToolRiskLevel(String toolName, io.contexa.contexacommon.enums.RiskLevel level) {
        toolRiskMap.put(toolName, level);
        log.debug("도구 위험도 설정: {} -> {}", toolName, level);
    }
    
    // Private 메서드들
    
    /**
     * 어노테이션 기반 위험도 추출
     */
    private io.contexa.contexacommon.enums.RiskLevel getAnnotationRiskLevel(ToolCallback tool) {
        try {
            Class<?> toolClass = tool.getClass();
            SoarTool annotation = toolClass.getAnnotation(SoarTool.class);
            
            if (annotation != null) {
                return convertSoarRiskLevel(annotation.riskLevel());
            }
        } catch (Exception e) {
            log.warn("어노테이션 위험도 추출 실패 (Fail-Close 적용): {}", e.getMessage());
            // Fail-Close: 예외 발생 시 높은 위험도 반환 (Zero Trust 원칙)
            return io.contexa.contexacommon.enums.RiskLevel.HIGH;
        }

        return io.contexa.contexacommon.enums.RiskLevel.LOW;
    }
    
    /**
     * SOAR 위험도를 Approval 위험도로 변환
     */
    private io.contexa.contexacommon.enums.RiskLevel convertSoarRiskLevel(SoarTool.RiskLevel soarLevel) {
        return switch (soarLevel) {
            case LOW -> io.contexa.contexacommon.enums.RiskLevel.LOW;
            case MEDIUM -> io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
            case HIGH -> io.contexa.contexacommon.enums.RiskLevel.HIGH;
            case CRITICAL -> io.contexa.contexacommon.enums.RiskLevel.CRITICAL;
        };
    }
    
    /**
     * 도구 이름 기반 위험도 평가
     */
    private io.contexa.contexacommon.enums.RiskLevel assessByToolName(String toolName) {
        // 미리 설정된 위험도 확인
        if (toolRiskMap.containsKey(toolName)) {
            return toolRiskMap.get(toolName);
        }
        
        String lowerName = toolName.toLowerCase();
        
        // Critical 키워드 확인
        for (String keyword : CRITICAL_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                for (String highRisk : HIGH_RISK_KEYWORDS) {
                    if (lowerName.contains(highRisk)) {
                        return io.contexa.contexacommon.enums.RiskLevel.CRITICAL;
                    }
                }
            }
        }
        
        // High Risk 키워드 확인
        for (String keyword : HIGH_RISK_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                return io.contexa.contexacommon.enums.RiskLevel.HIGH;
            }
        }
        
        // 분석/스캔 도구는 중간 위험도
        if (lowerName.contains("scan") || lowerName.contains("analysis") || 
            lowerName.contains("detect")) {
            return io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
        }
        
        // 읽기 전용은 낮은 위험도
        if (lowerName.contains("read") || lowerName.contains("list") || 
            lowerName.contains("get") || lowerName.contains("view")) {
            return io.contexa.contexacommon.enums.RiskLevel.LOW;
        }
        
        return io.contexa.contexacommon.enums.RiskLevel.MEDIUM; // 기본값
    }
    
    /**
     * 컨텍스트 기반 위험도 평가
     */
    private io.contexa.contexacommon.enums.RiskLevel assessByContext(Map<String, Object> context) {
        if (context == null) {
            return io.contexa.contexacommon.enums.RiskLevel.LOW;
        }
        
        // 운영 환경 확인
        if (Boolean.TRUE.equals(context.get("productionEnvironment"))) {
            return io.contexa.contexacommon.enums.RiskLevel.HIGH;
        }
        
        // 대상 시스템 확인
        String target = (String) context.get("target");
        if (target != null) {
            if (target.contains("production") || target.contains("critical")) {
                return io.contexa.contexacommon.enums.RiskLevel.HIGH;
            }
        }
        
        // 사용자 권한 확인
        String userId = (String) context.get("userId");
        if (userId != null && !userId.equals("admin")) {
            return io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
        }
        
        return io.contexa.contexacommon.enums.RiskLevel.LOW;
    }
    
    /**
     * 시간대 기반 위험도 평가
     */
    private io.contexa.contexacommon.enums.RiskLevel assessByTime() {
        LocalTime now = LocalTime.now();
        
        // 업무 시간 외 (저녁 10시 ~ 아침 6시)
        if (now.isAfter(LocalTime.of(22, 0)) || now.isBefore(LocalTime.of(6, 0))) {
            return io.contexa.contexacommon.enums.RiskLevel.HIGH;
        }
        
        // 점심시간 (12시 ~ 1시)
        if (now.isAfter(LocalTime.of(12, 0)) && now.isBefore(LocalTime.of(13, 0))) {
            return io.contexa.contexacommon.enums.RiskLevel.MEDIUM;
        }
        
        return io.contexa.contexacommon.enums.RiskLevel.LOW;
    }
    
    /**
     * 가장 높은 위험도 반환
     */
    private io.contexa.contexacommon.enums.RiskLevel getHighestRisk(io.contexa.contexacommon.enums.RiskLevel... levels) {
        io.contexa.contexacommon.enums.RiskLevel highest = io.contexa.contexacommon.enums.RiskLevel.LOW;
        
        for (io.contexa.contexacommon.enums.RiskLevel level : levels) {
            if (level.ordinal() > highest.ordinal()) {
                highest = level;
            }
        }
        
        return highest;
    }
    
    /**
     * 평가 요소들
     */
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
    
    /**
     * 권장사항
     */
    private String getRecommendations(io.contexa.contexacommon.enums.RiskLevel level) {
        return switch (level) {
            case LOW -> "안전한 작업입니다. 실행 가능합니다.";
            case MEDIUM -> "주의가 필요한 작업입니다. 실행 전 확인하세요.";
            case HIGH -> "위험한 작업입니다. 승인이 필요합니다.";
            case CRITICAL -> "매우 위험한 작업입니다. 다단계 승인이 필요합니다.";
        };
    }
    
    /**
     * 위험도 평가 결과
     */
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