package io.contexa.contexacore.std.advisor.soar;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.Getter;

import java.util.*;

/**
 * 도구 정책 필터링 결과
 * 
 * SOAR 도구 정책 적용 후의 필터링 결과를 담는 클래스입니다.
 * 허용된 도구, 차단된 도구, 위험도 정보, 메타데이터 등을 관리합니다.
 */
@Getter
public class FilteringResult {
    
    /** 허용된 도구 목록 */
    private final List<String> allowedTools = new ArrayList<>();
    
    /** 차단된(필터링된) 도구 목록 */
    private final List<String> filteredTools = new ArrayList<>();
    
    /** 도구별 위험도 매핑 */
    private final Map<String, SoarTool.RiskLevel> toolRiskMap = new HashMap<>();
    
    /** 도구별 메타데이터 */
    private final Map<String, Map<String, Object>> toolMetadata = new HashMap<>();
    
    /** 고위험 도구 목록 */
    private final List<String> highRiskTools = new ArrayList<>();
    
    /**
     * 허용된 도구 추가
     */
    public void addAllowedTool(String toolName) {
        if (toolName != null && !allowedTools.contains(toolName)) {
            allowedTools.add(toolName);
        }
    }
    
    /**
     * 차단된 도구 추가
     */
    public void addFilteredTool(String toolName) {
        if (toolName != null && !filteredTools.contains(toolName)) {
            filteredTools.add(toolName);
        }
    }
    
    /**
     * 도구 위험도 추가
     */
    public void addToolRisk(String toolName, SoarTool.RiskLevel riskLevel) {
        if (toolName != null && riskLevel != null) {
            toolRiskMap.put(toolName, riskLevel);
        }
    }
    
    /**
     * 도구 메타데이터 추가
     */
    public void addToolMetadata(String toolName, Map<String, Object> metadata) {
        if (toolName != null && metadata != null) {
            toolMetadata.put(toolName, new HashMap<>(metadata));
        }
    }
    
    /**
     * 고위험 도구 추가
     */
    public void addHighRiskTool(String toolName) {
        if (toolName != null && !highRiskTools.contains(toolName)) {
            highRiskTools.add(toolName);
        }
    }
    
    /**
     * 필터링된 도구가 있는지 확인
     */
    public boolean hasFilteredTools() {
        return !filteredTools.isEmpty();
    }
    
    /**
     * 고위험 도구가 있는지 확인
     */
    public boolean hasHighRiskTools() {
        return !highRiskTools.isEmpty();
    }
    
    /**
     * 특정 도구가 허용되었는지 확인
     */
    public boolean isAllowed(String toolName) {
        return allowedTools.contains(toolName);
    }
    
    /**
     * 특정 도구가 차단되었는지 확인
     */
    public boolean isFiltered(String toolName) {
        return filteredTools.contains(toolName);
    }
    
    /**
     * 특정 도구의 위험도 조회
     */
    public SoarTool.RiskLevel getRiskLevel(String toolName) {
        return toolRiskMap.get(toolName);
    }
    
    /**
     * 전체 필터링 통계 조회
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalAllowed", allowedTools.size());
        stats.put("totalFiltered", filteredTools.size());
        stats.put("totalHighRisk", highRiskTools.size());
        stats.put("hasHighRisk", hasHighRiskTools());
        
        // 위험도별 도구 개수
        Map<String, Long> riskDistribution = new HashMap<>();
        for (SoarTool.RiskLevel level : SoarTool.RiskLevel.values()) {
            long count = toolRiskMap.values().stream()
                .filter(risk -> risk == level)
                .count();
            riskDistribution.put(level.name(), count);
        }
        stats.put("riskDistribution", riskDistribution);
        
        return stats;
    }
    
    @Override
    public String toString() {
        return String.format("FilteringResult{allowed=%d, filtered=%d, highRisk=%d}",
            allowedTools.size(), filteredTools.size(), highRiskTools.size());
    }
}