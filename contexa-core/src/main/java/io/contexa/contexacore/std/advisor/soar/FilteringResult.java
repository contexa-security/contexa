package io.contexa.contexacore.std.advisor.soar;

import io.contexa.contexacommon.annotation.SoarTool;
import lombok.Getter;

import java.util.*;


@Getter
public class FilteringResult {
    
    
    private final List<String> allowedTools = new ArrayList<>();
    
    
    private final List<String> filteredTools = new ArrayList<>();
    
    
    private final Map<String, SoarTool.RiskLevel> toolRiskMap = new HashMap<>();
    
    
    private final Map<String, Map<String, Object>> toolMetadata = new HashMap<>();
    
    
    private final List<String> highRiskTools = new ArrayList<>();
    
    
    public void addAllowedTool(String toolName) {
        if (toolName != null && !allowedTools.contains(toolName)) {
            allowedTools.add(toolName);
        }
    }
    
    
    public void addFilteredTool(String toolName) {
        if (toolName != null && !filteredTools.contains(toolName)) {
            filteredTools.add(toolName);
        }
    }
    
    
    public void addToolRisk(String toolName, SoarTool.RiskLevel riskLevel) {
        if (toolName != null && riskLevel != null) {
            toolRiskMap.put(toolName, riskLevel);
        }
    }
    
    
    public void addToolMetadata(String toolName, Map<String, Object> metadata) {
        if (toolName != null && metadata != null) {
            toolMetadata.put(toolName, new HashMap<>(metadata));
        }
    }
    
    
    public void addHighRiskTool(String toolName) {
        if (toolName != null && !highRiskTools.contains(toolName)) {
            highRiskTools.add(toolName);
        }
    }
    
    
    public boolean hasFilteredTools() {
        return !filteredTools.isEmpty();
    }
    
    
    public boolean hasHighRiskTools() {
        return !highRiskTools.isEmpty();
    }
    
    
    public boolean isAllowed(String toolName) {
        return allowedTools.contains(toolName);
    }
    
    
    public boolean isFiltered(String toolName) {
        return filteredTools.contains(toolName);
    }
    
    
    public SoarTool.RiskLevel getRiskLevel(String toolName) {
        return toolRiskMap.get(toolName);
    }
    
    
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalAllowed", allowedTools.size());
        stats.put("totalFiltered", filteredTools.size());
        stats.put("totalHighRisk", highRiskTools.size());
        stats.put("hasHighRisk", hasHighRiskTools());
        
        
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