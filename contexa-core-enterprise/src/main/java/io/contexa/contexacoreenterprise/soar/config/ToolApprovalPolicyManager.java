package io.contexa.contexacoreenterprise.soar.config;

import io.contexa.contexacommon.annotation.SoarTool;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;


@Slf4j
public class ToolApprovalPolicyManager {
    
    
    private final Map<String, ApprovalPolicy> toolPolicies = new ConcurrentHashMap<>();
    
    
    private final List<PatternBasedPolicy> patternPolicies = new ArrayList<>();
    
    
    private ApprovalPolicy defaultPolicy;
    
    @PostConstruct
    public void initialize() {
        log.info("Tool Approval Policy Manager 초기화");
        
        
        defaultPolicy = new ApprovalPolicy();
        defaultPolicy.setRequiresApproval(false);
        defaultPolicy.setRiskLevel(SoarTool.RiskLevel.LOW);
        defaultPolicy.setTimeoutSeconds(300); 
        
        
        loadDefaultPolicies();
    }
    
    
    public boolean requiresApproval(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.isRequiresApproval();
    }
    
    
    public SoarTool.RiskLevel getRiskLevel(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getRiskLevel();
    }
    
    
    public int getApprovalTimeout(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getTimeoutSeconds();
    }
    
    
    public boolean isBlocked(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        
        
        if (policy.getRiskLevel() == SoarTool.RiskLevel.CRITICAL) {
            
            return false; 
        }
        
        
        return isInBlockedList(toolName);
    }
    
    
    private boolean isInBlockedList(String toolName) {
        
        String[] blockedPatterns = {
            "system_shutdown",
            "data_delete_all", 
            "format_disk",
            "drop_database"
        };
        
        for (String pattern : blockedPatterns) {
            if (toolName.toLowerCase().contains(pattern.toLowerCase())) {
                return true;
            }
        }
        
        return false;
    }
    
    
    public ApprovalPolicy getPolicy(String toolName) {
        
        if (toolPolicies.containsKey(toolName)) {
            return toolPolicies.get(toolName);
        }
        
        
        for (PatternBasedPolicy patternPolicy : patternPolicies) {
            if (patternPolicy.matches(toolName)) {
                return patternPolicy.getPolicy();
            }
        }
        
        
        return defaultPolicy;
    }
    
    
    public void setPolicy(String toolName, ApprovalPolicy policy) {
        toolPolicies.put(toolName, policy);
        log.info("도구 정책 설정: {} -> {}", toolName, policy);
    }
    
    
    public void addPatternPolicy(String pattern, ApprovalPolicy policy) {
        patternPolicies.add(new PatternBasedPolicy(pattern, policy));
        log.info("패턴 정책 추가: {} -> {}", pattern, policy);
    }
    
    
    private void loadDefaultPolicies() {
        
        ApprovalPolicy highRiskPolicy = new ApprovalPolicy();
        highRiskPolicy.setRequiresApproval(true);
        highRiskPolicy.setRiskLevel(SoarTool.RiskLevel.HIGH);
        highRiskPolicy.setTimeoutSeconds(180); 
        highRiskPolicy.setDescription("High risk operations requiring approval");
        
        addPatternPolicy(".*block.*", highRiskPolicy);
        addPatternPolicy(".*isolate.*", highRiskPolicy);
        addPatternPolicy(".*delete.*", highRiskPolicy);
        addPatternPolicy(".*shutdown.*", highRiskPolicy);
        
        
        ApprovalPolicy criticalRiskPolicy = new ApprovalPolicy();
        criticalRiskPolicy.setRequiresApproval(true);
        criticalRiskPolicy.setRiskLevel(SoarTool.RiskLevel.CRITICAL);
        criticalRiskPolicy.setTimeoutSeconds(120); 
        criticalRiskPolicy.setDescription("Critical operations requiring immediate approval");
        
        addPatternPolicy(".*destroy.*", criticalRiskPolicy);
        addPatternPolicy(".*terminate.*", criticalRiskPolicy);
        addPatternPolicy(".*wipe.*", criticalRiskPolicy);
        
        
        ApprovalPolicy mediumRiskPolicy = new ApprovalPolicy();
        mediumRiskPolicy.setRequiresApproval(true);
        mediumRiskPolicy.setRiskLevel(SoarTool.RiskLevel.MEDIUM);
        mediumRiskPolicy.setTimeoutSeconds(300); 
        mediumRiskPolicy.setDescription("Medium risk operations");
        
        addPatternPolicy(".*modify.*", mediumRiskPolicy);
        addPatternPolicy(".*update.*", mediumRiskPolicy);
        addPatternPolicy(".*execute.*", mediumRiskPolicy);
        
        
        ApprovalPolicy lowRiskPolicy = new ApprovalPolicy();
        lowRiskPolicy.setRequiresApproval(false);
        lowRiskPolicy.setRiskLevel(SoarTool.RiskLevel.LOW);
        lowRiskPolicy.setTimeoutSeconds(600); 
        lowRiskPolicy.setDescription("Low risk read-only operations");
        
        addPatternPolicy(".*read.*", lowRiskPolicy);
        addPatternPolicy(".*list.*", lowRiskPolicy);
        addPatternPolicy(".*get.*", lowRiskPolicy);
        addPatternPolicy(".*search.*", lowRiskPolicy);
        addPatternPolicy(".*analyze.*", lowRiskPolicy);
        
        log.info("기본 승인 정책 로드 완료: {} 개의 패턴 정책", patternPolicies.size());
    }
    
    
    public Map<String, Object> getAllPolicies() {
        Map<String, Object> allPolicies = new HashMap<>();
        allPolicies.put("toolPolicies", toolPolicies);
        allPolicies.put("patternPolicies", patternPolicies);
        allPolicies.put("defaultPolicy", defaultPolicy);
        return allPolicies;
    }
    
    
    public Map<String, Object> getPolicyStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalToolPolicies", toolPolicies.size());
        stats.put("totalPatternPolicies", patternPolicies.size());
        
        
        Map<SoarTool.RiskLevel, Integer> riskDistribution = new HashMap<>();
        for (ApprovalPolicy policy : toolPolicies.values()) {
            riskDistribution.merge(policy.getRiskLevel(), 1, Integer::sum);
        }
        stats.put("riskDistribution", riskDistribution);
        
        return stats;
    }
    
    
    @Data
    public static class ApprovalPolicy {
        private boolean requiresApproval;
        private SoarTool.RiskLevel riskLevel;
        private int timeoutSeconds;
        private String description;
        private Map<String, Object> metadata = new HashMap<>();
        
        @Override
        public String toString() {
            return String.format("ApprovalPolicy{requires=%s, risk=%s, timeout=%ds}", 
                requiresApproval, riskLevel, timeoutSeconds);
        }
    }
    
    
    @Data
    private static class PatternBasedPolicy {
        private final Pattern pattern;
        private final ApprovalPolicy policy;
        
        public PatternBasedPolicy(String patternString, ApprovalPolicy policy) {
            this.pattern = Pattern.compile(patternString, Pattern.CASE_INSENSITIVE);
            this.policy = policy;
        }
        
        public boolean matches(String toolName) {
            return pattern.matcher(toolName).matches();
        }
        
        @Override
        public String toString() {
            return String.format("PatternPolicy{pattern=%s, policy=%s}", 
                pattern.pattern(), policy);
        }
    }
}