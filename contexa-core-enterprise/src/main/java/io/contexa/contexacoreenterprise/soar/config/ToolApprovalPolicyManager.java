package io.contexa.contexacoreenterprise.soar.config;

import io.contexa.contexacommon.annotation.SoarTool;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Tool 승인 정책 관리자
 * 
 * 도구별 승인 정책을 관리하고 적용합니다.
 * 하드코딩된 로직 대신 정책 기반의 유연한 승인 메커니즘을 제공합니다.
 */
@Slf4j
public class ToolApprovalPolicyManager {
    
    // 도구별 정책 저장소
    private final Map<String, ApprovalPolicy> toolPolicies = new ConcurrentHashMap<>();
    
    // 패턴 기반 정책 저장소
    private final List<PatternBasedPolicy> patternPolicies = new ArrayList<>();
    
    // 기본 정책
    private ApprovalPolicy defaultPolicy;
    
    @PostConstruct
    public void initialize() {
        log.info("Tool Approval Policy Manager 초기화");
        
        // 기본 정책 설정
        defaultPolicy = new ApprovalPolicy();
        defaultPolicy.setRequiresApproval(false);
        defaultPolicy.setRiskLevel(SoarTool.RiskLevel.LOW);
        defaultPolicy.setTimeoutSeconds(300); // 5분
        
        // 초기 정책 로드 (추후 데이터베이스에서 로드 가능)
        loadDefaultPolicies();
    }
    
    /**
     * 도구가 승인이 필요한지 확인
     * 
     * @param toolName 도구 이름
     * @return 승인 필요 여부
     */
    public boolean requiresApproval(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.isRequiresApproval();
    }
    
    /**
     * 도구의 위험도 레벨 확인
     * 
     * @param toolName 도구 이름
     * @return 위험도 레벨
     */
    public SoarTool.RiskLevel getRiskLevel(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getRiskLevel();
    }
    
    /**
     * 도구의 승인 타임아웃 확인
     * 
     * @param toolName 도구 이름
     * @return 타임아웃 시간 (초)
     */
    public int getApprovalTimeout(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getTimeoutSeconds();
    }
    
    /**
     * 도구가 차단되었는지 확인
     * 
     * @param toolName 도구 이름
     * @return 차단 여부
     */
    public boolean isBlocked(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        
        // CRITICAL 위험도 도구는 기본적으로 차단될 수 있음
        if (policy.getRiskLevel() == SoarTool.RiskLevel.CRITICAL) {
            // 추후 더 세밀한 차단 로직 추가 가능
            return false; // 현재는 승인만 필요하고 차단하지는 않음
        }
        
        // 특정 도구 이름 패턴이 차단 목록에 있는지 확인
        return isInBlockedList(toolName);
    }
    
    /**
     * 차단 목록에 있는지 확인
     * 
     * @param toolName 도구 이름
     * @return 차단 목록 포함 여부
     */
    private boolean isInBlockedList(String toolName) {
        // 하드코딩된 차단 목록 (추후 설정으로 이동 가능)
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
    
    /**
     * 도구에 대한 정책 가져오기
     * 
     * @param toolName 도구 이름
     * @return 적용 가능한 정책
     */
    public ApprovalPolicy getPolicy(String toolName) {
        // 1. 도구별 정책 확인
        if (toolPolicies.containsKey(toolName)) {
            return toolPolicies.get(toolName);
        }
        
        // 2. 패턴 기반 정책 확인
        for (PatternBasedPolicy patternPolicy : patternPolicies) {
            if (patternPolicy.matches(toolName)) {
                return patternPolicy.getPolicy();
            }
        }
        
        // 3. 기본 정책 반환
        return defaultPolicy;
    }
    
    /**
     * 도구별 정책 설정
     * 
     * @param toolName 도구 이름
     * @param policy 적용할 정책
     */
    public void setPolicy(String toolName, ApprovalPolicy policy) {
        toolPolicies.put(toolName, policy);
        log.info("도구 정책 설정: {} -> {}", toolName, policy);
    }
    
    /**
     * 패턴 기반 정책 추가
     * 
     * @param pattern 도구 이름 패턴
     * @param policy 적용할 정책
     */
    public void addPatternPolicy(String pattern, ApprovalPolicy policy) {
        patternPolicies.add(new PatternBasedPolicy(pattern, policy));
        log.info("패턴 정책 추가: {} -> {}", pattern, policy);
    }
    
    /**
     * 기본 정책 로드
     * 실제 운영 환경에서는 데이터베이스나 설정 파일에서 로드
     */
    private void loadDefaultPolicies() {
        // HIGH RISK 도구 패턴
        ApprovalPolicy highRiskPolicy = new ApprovalPolicy();
        highRiskPolicy.setRequiresApproval(true);
        highRiskPolicy.setRiskLevel(SoarTool.RiskLevel.HIGH);
        highRiskPolicy.setTimeoutSeconds(180); // 3분
        highRiskPolicy.setDescription("High risk operations requiring approval");
        
        addPatternPolicy(".*block.*", highRiskPolicy);
        addPatternPolicy(".*isolate.*", highRiskPolicy);
        addPatternPolicy(".*delete.*", highRiskPolicy);
        addPatternPolicy(".*shutdown.*", highRiskPolicy);
        
        // CRITICAL RISK 도구 패턴
        ApprovalPolicy criticalRiskPolicy = new ApprovalPolicy();
        criticalRiskPolicy.setRequiresApproval(true);
        criticalRiskPolicy.setRiskLevel(SoarTool.RiskLevel.CRITICAL);
        criticalRiskPolicy.setTimeoutSeconds(120); // 2분
        criticalRiskPolicy.setDescription("Critical operations requiring immediate approval");
        
        addPatternPolicy(".*destroy.*", criticalRiskPolicy);
        addPatternPolicy(".*terminate.*", criticalRiskPolicy);
        addPatternPolicy(".*wipe.*", criticalRiskPolicy);
        
        // MEDIUM RISK 도구 패턴
        ApprovalPolicy mediumRiskPolicy = new ApprovalPolicy();
        mediumRiskPolicy.setRequiresApproval(true);
        mediumRiskPolicy.setRiskLevel(SoarTool.RiskLevel.MEDIUM);
        mediumRiskPolicy.setTimeoutSeconds(300); // 5분
        mediumRiskPolicy.setDescription("Medium risk operations");
        
        addPatternPolicy(".*modify.*", mediumRiskPolicy);
        addPatternPolicy(".*update.*", mediumRiskPolicy);
        addPatternPolicy(".*execute.*", mediumRiskPolicy);
        
        // LOW RISK 도구 패턴 (승인 불필요)
        ApprovalPolicy lowRiskPolicy = new ApprovalPolicy();
        lowRiskPolicy.setRequiresApproval(false);
        lowRiskPolicy.setRiskLevel(SoarTool.RiskLevel.LOW);
        lowRiskPolicy.setTimeoutSeconds(600); // 10분
        lowRiskPolicy.setDescription("Low risk read-only operations");
        
        addPatternPolicy(".*read.*", lowRiskPolicy);
        addPatternPolicy(".*list.*", lowRiskPolicy);
        addPatternPolicy(".*get.*", lowRiskPolicy);
        addPatternPolicy(".*search.*", lowRiskPolicy);
        addPatternPolicy(".*analyze.*", lowRiskPolicy);
        
        log.info("기본 승인 정책 로드 완료: {} 개의 패턴 정책", patternPolicies.size());
    }
    
    /**
     * 모든 정책 조회
     * 
     * @return 모든 정책 맵
     */
    public Map<String, Object> getAllPolicies() {
        Map<String, Object> allPolicies = new HashMap<>();
        allPolicies.put("toolPolicies", toolPolicies);
        allPolicies.put("patternPolicies", patternPolicies);
        allPolicies.put("defaultPolicy", defaultPolicy);
        return allPolicies;
    }
    
    /**
     * 정책 통계 조회
     * 
     * @return 정책 통계
     */
    public Map<String, Object> getPolicyStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalToolPolicies", toolPolicies.size());
        stats.put("totalPatternPolicies", patternPolicies.size());
        
        // 위험도별 통계
        Map<SoarTool.RiskLevel, Integer> riskDistribution = new HashMap<>();
        for (ApprovalPolicy policy : toolPolicies.values()) {
            riskDistribution.merge(policy.getRiskLevel(), 1, Integer::sum);
        }
        stats.put("riskDistribution", riskDistribution);
        
        return stats;
    }
    
    /**
     * 승인 정책 클래스
     */
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
    
    /**
     * 패턴 기반 정책 클래스
     */
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