package io.contexa.contexacommon.domain.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * 위험 평가 컨텍스트
 * 
 * 제로 트러스트 기반 위험 평가를 위한 모든 필요한 정보를 담는 컨텍스트입니다.
 * CustomWebSecurityExpressionRoot에서 사용되며 실시간 위험 평가에 활용됩니다.
 */
@Getter
@Setter
public class RiskAssessmentContext extends IAMContext {
    
    private static final String IAM_CONTEXT_TYPE = "RISK_ASSESSMENT";
    
    // 기본 인증 정보
    private String userId;
    private String userName;
    private String sessionId;
    
    // 접근 대상 정보
    private String resourceIdentifier;
    private String actionType;
    private String methodName;
    
    // 네트워크 정보
    private String remoteIp;
    private String userAgent;
    private String location;
    
    // 사용자 권한 정보
    private List<String> userRoles;
    private List<String> userGroups;
    private List<String> userPermissions;
    
    // 컨텍스트 분석을 위한 추가 정보
    private String historyContext; // 과거 접근 패턴 요약
    private Map<String, Object> behaviorMetrics; // 행동 분석 메트릭
    private Map<String, Object> environmentAttributes; // 환경 속성
    
    // 위험 평가 설정
    private boolean enableHistoryAnalysis = true;
    private boolean enableBehaviorAnalysis = true;
    private int maxHistoryRecords = 5;
    private double riskThreshold = 0.5;
    
    public RiskAssessmentContext() {
        super(SecurityLevel.STANDARD, AuditRequirement.DETAILED);
        this.behaviorMetrics = new java.util.HashMap<>();
        this.environmentAttributes = new java.util.HashMap<>();
    }
    
    public RiskAssessmentContext(String userId, String sessionId,
                                 SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(userId, sessionId, securityLevel, auditRequirement);
        this.userId = userId;
        this.sessionId = sessionId;
        this.behaviorMetrics = new java.util.HashMap<>();
        this.environmentAttributes = new java.util.HashMap<>();
    }
    
    /**
     * 기본 위험 평가 컨텍스트 생성
     */
    public static RiskAssessmentContext create(String userId, String resourceIdentifier, String actionType) {
        RiskAssessmentContext context = new RiskAssessmentContext();
        context.setUserId(userId);
        context.setResourceIdentifier(resourceIdentifier);
        context.setActionType(actionType);
        context.addIAMMetadata("securityLevel", SecurityLevel.STANDARD);
        context.addIAMMetadata("auditRequirement", AuditRequirement.DETAILED);
        return context;
    }
    
    /**
     * 상세 위험 평가 컨텍스트 생성
     */
    public static RiskAssessmentContext createDetailed(String userId, String userName, String sessionId,
                                                      String resourceIdentifier, String actionType,
                                                      String remoteIp, List<String> userRoles) {
        RiskAssessmentContext context = new RiskAssessmentContext(userId, sessionId, 
                                                                  SecurityLevel.ENHANCED, AuditRequirement.DETAILED);
        context.setUserName(userName);
        context.setResourceIdentifier(resourceIdentifier);
        context.setActionType(actionType);
        context.setRemoteIp(remoteIp);
        context.setUserRoles(userRoles);
        return context;
    }
    
    /**
     * 긴급 위험 평가 컨텍스트 생성
     */
    public static RiskAssessmentContext createUrgent(String userId, String resourceIdentifier, 
                                                    String actionType, String reason) {
        RiskAssessmentContext context = create(userId, resourceIdentifier, actionType);
        context.addIAMMetadata("securityLevel", SecurityLevel.MAXIMUM);
        context.addIAMMetadata("auditRequirement", AuditRequirement.COMPREHENSIVE);
        context.getEnvironmentAttributes().put("urgentReason", reason);
        return context;
    }
    
    /**
     * 히스토리 컨텍스트 설정
     */
    public RiskAssessmentContext withHistoryContext(String historyContext) {
        this.historyContext = historyContext;
        return this;
    }
    
    /**
     * 행동 메트릭 설정
     */
    public RiskAssessmentContext withBehaviorMetrics(Map<String, Object> behaviorMetrics) {
        this.behaviorMetrics = behaviorMetrics;
        return this;
    }
    
    /**
     * 환경 속성 설정
     */
    public RiskAssessmentContext withEnvironmentAttribute(String key, Object value) {
        if (this.environmentAttributes == null) {
            this.environmentAttributes = new java.util.HashMap<>();
        }
        this.environmentAttributes.put(key, value);
        return this;
    }
    
    /**
     * 복잡도 계산 (위험 평가용)
     */
    public int calculateRiskComplexity() {
        int complexity = 0;
        
        if (userRoles != null) complexity += userRoles.size();
        if (userGroups != null) complexity += userGroups.size();
        if (userPermissions != null) complexity += userPermissions.size();
        if (behaviorMetrics != null) complexity += behaviorMetrics.size();
        if (environmentAttributes != null) complexity += environmentAttributes.size();
        
        return complexity;
    }
    
    @Override
    public String getIAMContextType() {
        return IAM_CONTEXT_TYPE;
    }
    
    @Override
    public String toString() {
        return String.format("RiskAssessmentContext{userId='%s', resource='%s', action='%s', ip='%s', complexity=%d}", 
                userId, resourceIdentifier, actionType, remoteIp, calculateRiskComplexity());
    }
} 