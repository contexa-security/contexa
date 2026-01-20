package io.contexa.contexacommon.domain.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;


@Getter
@Setter
public class RiskAssessmentContext extends IAMContext {
    
    private static final String IAM_CONTEXT_TYPE = "RISK_ASSESSMENT";
    
    
    private String userId;
    private String userName;
    private String sessionId;
    
    
    private String resourceIdentifier;
    private String actionType;
    private String methodName;
    
    
    private String remoteIp;
    private String userAgent;
    private String location;
    
    
    private List<String> userRoles;
    private List<String> userGroups;
    private List<String> userPermissions;
    
    
    private String historyContext; 
    private Map<String, Object> behaviorMetrics; 
    private Map<String, Object> environmentAttributes; 
    
    
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
    
    
    public static RiskAssessmentContext create(String userId, String resourceIdentifier, String actionType) {
        RiskAssessmentContext context = new RiskAssessmentContext();
        context.setUserId(userId);
        context.setResourceIdentifier(resourceIdentifier);
        context.setActionType(actionType);
        context.addIAMMetadata("securityLevel", SecurityLevel.STANDARD);
        context.addIAMMetadata("auditRequirement", AuditRequirement.DETAILED);
        return context;
    }
    
    
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
    
    
    public static RiskAssessmentContext createUrgent(String userId, String resourceIdentifier, 
                                                    String actionType, String reason) {
        RiskAssessmentContext context = create(userId, resourceIdentifier, actionType);
        context.addIAMMetadata("securityLevel", SecurityLevel.MAXIMUM);
        context.addIAMMetadata("auditRequirement", AuditRequirement.COMPREHENSIVE);
        context.getEnvironmentAttributes().put("urgentReason", reason);
        return context;
    }
    
    
    public RiskAssessmentContext withHistoryContext(String historyContext) {
        this.historyContext = historyContext;
        return this;
    }
    
    
    public RiskAssessmentContext withBehaviorMetrics(Map<String, Object> behaviorMetrics) {
        this.behaviorMetrics = behaviorMetrics;
        return this;
    }
    
    
    public RiskAssessmentContext withEnvironmentAttribute(String key, Object value) {
        if (this.environmentAttributes == null) {
            this.environmentAttributes = new java.util.HashMap<>();
        }
        this.environmentAttributes.put(key, value);
        return this;
    }
    
    
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