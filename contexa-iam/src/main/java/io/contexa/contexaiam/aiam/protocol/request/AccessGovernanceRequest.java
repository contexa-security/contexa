package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.DiagnosisType;


public class AccessGovernanceRequest extends IAMRequest<AccessGovernanceContext> {

    private static final DiagnosisType DIAGNOSIS_TYPE = DiagnosisType.ACCESS_GOVERNANCE;

    public AccessGovernanceRequest(AccessGovernanceContext context, String operation) {
        super(context, operation);
        this.withDiagnosisType(DIAGNOSIS_TYPE);
    }
    
    
    public static AccessGovernanceRequest createComprehensiveAnalysis(String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope("ALL_USERS");
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.COMPREHENSIVE.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
    
    
    public static AccessGovernanceRequest createScopeAnalysis(String auditScope, String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope(auditScope);
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.PERMISSION_AUDIT.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
    
    
    public static AccessGovernanceRequest createRoleOptimizationAnalysis(String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope("ALL_USERS");
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.ROLE_OPTIMIZATION.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
    
    
    public static AccessGovernanceRequest createSodViolationAnalysis(String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope("ALL_USERS");
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.SOD_VIOLATION.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
} 