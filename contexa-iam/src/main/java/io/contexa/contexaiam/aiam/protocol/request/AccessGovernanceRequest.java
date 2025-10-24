package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.DiagnosisType;

/**
 * 권한 거버넌스 분석 요청 객체
 * 
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하는 요청
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 */
public class AccessGovernanceRequest extends IAMRequest<AccessGovernanceContext> {

    private static final DiagnosisType DIAGNOSIS_TYPE = DiagnosisType.ACCESS_GOVERNANCE;

    public AccessGovernanceRequest(AccessGovernanceContext context, String operation) {
        super(context, operation);
        this.withDiagnosisType(DIAGNOSIS_TYPE);
    }
    
    /**
     * 권한 거버넌스 분석 요청 생성 (편의 메서드)
     */
    public static AccessGovernanceRequest createComprehensiveAnalysis(String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope("ALL_USERS");
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.COMPREHENSIVE.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
    
    /**
     * 특정 범위 권한 거버넌스 분석 요청 생성
     */
    public static AccessGovernanceRequest createScopeAnalysis(String auditScope, String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope(auditScope);
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.PERMISSION_AUDIT.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
    
    /**
     * 역할 최적화 분석 요청 생성
     */
    public static AccessGovernanceRequest createRoleOptimizationAnalysis(String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope("ALL_USERS");
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.ROLE_OPTIMIZATION.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
    
    /**
     * 업무 분리 위반 검사 요청 생성
     */
    public static AccessGovernanceRequest createSodViolationAnalysis(String organizationId) {
        AccessGovernanceContext context = new AccessGovernanceContext();
        context.setAuditScope("ALL_USERS");
        context.setAnalysisType(AccessGovernanceContext.AnalysisType.SOD_VIOLATION.name());
        context.setOrganizationId(organizationId);
        return new AccessGovernanceRequest(context, organizationId);
    }
} 