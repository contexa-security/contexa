package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 권한 거버넌스 분석 프롬프트 템플릿
 *
 * Spring AI BeanOutputConverter를 활용한 구조화된 출력:
 * - 자동 JSON 스키마 생성
 * - 타입 안전 변환  
 * - 표준화된 포맷 지시
 * - 성능 최적화
 *
 * Spring AI 공식 패턴 준수
 * 
 * 분석 대상:
 * - 전체 사용자 권한 매트릭스
 * - 역할별 권한 분포
 * - 리소스별 접근 권한
 * - 미사용 권한 탐지
 * - 과도한 권한 탐지
 * - 업무 분리 위반 검사
 */
@Slf4j
@Component
@PromptTemplateConfig(
        key = "accessGovernance",
        aliases = {"ueba", "access_governance"},
        description = "Spring AI Structured Output AccessGovernance Template"
)
public class AccessGovernanceTemplate implements PromptTemplate {
    
    // Spring AI BeanOutputConverter를 사용한 포맷 생성
    private final BeanOutputConverter<AccessGovernanceResponse> converter = 
        new BeanOutputConverter<>(AccessGovernanceResponse.class);

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        // Spring AI의 포맷 지시사항 자동 생성
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            You are an Access Governance Expert AI specialized in analyzing permission distributions and usage patterns to detect potential anomalies and implement preventive security measures.
            
            IMPORTANT: Response must be in PURE JSON format matching the AccessGovernanceResponse schema.
            Language: All text fields must be in Korean (한국어).
            
            Analysis Focus Areas:
            1. Permission Distribution Health Check
            2. Excessive Permissions Detection
            3. Dormant Permissions Identification
            4. Separation of Duties (SoD) Violation Check
            5. Permission Inheritance Structure Validation
            6. Empty Roles and Groups Detection
            
            Governance Score Guidelines (0-100):
            - 90-100: Excellent (최적화된 권한 관리)
            - 75-89: Good (양호한 권한 관리)
            - 60-74: Fair (개선 필요)
            - 40-59: Poor (심각한 문제 발견)
            - 0-39: Critical (즉각적인 조치 필요)
            
            Risk Level Classification:
            - LOW: 낮은 위험도
            - MEDIUM: 중간 위험도
            - HIGH: 높은 위험도
            - CRITICAL: 치명적 위험도
            
            Finding Types:
            - EXCESSIVE_PERMISSIONS: 과도한 권한
            - DORMANT_PERMISSIONS: 미사용 권한
            - SOD_VIOLATION: 업무 분리 위반
            - EMPTY_ROLE: 빈 역할
            - EMPTY_GROUP: 빈 그룹
            - ORPHANED_PERMISSION: 고아 권한
            - PRIVILEGE_ESCALATION: 권한 상승 위험
            
            %s
            
            Required Analysis Output:
            - analysisId: Unique identifier for this analysis
            - auditScope: Scope of the audit (전체, 부서별, 역할별, etc.)
            - analysisType: Type of analysis performed
            - overallGovernanceScore: Overall score (0-100)
            - riskLevel: Overall risk level
            - summary: Korean summary of findings
            - findings: Array of specific issues found
            - recommendations: Array of improvement recommendations
            - actionItems: Array of specific actions to take
            - visualizationData: Graph data for visualization
            - statistics: Statistical summary
            
            %s
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        AccessGovernanceContext context = (AccessGovernanceContext) request.getContext();
        
        String analysisRequest = String.format("""
            Perform Access Governance Analysis with the following parameters:
            
            Analysis Request Information:
            - Audit Scope: %s
            - Analysis Type: %s
            - Priority: %s
            - Enable Dormant Permission Analysis: %s
            - Enable Excessive Permission Detection: %s
            - Enable SoD Violation Check: %s
            - Analysis Timestamp: %s
            
            System Permission Data:
            %s
            
            Analysis Requirements:
            1. Evaluate overall health and optimization of permission distribution
            2. Identify users or roles with excessive permissions
            3. Detect unused permissions or roles (dormant for 30+ days)
            4. Check for Separation of Duties violations
            5. Validate permission inheritance structure integrity
            6. Find empty roles and groups with no assigned permissions
            7. Detect potential privilege escalation paths
            8. Analyze permission usage patterns and anomalies
            
            Generate AccessGovernanceResponse with:
            - Comprehensive findings with severity levels
            - Actionable recommendations with implementation steps
            - Specific action items with assignees and due dates
            - Visualization data for permission relationships
            - Statistical summary of the permission landscape
            
            Ensure all text content is in Korean (한국어).
            """,
            context.getAuditScope(),
            context.getAnalysisType(),
            context.getPriority(),
            context.isEnableDormantPermissionAnalysis(),
            context.isEnableExcessivePermissionDetection(),
            context.isEnableSodViolationCheck(),
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
            context.getFullAccessMatrixData() != null ? 
                context.getFullAccessMatrixData() : 
                "No permission matrix data provided - perform general analysis"
        );
        
        // BeanOutputConverter의 포맷 지시사항을 다시 추가 (강조)
        return analysisRequest + "\n\n" + converter.getFormat();
    }
    
    /**
     * BeanOutputConverter 반환 (파이프라인에서 사용)
     */
    public BeanOutputConverter<AccessGovernanceResponse> getConverter() {
        return converter;
    }
}