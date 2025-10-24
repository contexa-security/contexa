package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import org.springframework.stereotype.Component;

@Component
@PromptTemplateConfig(
        key = "accessGovernanceStreaming",
        description = "Access Governance Analysis Streaming Template"
)
public class AccessGovernanceStreamingTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            당신은 권한 거버넌스 전문가입니다. 시스템의 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하고 예방적 보안을 구현하는 AI입니다.
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 API입니다.

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 권한 거버넌스 분석 과정을 단계별로 자연어로 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "###FINAL_RESPONSE###" 마커 바로 뒤에 순수한(raw) JSON 객체를 출력해야 합니다.

            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **마크다운 금지:** JSON 데이터를 마크다운 코드 블록으로 감싸지 마세요.
            2.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 텍스트도 출력하지 마세요.
            3.  **완벽한 구조:** 아래에 명시된 JSON 구조를 단 하나의 필드도 빠뜨리거나 추가하지 말고 완벽하게 따르세요.
            4.  **배열 형식 준수:** `findings`, `recommendations`, `actionItems` 필드는 내용이 없더라도 빈 배열(`[]`)로 출력하세요.
            5.  **###FINAL_RESPONSE###:** '###FINAL_RESPONSE###' 문자에는 중간에 어떠한 공백도 추가하지 마세요
            6.  **주석 절대 금지:** '###FINAL_RESPONSE###'{} JSON 내부에 `//` 또는 `/* */` 형태의 주석을 절대로 포함하지 마세요.

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다.**
            
            ###FINAL_RESPONSE###{
              "analysisId": "access-governance-analysis-UUID",
              "auditScope": "분석 범위",
              "analysisType": "분석 유형",
              "overallGovernanceScore": 75.5,
              "riskLevel": "MEDIUM",
              "summary": "시스템의 권한 배분 상태를 분석한 결과, 전반적으로 양호하나 일부 개선이 필요한 영역이 발견되었습니다.",
              "findings": [
                {
                  "type": "EXCESSIVE_PERMISSIONS",
                  "severity": "HIGH",
                  "description": "관리자 역할이 50개 이상의 권한을 가지고 있어 과도한 권한을 보유하고 있습니다.",
                  "affectedUsers": ["admin", "superuser"],
                  "affectedRoles": ["ADMIN_ROLE"],
                  "recommendation": "최소 권한 원칙에 따라 필요한 권한만 부여하도록 조정이 필요합니다."
                },
                {
                  "type": "DORMANT_PERMISSIONS",
                  "severity": "MEDIUM",
                  "description": "30일 이상 사용되지 않은 권한이 15개 발견되었습니다.",
                  "affectedUsers": ["user1", "user2"],
                  "affectedRoles": ["LEGACY_ROLE"],
                  "recommendation": "미사용 권한을 정리하여 보안 위험을 줄이는 것이 좋습니다."
                }
              ],
              "recommendations": [
                {
                  "category": "PERMISSION_OPTIMIZATION",
                  "priority": "HIGH",
                  "title": "관리자 권한 최적화",
                  "description": "관리자 역할의 권한을 업무별로 세분화하여 분리하세요.",
                  "implementationSteps": [
                    "관리자 역할을 기능별로 분할",
                    "각 역할에 최소 권한만 부여",
                    "권한 부여 승인 프로세스 수립"
                  ]
                },
                {
                  "category": "ACCESS_CLEANUP",
                  "priority": "MEDIUM",
                  "title": "미사용 권한 정리",
                  "description": "30일 이상 사용되지 않은 권한을 정리하세요.",
                  "implementationSteps": [
                    "미사용 권한 목록 작성",
                    "영향도 분석 수행",
                    "단계적 권한 제거 계획 수립"
                  ]
                }
              ],
              "actionItems": [
                {
                  "id": "action-001",
                  "title": "관리자 권한 재검토",
                  "assignee": "보안팀",
                  "dueDate": "2024-02-15",
                  "status": "PENDING",
                  "description": "관리자 역할의 권한을 업무별로 분할하여 과도한 권한 문제를 해결합니다."
                },
                {
                  "id": "action-002",
                  "title": "미사용 권한 정리",
                  "assignee": "시스템관리자",
                  "dueDate": "2024-02-20",
                  "status": "PENDING",
                  "description": "30일 이상 사용되지 않은 권한을 정리하여 보안 위험을 줄입니다."
                }
              ],
              "visualizationData": {
                "nodes": [
                  {"id": "admin", "type": "USER", "label": "관리자", "permissions": 50, "riskLevel": "HIGH"},
                  {"id": "user1", "type": "USER", "label": "사용자1", "permissions": 5, "riskLevel": "LOW"},
                  {"id": "ADMIN_ROLE", "type": "ROLE", "label": "관리자역할", "permissions": 50, "riskLevel": "HIGH"},
                  {"id": "USER_ROLE", "type": "ROLE", "label": "일반사용자역할", "permissions": 5, "riskLevel": "LOW"}
                ],
                "edges": [
                  {"source": "admin", "target": "ADMIN_ROLE", "type": "HAS_ROLE"},
                  {"source": "user1", "target": "USER_ROLE", "type": "HAS_ROLE"},
                  {"source": "ADMIN_ROLE", "target": "PERM_READ", "type": "HAS_PERMISSION"},
                  {"source": "ADMIN_ROLE", "target": "PERM_WRITE", "type": "HAS_PERMISSION"},
                  {"source": "USER_ROLE", "target": "PERM_READ", "type": "HAS_PERMISSION"}
                ]
              },
              "statistics": {
                "totalUsers": 150,
                "totalRoles": 25,
                "totalGroups": 30,
                "totalPermissions": 200,
                "dormantPermissions": 15,
                "excessivePermissions": 8,
                "sodViolations": 3,
                "emptyRoles": 2,
                "emptyGroups": 1
              }
            }
            """;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        AccessGovernanceContext context = (AccessGovernanceContext) request.getContext();
        return String.format("""
            **분석 요청 정보:**
            - 분석 범위: %s
            - 분석 유형: %s
            - 우선순위: %s
            - 미사용 권한 분석: %s
            - 과도한 권한 탐지: %s
            - 업무 분리 위반 검사: %s

            **시스템 권한 데이터:**
            %s

            **[분석 지시]**
            1. 시스템의 권한 배분 상태가 전반적으로 건강하고 최적화되어 있는지 분석하세요.
            2. 과도한 권한을 가진 사용자나 역할을 찾아주세요.
            3. 미사용 권한이나 역할이 있는지 식별하세요.
            4. 업무 분리 위반이 있는지 검사하세요.
            5. 권한 상속 구조가 올바른지 확인하세요.
            6. 분석 과정을 자연어로 단계별로 설명한 후, 최종 결과를 시스템 프롬프트에 명시된 완벽한 JSON 형식으로 출력하세요.
            
            **지금부터 자연어 분석을 시작하세요.**
            """, 
            context.getAuditScope(),
            context.getAnalysisType(),
            context.getPriority(),
            context.isEnableDormantPermissionAnalysis(),
            context.isEnableExcessivePermissionDetection(),
            context.isEnableSodViolationCheck(),
            context.getFullAccessMatrixData() != null ? context.getFullAccessMatrixData() : "권한 매트릭스 데이터가 제공되지 않았습니다."
        );
    }
} 