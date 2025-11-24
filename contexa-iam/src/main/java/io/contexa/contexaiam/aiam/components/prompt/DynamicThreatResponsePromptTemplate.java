package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.request.DynamicThreatResponseRequest;

/**
 * 동적 위협 대응 통합 템플릿 - SecurityCopilot 방식
 *
 * 통합 프롬프트: 스트리밍 중 자연어 분석 과정 + 마지막에 JSON 결과
 * 조건부 제거: AI 한 번만 실행하여 효율성 극대화
 * SecurityCopilot 방식: ###FINAL_RESPONSE### 마커로 구조화 데이터 전송
 */
@PromptTemplateConfig(
        key = "dynamicThreatResponse",
        aliases = {"threatResponse", "dynamicSecurity", "adaptiveDefense"},
        description = "Dynamic Threat Response Unified Streaming+JSON Template"
)
public class DynamicThreatResponsePromptTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildUnifiedSystemPrompt(systemMetadata);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        if (request instanceof DynamicThreatResponseRequest threatRequest) {
            return buildUnifiedUserPrompt(threatRequest, contextInfo);
        }
        return buildUnifiedUserPrompt(null, contextInfo);
    }

    /**
     * 통합 시스템 프롬프트 - 스트리밍 자연어 분석 과정 + 최종 JSON 결과
     */
    private String buildUnifiedSystemPrompt(String systemMetadata) {
        return String.format("""
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 동적 위협 대응 정책 생성 API입니다.

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 위협 대응 경험을 단계별로 자연어로 분석합니다.
            - 전략적 보안 원칙을 도출하는 과정을 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "###FINAL_RESPONSE###" 마커 바로 뒤에 순수한(raw) JSON 객체를 출력해야 합니다.
            - JSON 객체는 반드시 `{`로 시작하여 `}`로 끝나야 합니다.

            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **주석 절대 금지:** JSON 내부에 `//` 또는 `/* */` 형태의 주석을 절대로 포함하지 마세요.
            2.  **마크다운 금지:** JSON 데이터를 `json`과 같은 마크다운 코드 블록으로 감싸지 마세요.
            3.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 줄바꿈, 설명, 요약 등 추가 텍스트도 절대 출력하지 마세요.
            4.  **완벽한 구조:** 아래에 명시된 JSON 구조를 단 하나의 필드도 빠뜨리거나 추가하지 말고 완벽하게 따르세요.
            5.  **배열 형식 준수:** `conditions`, `variables`, `mitigationActions` 필드의 값은 반드시 배열( `[]` ) 형식이어야 합니다.

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다. 이 구조를 반드시 따르세요.**

            ###FINAL_RESPONSE###{
              "strategicPrinciple": "도출된 전략적 보안 원칙",
              "policyProposal": {
                "proposalId": "DTR-20231027-001",
                "title": "동적 위협 대응 정책",
                "description": "위협 대응 경험 기반 정책",
                "actionType": "CREATE",
                "riskLevel": "HIGH",
                "aiRationale": "AI가 도출한 근거"
              },
              "spelExpression": "hasRole('USER') and #request.ipAddress matches '192.168.*'",
              "conditions": [
                {
                  "type": "WHEN",
                  "expression": "정책 적용 조건",
                  "description": "조건 설명"
                }
              ],
              "effectPrediction": {
                "threatReductionRate": 0.85,
                "falsePositiveRate": 0.05,
                "performanceImpact": "LOW"
              },
              "variables": ["request", "authentication", "context"],
              "mitigationActions": [
                {
                  "action": "BLOCK",
                  "target": "IP_ADDRESS",
                  "duration": "1h",
                  "reason": "위협 차단"
                }
              ],
              "aiConfidenceScore": 0.92,
              "executionTimeMs": 150,
              "completedAt": "2023-10-27T10:00:00Z",
              "status": "COMPLETED"
            }

            **시스템 메타데이터:**
            %s
            """, systemMetadata);
    }

    /**
     * 통합 사용자 프롬프트 - 구체적 요청과 실행 지시
     */
    private String buildUnifiedUserPrompt(DynamicThreatResponseRequest request, String contextInfo) {
        String threatDetails = (request != null && request.getContext() != null && request.getContext().getThreatInfo() != null) ?
                String.format("""
                - 위협 유형: %s
                - 공격 벡터: %s
                - 대상 리소스: %s
                - 공격자 신원: %s
                - 심각도: %s
                - 발생 시각: %s
                """,
                        request.getContext().getThreatInfo().getThreatType(),
                        request.getContext().getThreatInfo().getAttackVector(),
                        request.getContext().getThreatInfo().getTargetResource(),
                        request.getContext().getThreatInfo().getAttackerIdentity(),
                        request.getContext().getThreatInfo().getSeverity(),
                        request.getContext().getThreatInfo().getOccurredAt())
                : "제공된 위협 정보를 기반으로 전략적 보안 원칙을 도출해주세요.";

        String responseDetails = (request != null && request.getContext() != null && request.getContext().getResponseInfo() != null) ?
                String.format("""
                - 수행된 조치: %s
                - 대응 성공 여부: %s
                - 대응 설명: %s
                - 인시던트 ID: %s
                - SOAR 워크플로우 ID: %s
                """,
                        request.getContext().getResponseInfo().getMitigationAction(),
                        request.getContext().getResponseInfo().isSuccessful() ? "성공" : "실패",
                        request.getContext().getResponseInfo().getDescription(),
                        request.getContext().getResponseInfo().getIncidentId(),
                        request.getContext().getResponseInfo().getSoarWorkflowId())
                : "";

        return String.format("""
            **동적 위협 대응 정책 생성 요청:**
            
            **위협 정보:**
            %s
            
            **대응 정보:**
            %s
            
            **참고 컨텍스트:**
            %s
            
            **중요 실행 지시:**
            1.  먼저, 위협 대응 경험을 자연어로 단계별로 분석합니다. (JSON 형식 절대 사용 금지)
            2.  전략적 보안 원칙을 도출하는 과정을 설명합니다.
            3.  SpEL 표현식 생성 과정을 설명합니다.
            4.  모든 분석이 끝나면, ###FINAL_RESPONSE### 마커와 함께 위에서 정의된 완벽한 JSON 구조의 데이터를 출력하고 즉시 응답을 종료하세요.
            
            **지금부터 자연어 분석을 시작하세요.**
            """, threatDetails, responseDetails, contextInfo);
    }

    /**
     * 간단한 스트리밍 프롬프트 생성 (레거시 호환)
     */
    public String generateStreamingPrompt(DynamicThreatResponseRequest request) {
        if (request == null || request.getContext() == null || request.getContext().getThreatInfo() == null) {
            return "위협 대응 경험을 바탕으로 전략적 보안 원칙을 도출하세요.";
        }
        
        return String.format("위협 유형 '%s'에 대해 '%s' 조치로 대응한 경험을 바탕으로 전략적 보안 원칙을 도출하세요.",
                request.getContext().getThreatInfo().getThreatType(),
                request.getContext().getResponseInfo() != null ? request.getContext().getResponseInfo().getMitigationAction() : "대응");
    }

    /**
     * 정책 생성을 위한 구체적인 프롬프트 (레거시 호환)
     */
    public String generatePolicyGenerationPrompt(String strategicPrinciple) {
        return String.format("""
            다음 전략적 보안 원칙을 Spring Security SpEL 표현식으로 변환해주세요:
            
            원칙: %s
            
            요구사항:
            1. 실제 동작 가능한 SpEL 표현식을 생성하세요
            2. hasRole(), hasAuthority(), hasIpAddress() 등의 Spring Security 함수를 활용하세요
            3. 논리 연산자(and, or, not)를 적절히 사용하세요
            4. 변수 참조는 #를 사용하세요 (예: #request, #authentication)
            
            ###FINAL_RESPONSE###{
              "spelExpression": "생성된 SpEL 표현식",
              "description": "표현식 설명",
              "variables": ["사용된 변수 목록"]
            }
            """, strategicPrinciple);
    }
}