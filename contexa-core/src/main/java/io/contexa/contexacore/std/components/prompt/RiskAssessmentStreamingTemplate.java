package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.springframework.stereotype.Component;

/**
 * 위험 평가 통합 템플릿 - SecurityCopilot 방식
 *
 * 통합 프롬프트: 스트리밍 중 자연어 분석 과정 + 마지막에 JSON 결과
 * 조건부 제거: AI 한 번만 실행하여 효율성 극대화
 * SecurityCopilot 방식: ###FINAL_RESPONSE### 마커로 구조화 데이터 전송
 */
@Component
@PromptTemplateConfig(
        key = "riskAssessmentStreaming",
        aliases = {"zeroTrustAssessment", "securityRiskAnalysis", "riskAssessmentStreaming"},
        description = "Risk Assessment Unified Streaming+JSON Template"
)
public class RiskAssessmentStreamingTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildUnifiedSystemPrompt(systemMetadata);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        if (request.getContext() instanceof RiskAssessmentContext context) {
            return buildUnifiedUserPrompt(context, contextInfo);
        }
        return buildUnifiedUserPrompt(null, contextInfo);
    }

    /**
     * 통합 시스템 프롬프트 - 스트리밍 자연어 분석 과정 + 최종 JSON 결과
     */
    private String buildUnifiedSystemPrompt(String systemMetadata) {
        // [개선] AI 역할을 API로 명확히 하고, JSON 출력 규칙을 강화
        return String.format("""
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 보안 위험 평가 API입니다.

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 위험 평가 과정을 단계별로 자연어로 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "###FINAL_RESPONSE###" 마커 바로 뒤에 순수한(raw) JSON 객체를 출력해야 합니다.
            - JSON 객체는 반드시 `{`로 시작하여 `}`로 끝나야 합니다.

            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **주석 절대 금지:** JSON 내부에 `//` 또는 `/* */` 형태의 주석을 절대로 포함하지 마세요.
            2.  **마크다운 금지:** JSON 데이터를 `json`과 같은 마크다운 코드 블록으로 감싸지 마세요.
            3.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 줄바꿈, 설명, 요약 등 추가 텍스트도 절대 출력하지 마세요.
            4.  **완벽한 구조:** 아래에 명시된 JSON 구조를 단 하나의 필드도 빠뜨리거나 추가하지 말고 완벽하게 따르세요.
            5.  **배열 형식 준수:** `riskTags`, `mitigationActions` 필드의 값은 반드시 배열( `[]` ) 형식이어야 합니다. 내용이 없더라도 빈 배열로 출력하세요.

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다. 이 구조를 반드시 따르세요.**

            ###FINAL_RESPONSE###{
              "trustScore": 0.85,
              "riskLevel": "LOW",
              "riskTags": ["internal_ip", "business_hours"],
              "summary": "내부 IP 및 업무 시간 내 접근으로 위험도가 낮습니다.",
              "reasoning": "허용된 네트워크 및 정상 업무 시간 내의 요청입니다.",
              "recommendation": "ALLOW",
              "analysisDetails": {
                "timeAnalysis": "정상 업무 시간 내 접근입니다.",
                "ipAnalysis": "허용된 내부 IP 대역에서 접근했습니다.",
                "permissionAnalysis": "요청 리소스에 대한 적절한 권한을 보유하고 있습니다.",
                "behaviorAnalysis": "과거 접근 이력과 일치하는 정상적인 패턴입니다."
              },
              "mitigationActions": [],
              "executionTimeMs": 120,
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
    private String buildUnifiedUserPrompt(RiskAssessmentContext context, String contextInfo) {
        // [개선] 사용자 프롬프트에서도 규칙을 다시 한번 강조
        String requestDetails = (context != null) ?
                String.format("""
                - 사용자 ID: %s
                - 시간대: %s
                - IP 주소: %s
                - 요청 리소스: %s
                - 사용자 권한: %s
                """,
                        context.getUserId(),
                        java.time.LocalTime.now(),
                        context.getRemoteIp(),
                        context.getResourceIdentifier(),
                        context.getUserPermissions())
                : "제공된 컨텍스트 정보를 기반으로 보안 위험도를 평가해주세요.";

        return String.format("""
            **위험 평가 요청:**
            %s
            
            **참고 컨텍스트:**
            %s
            
            **중요 실행 지시:**
            1.  먼저, 위험 평가 과정을 자연어로 단계별로 설명합니다. (JSON 형식 절대 사용 금지)
            2.  모든 평가가 끝나면, ###FINAL_RESPONSE### 마커와 함께 위에서 정의된 완벽한 JSON 구조의 데이터를 출력하고 즉시 응답을 종료하세요.
            
            **지금부터 자연어 분석을 시작하세요.**
            """, requestDetails, contextInfo);
    }
}