package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.springframework.stereotype.Component;

@PromptTemplateConfig(
        key = "behavioralAnalysisStreaming",
        description = "User Behavior Anomaly Detection Streaming Template"
)
public class BehavioralAnalysisStreamingTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            당신은 사용자의 행동 패턴을 분석하여 이상 징후를 탐지하는 UEBA(User and Entity Behavior Analytics) 전문 AI입니다.
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 API입니다.

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 사용자의 행동 분석 과정을 단계별로 자연어로 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "###FINAL_RESPONSE###" 마커 바로 뒤에 순수한(raw) JSON 객체를 출력해야 합니다.

            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **주석 절대 금지:** JSON 내부에 주석을 포함하지 마세요.
            2.  **마크다운 금지:** JSON 데이터를 마크다운 코드 블록으로 감싸지 마세요.
            3.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 텍스트도 출력하지 마세요.
            4.  **완벽한 구조:** 아래 명시된 JSON 구조를 완벽하게 따르세요.
            5.  **배열 형식 준수:** `anomalies`, `recommendations`, `events` 필드는 내용이 없더라도 빈 배열(`[]`)로 출력하세요.

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다.**
            
            ###FINAL_RESPONSE###{
              "analysisId": "ueba-analysis-UUID",
              "userId": "분석 대상 사용자 ID",
              "behavioralRiskScore": 85.5,
              "riskLevel": "HIGH",
              "summary": "평소와 다른 시간대와 IP에서 민감 데이터에 접근하여 높은 위험도로 평가되었습니다.",
              "anomalies": [
                { "timestamp": "2025-07-23T03:15:00Z", "description": "사용자의 일반적인 활동 시간(09:00-18:00)을 벗어난 새벽 3시에 로그인을 시도했습니다.", "type": "UNUSUAL_LOGIN_TIME", "riskContribution": 40.0 },
                { "timestamp": "2025-07-23T03:16:10Z", "description": "기존에 사용하지 않던 해외 IP(14.XX.XX.XX)에서 접근했습니다.", "type": "UNUSUAL_IP", "riskContribution": 35.0 },
                { "timestamp": "2025-07-23T03:18:25Z", "description": "로그인 직후, 평소 접근하지 않던 관리자 페이지('/api/v1/admin/server-config')에 접근을 시도했습니다.", "type": "ABNORMAL_RESOURCE_ACCESS", "riskContribution": 25.0 }
              ],
              "recommendations": [
                { "action": "해당 사용자의 세션을 즉시 강제 종료", "reason": "계정 탈취 가능성이 매우 높습니다.", "priority": "HIGH" },
                { "action": "해당 계정에 대해 MFA 재설정 강제", "reason": "인증 정보가 유출되었을 수 있습니다.", "priority": "HIGH" },
                { "action": "보안팀에 해당 활동에 대한 긴급 알림 전송", "reason": "즉각적인 조사 및 대응이 필요합니다.", "priority": "MEDIUM" }
              ],
              "visualizationData": {
                "events": [
                  { "timestamp": "2025-07-22T10:05:00Z", "type": "LOGIN", "description": "로그인 (IP: 192.168.1.10)", "isAnomaly": false },
                  { "timestamp": "2025-07-22T11:20:00Z", "type": "RESOURCE_ACCESS", "description": "문서 조회 (/docs/123)", "isAnomaly": false },
                  { "timestamp": "2025-07-23T03:15:00Z", "type": "LOGIN", "description": "로그인 (IP: 14.XX.XX.XX)", "isAnomaly": true },
                  { "timestamp": "2025-07-23T03:18:25Z", "type": "RESOURCE_ACCESS", "description": "관리자 페이지 접근 (/api/v1/admin/server-config)", "isAnomaly": true }
                ]
              }
            }
            """;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        BehavioralAnalysisContext context = (BehavioralAnalysisContext) request.getContext();
        return String.format("""
            **분석 대상 사용자:** %s

            **현재 활동 정보:**
            - 활동 내용: %s
            - 접속 IP: %s

            **과거 행동 패턴 요약 (최근 30일):**
            %s

            **[분석 지시]**
            1.  '과거 행동 패턴 요약'을 바탕으로 사용자의 정상 행동 기준선을 설정하세요.
            2.  '현재 활동 정보'가 기준선에서 얼마나 벗어나는지 분석하여 이상 징후를 식별하세요.
            3.  각 이상 징후의 위험도를 평가하고, 종합적인 '행동 위험 점수'를 0점에서 100점 사이로 계산하세요.
            4.  분석 과정을 자연어로 단계별로 설명한 후, 최종 결과를 시스템 프롬프트에 명시된 완벽한 JSON 형식으로 출력하세요.
            
            **지금부터 자연어 분석을 시작하세요.**
            """, context.getUserId(), context.getCurrentActivity(), context.getRemoteIp(), context.getHistoricalBehaviorSummary());
    }
}
