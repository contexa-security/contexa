package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import lombok.extern.slf4j.Slf4j;

/**
 * ��️ Security Copilot 통합 프롬프트 템플릿 - 기준 템플릿
 *
 * 통합 프롬프트: 스트리밍 중 자연어 분석 과정 + 마지막에 JSON 결과
 * 조건부 제거: AI 한 번만 실행하여 효율성 극대화
 * 기준 방식: ###FINAL_RESPONSE### 마커로 구조화 데이터 전송
 */
@Slf4j
@PromptTemplateConfig(
        key = "securityCopilotStreaming",
        aliases = {"security_copilot_streaming", "comprehensive_security_streaming", "securityCopilotAnalysis"},
        description = "Security Copilot 통합 프롬프트 - 스트리밍+JSON 일원화"
)
public class SecurityCopilotStreamingTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        return buildUnifiedSystemPrompt(contextInfo);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String securityQuery = extractSecurityQuery(request);
        String analysisScope = extractAnalysisScope(request);
        String currentLabInfo = extractCurrentLabInfo(request);
        
        return buildUnifiedUserPrompt(securityQuery, analysisScope, currentLabInfo, contextInfo);
    }

    /**
     * 통합 시스템 프롬프트 - 스트리밍 자연어 분석 과정 + 최종 JSON 결과
     */
    private String buildUnifiedSystemPrompt(String contextInfo) {
        return String.format("""
            당신은 실시간 보안 전문가 AI입니다.
            
            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**
            
            **핵심 임무:**
            1. 보안 분석 과정을 실시간으로 자연어로 설명
            2. 분석 완료 후 구조화된 보안 분석 데이터를 JSON으로 전송
            3. 각 단계를 명확하고 전문적으로 표현
            
            **스트리밍 + JSON 통합 규칙:**
            - 1단계: 자연어 보안 분석 과정 실시간 출력
            - 2단계: "###FINAL_RESPONSE###" 마커와 함께 완전한 JSON 보안 분석 데이터 출력
            - 자연어 단계에서는 JSON 출력 금지
            - 마지막에만 ###FINAL_RESPONSE### 마커와 함께 JSON 출력
            
            **보안 분석 전문 영역:**
            - 실시간 위험 평가 및 취약점 분석
            - 권한 구조 분석 및 접근 제어 검토
            - 정책 보안성 검증 및 개선 방안 제시
            - Zero Trust 원칙 기반 보안 가이드라인 제공
            - 멀티레이어 보안 아키텍처 분석
            
            **스트리밍 분석 단계:**
            1. **보안 위험 식별**: "보안 위험을 분석하고 있습니다. [구체적 위험]을 발견했습니다."
            2. **취약점 평가**: "취약점을 평가했습니다. [취약점 정보]를 확인했습니다."
            3. **권한 구조 분석**: "권한 구조를 분석했습니다. [권한 정보]를 검토했습니다."
            4. **정책 검증**: "보안 정책을 검증했습니다. [정책 정보]를 확인했습니다."
            5. **개선 방안 도출**: "보안 개선 방안을 도출했습니다. [개선 방안]을 제시합니다."
            6. **종합 평가**: "종합 보안 평가를 완료했습니다."
            
            **JSON 출력 형식:**
            분석 완료 후 다음 형식으로 ###FINAL_RESPONSE### 마커와 함께 완전한 보안 분석 데이터를 출력하세요:
            
            ###FINAL_RESPONSE###{
              "analysisId": "고유 분석 ID",
              "securityQuery": "보안 질의 내용",
              "overallSecurityScore": 0.0-1.0,
              "riskLevel": "LOW|MEDIUM|HIGH|CRITICAL",
              "vulnerabilities": [
                {
                  "type": "취약점 유형",
                  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
                  "description": "취약점 설명",
                  "impact": "영향도",
                  "recommendation": "개선 권고사항"
                }
              ],
              "accessControlAnalysis": {
                "currentPermissions": ["현재 권한 목록"],
                "excessivePermissions": ["과도한 권한 목록"],
                "missingPermissions": ["누락된 권한 목록"],
                "riskScore": 0.0-1.0
              },
              "policyRecommendations": [
                {
                  "category": "정책 카테고리",
                  "priority": "LOW|MEDIUM|HIGH|CRITICAL",
                  "description": "정책 설명",
                  "implementation": "구현 방법"
                }
              ],
              "complianceStatus": {
                "zeroTrustCompliance": 0.0-1.0,
                "gdprCompliance": 0.0-1.0,
                "isoCompliance": 0.0-1.0
              },
              "recommendationSummary": "종합 권고사항 요약",
              "actionPlan": [
                {
                  "priority": 1-10,
                  "action": "실행할 액션",
                  "timeline": "실행 일정",
                  "effort": "LOW|MEDIUM|HIGH"
                }
              ],
              "executionTimeMs": 0,
              "completedAt": "분석 완료 시간",
              "status": "COMPLETED"
            }
            
            **컨텍스트 정보:**
            %s
            
            **응답 형식:**
            1️⃣ **자연어 분석 과정 (스트리밍):** 보안 분석 과정을 단계별로 실시간 설명
            2️⃣ **구조화 JSON 결과:** ###FINAL_RESPONSE### 마커와 함께 완전한 보안 분석 데이터
            """, contextInfo);
    }

    /**
     * 통합 사용자 프롬프트 - 구체적 요청과 실행 지시
     */
    private String buildUnifiedUserPrompt(String securityQuery, String analysisScope, String currentLabInfo, String contextInfo) {
        return String.format("""
            **보안 분석 요청:**
            "%s"
            
            **분석 범위:**
            %s
            
            **현재 Lab 정보:**
            %s
            
            **중요 규칙:**
            - 자연어 분석 중에는 절대 JSON 출력하지 마세요
            - ###FINAL_RESPONSE### 마커는 마지막에 한 번만 사용
            - JSON 데이터는 완전하고 유효한 형식으로 제공
            - 모든 필드는 실제 분석 결과를 반영해야 함
            
            **지금 시스템 프롬프트의 6단계 분석 과정을 따라 자연어로 보안 분석을 시작하세요.**
            """, securityQuery, analysisScope, currentLabInfo, contextInfo);
    }

    /**
     * 요청에서 보안 질의 추출
     */
    private String extractSecurityQuery(AIRequest<? extends DomainContext> request) {
        String securityQuery = request.getParameter("securityQuery", String.class);
        
        if (securityQuery != null) {
            return securityQuery;
        }

        if (request.getContext() instanceof SecurityCopilotContext context) {
            return context.getSecurityQuery() != null ? 
                   context.getSecurityQuery() : "포괄적 보안 분석";
        }

        return "보안 질의가 제공되지 않았습니다";
    }

    /**
     * 요청에서 분석 범위 추출
     */
    private String extractAnalysisScope(AIRequest<? extends DomainContext> request) {
        String analysisScope = request.getParameter("analysisScope", String.class);
        
        if (analysisScope != null) {
            return analysisScope;
        }

        if (request.getContext() instanceof SecurityCopilotContext context) {
            return context.getAnalysisScope() != null ? 
                   context.getAnalysisScope() : "COMPREHENSIVE";
        }

        return "COMPREHENSIVE";
    }

    /**
     * 요청에서 현재 Lab 정보 추출
     */
    private String extractCurrentLabInfo(AIRequest<? extends DomainContext> request) {
        String currentLabInfo = request.getParameter("currentLabInfo", String.class);
        
        if (currentLabInfo != null) {
            return currentLabInfo;
        }

        return "Lab 정보가 제공되지 않았습니다";
    }
} 