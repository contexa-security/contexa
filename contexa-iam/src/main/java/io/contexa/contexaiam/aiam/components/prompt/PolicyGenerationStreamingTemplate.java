package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@PromptTemplateConfig(
        key = "policyGenerationStreaming",
        aliases = {"policy_generation_streaming", "generatePolicyFromTextStreaming", "generatePolicyFromText"},
        description = "정책 생성 통합 프롬프트 - 스트리밍+JSON 일원화"
)
public class PolicyGenerationStreamingTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        return buildUnifiedSystemPrompt(contextInfo);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        PolicyGenerationItem.AvailableItems availableItems = extractAvailableItems(request);
        String naturalQuery = extractNaturalQuery(request);

        return buildUnifiedUserPrompt(naturalQuery, availableItems, contextInfo);
    }

    
    private String buildUnifiedSystemPrompt(String contextInfo) {
        
        return String.format("""
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 IAM 정책 생성 API입니다.

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 정책 생성 과정을 단계별로 자연어로 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "###FINAL_RESPONSE###" 마커 바로 뒤에 순수한(raw) JSON 객체를 출력해야 합니다.
            - JSON 객체는 반드시 `{`로 시작하여 `}`로 끝나야 합니다.

            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **주석 절대 금지:** JSON 내부에 `//` 또는 `/* */` 형태의 주석을 절대로 포함하지 마세요.
            2.  **마크다운 금지:** JSON 데이터를 `json`과 같은 마크다운 코드 블록으로 감싸지 마세요.
            3.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 줄바꿈, 설명, 요약 등 추가 텍스트도 절대 출력하지 마세요.
            4.  **완벽한 구조:** 아래에 명시된 JSON 구조를 단 하나의 필드도 빠뜨리거나 추가하지 말고 완벽하게 따르세요.
            5.  **배열 형식 준수:** `roleIds`, `permissionIds`, `recommendedActions` 필드와 `conditions` 객체 내부의 값은 반드시 배열( `[]` ) 형식이어야 합니다. 내용이 없으면 빈 배열로 출력하세요.
            6.  **ID만 사용:** `roleIds`, `permissionIds`, `conditions`의 키(key)에는 반드시 '사용 가능한 항목들'에 명시된 ID만 사용하세요.

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다. 이 구조를 반드시 따르세요.**

            ###FINAL_RESPONSE###{
              "policyData": {
                "policyName": "요구사항에 맞는 실제 정책 이름",
                "description": "요구사항 기반 실제 정책 설명",
                "effect": "ALLOW",
                "roleIds": [101, 102],
                "permissionIds": [201, 202],
                "conditions": {
                  "301": ["true"],
                  "302": ["192.168.1.0/24"]
                },
                "aiRiskAssessmentEnabled": true,
                "requiredTrustScore": 0.8,
                "customConditionSpel": null
              },
              "roleIdToNameMap": {
                "101": "팀 관리자",
                "102": "문서 담당자"
              },
              "permissionIdToNameMap": {
                "201": "문서 조회",
                "202": "문서 편집"
              },
              "conditionIdToNameMap": {
                "301": "업무 시간 내",
                "302": "내부 네트워크"
              },
              "recommendedActions": [
                {
                  "priority": "MEDIUM",
                  "action": "생성된 정책에 대한 2차 검토를 권장합니다.",
                  "reason": "여러 역할과 조건이 조합되어 복잡성이 높습니다."
                }
              ],
              "policyScore": 92.5,
              "securityLevel": "강력함",
              "complianceCheck": {
                "gdprCompliant": true,
                "iso27001Compliant": true,
                "zeroTrustCompliant": true
              },
              "generatedAt": "2023-10-27T10:00:00Z",
              "version": "1.0.0"
            }
            
            **컨텍스트 정보:**
            %s
            """, contextInfo);
    }

    
    private String buildUnifiedUserPrompt(String naturalQuery, PolicyGenerationItem.AvailableItems availableItems, String contextInfo) {
        
        return String.format("""
            **자연어 요구사항:**
            "%s"
            
            **사용 가능한 항목들 (이 목록에 있는 ID와 이름만 사용하세요):**
            %s
            
            **중요 실행 지시:**
            1.  먼저, 정책 생성 과정을 자연어로 단계별로 설명합니다. (JSON 형식 절대 사용 금지)
            2.  모든 생성이 끝나면, ###FINAL_RESPONSE### 마커와 함께 위에서 정의된 완벽한 JSON 구조의 데이터를 출력하고 즉시 응답을 종료하세요.
            
            **지금부터 자연어 분석을 시작하세요.**
            """, naturalQuery, formatAvailableItems(availableItems));
    }

    private String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        String naturalQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalQuery != null) {
            return naturalQuery;
        }
        return request.getContext() != null ? request.getContext().toString() : "자연어 요구사항이 제공되지 않았습니다";
    }

    private PolicyGenerationItem.AvailableItems extractAvailableItems(AIRequest<? extends DomainContext> request) {
        return request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);
    }

    private String formatAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        if (availableItems == null) {
            return "사용 가능한 항목 정보가 제공되지 않았습니다.";
        }
        StringBuilder info = new StringBuilder();
        if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
            info.append("**역할 목록:**\n");
            availableItems.roles().forEach(role ->
                    info.append(String.format("- %s (ID: %d)\n", role.name(), role.id())));
        }
        if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
            info.append("\n**권한 목록:**\n");
            availableItems.permissions().forEach(permission ->
                    info.append(String.format("- %s (ID: %d)\n", permission.name(), permission.id())));
        }
        if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
            info.append("\n**조건 목록:**\n");
            availableItems.conditions().forEach(condition ->
                    info.append(String.format("- %s (ID: %d)\n", condition.name(), condition.id())));
        }
        return info.length() > 0 ? info.toString() : "사용 가능한 항목이 없습니다.";
    }
}