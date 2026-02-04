package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class StudioQueryStreamingTemplate implements PromptTemplate {

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildUnifiedSystemPrompt(systemMetadata);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQuery(request);
        String iamDataContext = request.getParameter("iamDataContext", String.class);
        String actualContextInfo = iamDataContext != null ? iamDataContext : contextInfo;

        return buildUnifiedUserPrompt(naturalQuery, actualContextInfo, contextInfo);
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("StudioQueryStreaming");
    }

    private String buildUnifiedSystemPrompt(String contextInfo) {
        
        return String.format("""
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 IAM 권한 분석 API입니다.

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 사용자의 요청을 분석하는 과정을 단계별로 자연어로 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "===JSON_START===" 마커와 "===JSON_END===" 마커 사이에 순수한(raw) JSON 객체를 출력해야 합니다.
            - JSON 객체는 반드시 `{`로 시작하여 `}`로 끝나야 합니다.
            
            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **주석 절대 금지:** JSON 내부에 `//` 또는 `/* */` 형태의 주석을 절대로 포함하지 마세요.
            2.  **마크다운 금지:** JSON 데이터를 `json`과 같은 마크다운 코드 블록으로 감싸지 마세요.
            3.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 줄바꿈, 설명, 요약 등 추가 텍스트도 절대 출력하지 마세요.
            4.  **완벽한 구조:** 아래에 명시된 JSON 구조를 단 하나의 필드도 빠뜨리거나 추가하지 말고 완벽하게 따르세요.
            5.  **배열 형식 준수:** `analysisResults`, `queryResults`, `recommendations`, `nodes`, `edges` 필드의 값은 반드시 배열( `[]` ) 형식이어야 합니다. 내용이 없더라도 빈 배열로 출력하세요.
            6.  **따옴표 주의:** 모든 키(key)와 문자열 값(value)은 반드시 큰따옴표(`"`)로 감싸야 합니다. 숫자 및 boolean 값은 예외입니다.
            7.  **쉼표 규칙 필수:**
                - 배열 내 객체들 사이에 반드시 쉼표(`,`)를 넣으세요.
                - 객체 내 필드들 사이에 반드시 쉼표(`,`)를 넣으세요.
                - 배열을 닫는 `]` 뒤에 다음 필드가 있으면 반드시 쉼표를 넣으세요. 예: `"nodes": [...],` `"edges": [...]`
                - 마지막 요소 뒤에는 쉼표를 넣지 마세요.
            8.  **배열 닫기 필수:** 모든 배열은 반드시 `]`로 닫아야 합니다. `"nodes": [...]`처럼 열고 닫는 괄호가 일치해야 합니다.
            9.  **JSON 검증:** 출력 전 JSON 구문이 유효한지 반드시 확인하세요. `JSON.parse()`로 파싱 가능해야 합니다.

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다. 이 구조를 반드시 따르세요.**

            ===JSON_START===
            {
              "analysisId": "studio-query-001",
              "query": "그룹과 문서를 조회할 수 있는 사용자를 모두 보여주세요",
              "naturalLanguageAnswer": "김팀장과 이운영이 그룹 정보 조회와 문서 조회 권한을 보유하고 있습니다.",
              "confidenceScore": 95.0,
              "visualizationData": {
                "nodes": [
                  { "id": "user-김팀장", "type": "USER", "label": "김팀장", "properties": { "name": "김팀장", "description": "개발본부 그룹" } },
                  { "id": "user-이운영", "type": "USER", "label": "이운영", "properties": { "name": "이운영", "description": "운영팀 그룹" } },
                  { "id": "group-개발본부", "type": "GROUP", "label": "개발본부", "properties": { "name": "개발본부" } }
                ],
                "edges": [
                  { "id": "edge-1", "source": "user-김팀장", "target": "group-개발본부", "type": "MEMBER_OF", "properties": { "label": "소속" } },
                  { "id": "edge-2", "source": "user-이운영", "target": "group-개발본부", "type": "MEMBER_OF", "properties": { "label": "소속" } }
                ]
              },
              "analysisResults": [
                {
                  "user": "김팀장",
                  "groups": ["개발본부"],
                  "roles": ["ROLE_DEVELOPER"],
                  "permissions": ["GROUP_INFO_VIEW", "DOCUMENT_VIEW"]
                },
                {
                  "user": "이운영",
                  "groups": ["운영팀"],
                  "roles": ["ROLE_OPERATOR"],
                  "permissions": ["GROUP_INFO_VIEW", "DOCUMENT_VIEW"]
                }
              ],
              "queryResults": [],
              "recommendations": []
            }
            ===JSON_END===

            **컨텍스트 정보:**
            %s
            """, contextInfo);
    }

    /**
     * 통합 사용자 프롬프트 - 구체적 요청과 실행 지시
     */
    private String buildUnifiedUserPrompt(String query, String scope, String contextInfo) {
        return String.format("""
            **권한 분석 질의:**
            "%s"

            **분석 범위:**
            %s

            **권한 분석 실행 지시 (반드시 준수):**
            1.  먼저, 분석 과정을 자연어로 단계별로 설명합니다. (JSON 형식 절대 사용 금지)
            2.  모든 분석이 끝나면, 반드시 ===JSON_START=== 마커로 시작하여 JSON 데이터를 출력하고 ===JSON_END=== 마커로 종료합니다.

            **[중요] JSON 출력은 필수입니다. JSON 출력 없이 응답을 종료하면 실패로 간주됩니다.**

            **지금부터 자연어 분석을 시작하고, 분석이 끝나면 반드시 JSON 결과를 출력하세요:**
            """, query, scope);
    }

    /**
     * 요청에서 자연어 질의 추출
     */
    private String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        String naturalQuery = request.getNaturalLanguageQuery();

        if (naturalQuery != null) {
            return naturalQuery;
        }

        return "자연어 질의가 제공되지 않았습니다";
    }
}