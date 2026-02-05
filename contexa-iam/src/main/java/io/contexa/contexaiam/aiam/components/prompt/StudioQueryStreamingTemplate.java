package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractStreamingPromptTemplate;
import lombok.extern.slf4j.Slf4j;

/**
 * Streaming template for IAM Studio query analysis.
 * <p>
 * This template generates prompts for analyzing IAM permission queries
 * with real-time streaming feedback and structured JSON output.
 * </p>
 */
@Slf4j
public class StudioQueryStreamingTemplate extends AbstractStreamingPromptTemplate {

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 IAM 권한 분석 API입니다.

            사용자 권한 질의를 분석하여 다음을 포함한 종합 결과를 제공합니다:
            - 사용자 및 그룹의 권한 분석
            - 역할 및 권한 매핑
            - 그래프 표현을 위한 시각화 데이터
            - 실행 가능한 권장 사항

            **[필수] 반드시 준수**
            엣지의 source/target은 반드시 nodes 배열에 존재하는 노드 ID와 정확히 일치해야 함
            """;
    }

    /**
     * Returns the manual JSON schema example for LLM guidance.
     * This schema provides detailed field descriptions and rules that LLM must follow.
     *
     * @return JSON schema example with field descriptions
     */
    @Override
    protected String getJsonSchemaExample() {
        return """
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
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("StudioQueryStreaming");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQuery(request, "자연어 질의가 제공되지 않았습니다");
        String actualContextInfo = extractContextInfo(request, contextInfo);

        return buildUserPrompt(naturalQuery, actualContextInfo);
    }

    /**
     * Builds the user prompt with query details and execution instructions.
     *
     * @param query the natural language query
     * @param scope the analysis scope (IAM data context)
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String query, String scope) {
        return String.format("""
            **권한 분석 질의:**
            "%s"

            **분석 범위:**
            %s
            %s
            """, query, scope, buildUserPromptExecutionInstructions());
    }
}
