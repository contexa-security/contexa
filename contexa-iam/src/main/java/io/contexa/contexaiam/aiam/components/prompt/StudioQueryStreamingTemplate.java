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

            **[필수] 노드/엣지 ID 생성 규칙 (반드시 준수)**
            1. 모든 노드 ID는 반드시 영문 소문자와 숫자, 하이픈(-)만 사용
               - 올바른 예: user-1, user-kim, group-dev-team, permission-view
               - 잘못된 예: user-김팀장, group-개발팀, permission-조회
            2. 한국어 이름이 있는 경우 영문 변환 규칙:
               - 사람 이름: 성을 영문으로 변환 (김 → kim, 이 → lee, 박 → park)
               - 그룹명: 의미를 영문으로 변환 (개발팀 → dev-team, 운영팀 → ops-team)
               - 권한명: 영문 코드 사용 (조회 → view, 수정 → edit, 삭제 → delete)
            3. 엣지의 source/target은 반드시 nodes 배열에 존재하는 노드 ID와 정확히 일치해야 함
            4. label 필드에만 한국어 표시명을 사용
            """;
    }

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
                  { "id": "user-kim", "type": "USER", "label": "김팀장", "properties": { "name": "김팀장", "description": "개발본부 그룹" } },
                  { "id": "user-lee", "type": "USER", "label": "이운영", "properties": { "name": "이운영", "description": "운영팀 그룹" } },
                  { "id": "group-dev", "type": "GROUP", "label": "개발본부", "properties": { "name": "개발본부" } }
                ],
                "edges": [
                  { "id": "edge-1", "source": "user-kim", "target": "group-dev", "type": "MEMBER_OF", "properties": { "label": "소속" } },
                  { "id": "edge-2", "source": "user-lee", "target": "group-dev", "type": "MEMBER_OF", "properties": { "label": "소속" } }
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
        String naturalQuery = extractNaturalQuery(request);
        String iamDataContext = request.getParameter("iamDataContext", String.class);
        String actualContextInfo = iamDataContext != null ? iamDataContext : contextInfo;

        return buildUserPrompt(naturalQuery, actualContextInfo, contextInfo);
    }

    /**
     * Builds the user prompt with query details and execution instructions.
     *
     * @param query the natural language query
     * @param scope the analysis scope (IAM data context)
     * @param contextInfo additional context information
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String query, String scope, String contextInfo) {
        return String.format("""
            **Permission Analysis Query:**
            "%s"

            **Analysis Scope:**
            %s
            %s
            """, query, scope, buildUserPromptExecutionInstructions());
    }

    /**
     * Extracts the natural language query from the request.
     *
     * @param request the AI request
     * @return the natural language query or a default message
     */
    private String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        String naturalQuery = request.getNaturalLanguageQuery();

        if (naturalQuery != null) {
            return naturalQuery;
        }

        return "Natural language query was not provided";
    }
}
