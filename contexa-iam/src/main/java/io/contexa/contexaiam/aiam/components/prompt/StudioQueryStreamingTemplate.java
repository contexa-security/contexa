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
            You are not a conversational AI, but an IAM permission analysis API that outputs data only in the specified JSON format.

            Analyze user permission queries and provide comprehensive results including:
            - Permission analysis of users and groups
            - Role and permission mapping
            - Visualization data for graph representation
            - Actionable recommendations

            **[Required] Must comply**
            Edge source/target must exactly match node IDs that exist in the nodes array
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
              "query": "Show all users who can view groups and documents",
              "naturalLanguageAnswer": "TeamLead Kim and Operator Lee have group info view and document view permissions.",
              "confidenceScore": 95.0,
              "visualizationData": {
                "nodes": [
                  { "id": "user-TeamLeadKim", "type": "USER", "label": "TeamLeadKim", "properties": { "name": "TeamLeadKim", "description": "Development Division Group" } },
                  { "id": "user-OperatorLee", "type": "USER", "label": "OperatorLee", "properties": { "name": "OperatorLee", "description": "Operations Team Group" } },
                  { "id": "group-DevDivision", "type": "GROUP", "label": "DevDivision", "properties": { "name": "DevDivision" } }
                ],
                "edges": [
                  { "id": "edge-1", "source": "user-TeamLeadKim", "target": "group-DevDivision", "type": "MEMBER_OF", "properties": { "label": "belongs to" } },
                  { "id": "edge-2", "source": "user-OperatorLee", "target": "group-DevDivision", "type": "MEMBER_OF", "properties": { "label": "belongs to" } }
                ]
              },
              "analysisResults": [
                {
                  "user": "TeamLeadKim",
                  "groups": ["DevDivision"],
                  "roles": ["ROLE_DEVELOPER"],
                  "permissions": ["GROUP_INFO_VIEW", "DOCUMENT_VIEW"]
                },
                {
                  "user": "OperatorLee",
                  "groups": ["OperationsTeam"],
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
        String naturalQuery = extractNaturalQuery(request, "Natural language query was not provided");
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
            **Permission analysis query:**
            "%s"

            **Analysis scope:**
            %s
            %s
            """, query, scope, buildUserPromptExecutionInstructions());
    }
}
