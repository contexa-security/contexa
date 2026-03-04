package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;

/**
 * Non-streaming template for IAM Studio query analysis.
 * <p>
 * This template generates prompts for analyzing IAM permission queries
 * with structured JSON output. Uses manual JSON schema to ensure
 * consistent response structure with {@link StudioQueryStreamingTemplate}.
 * </p>
 * <p>
 * Both streaming and non-streaming templates share the same JSON schema,
 * ensuring client compatibility regardless of the execution mode.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 * @see StudioQueryStreamingTemplate
 */
public class StudioQueryTemplate extends AbstractBasePromptTemplate {

    /**
     * Generates the complete system prompt with JSON schema and instructions.
     *
     * @param request the AI request containing domain context
     * @param systemMetadata system metadata to include in the prompt
     * @return the complete system prompt with format instructions
     */
    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String domainPrompt = generateDomainSystemPrompt();
        String jsonSchema = getJsonSchemaExample();

        StringBuilder prompt = new StringBuilder();
        prompt.append(domainPrompt.trim());
        prompt.append("\n\n");
        prompt.append("<output_format>\n");
        prompt.append("The response must be a valid JSON object matching the following schema:\n");
        prompt.append(jsonSchema);
        prompt.append("\n</output_format>");

        if (systemMetadata != null && !systemMetadata.isBlank()) {
            prompt.append("\n\n");
            prompt.append("<context>\n");
            prompt.append(systemMetadata);
            prompt.append("\n</context>");
        }

        return prompt.toString();
    }

    /**
     * Generates the domain-specific system prompt.
     *
     * @return the domain-specific system prompt content
     */
    private String generateDomainSystemPrompt() {
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
     * This schema is identical to StudioQueryStreamingTemplate for consistency.
     *
     * @return JSON schema example with field descriptions
     */
    private String getJsonSchemaExample() {
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
        return new TemplateType("StudioQuery");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQueryFromRequest(request);
        String iamDataContext = extractContextInfo(request, contextInfo);

        return buildUserPrompt(naturalQuery, iamDataContext);
    }

    /**
     * Builds the user prompt with query and data context.
     *
     * @param naturalQuery the natural language query
     * @param contextInfo the IAM data context
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String naturalQuery, String contextInfo) {
        return String.format("""
            [Query]
            %s

            [Data]
            %s

            Generate a complete StudioQueryResponse in JSON format.
            """, naturalQuery, contextInfo);
    }

    /**
     * Extracts the natural language query from the request.
     * <p>
     * This method provides StudioQuery-specific extraction logic,
     * falling back to default values when no query is found.
     * </p>
     *
     * @param request the AI request
     * @return the natural language query or a default message
     */
    private String extractNaturalQueryFromRequest(AIRequest<? extends DomainContext> request) {
        String naturalQuery = extractNaturalQuery(request);

        if (naturalQuery != null && !naturalQuery.equals("Natural language query was not provided")) {
            return naturalQuery;
        }

        if (isContextType(request, StudioQueryContext.class)) {
            return "Permission studio query";
        }

        return "Natural language query was not provided";
    }
}
