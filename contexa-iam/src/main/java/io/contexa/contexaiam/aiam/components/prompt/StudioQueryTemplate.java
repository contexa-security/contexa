package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractStandardPromptTemplate;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;

/**
 * Non-streaming template for IAM Studio query analysis.
 * <p>
 * This template generates prompts for analyzing IAM permission queries
 * with structured JSON output. Extends {@link AbstractStandardPromptTemplate}
 * to leverage BeanOutputConverter for consistent response structure with
 * {@link StudioQueryStreamingTemplate}.
 * </p>
 * <p>
 * Both streaming and non-streaming templates share the same response structure
 * through {@link StudioQueryResponse}, ensuring client compatibility regardless
 * of the execution mode.
 * </p>
 *
 * @see AbstractStandardPromptTemplate
 * @see StudioQueryStreamingTemplate
 * @see StudioQueryResponse
 */
public class StudioQueryTemplate extends AbstractStandardPromptTemplate<StudioQueryResponse> {

    /**
     * Creates a new StudioQueryTemplate.
     */
    public StudioQueryTemplate() {
        super(StudioQueryResponse.class);
    }

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            <role>
            You are a Korean IAM permission analysis expert that analyzes provided IAM data and user queries.
            </role>

            <instructions>
            1. **Query Analysis**: Interpret the query accurately to identify requirements.
               - "Who can ~?" = Return only users with the specified permission
               - "Who cannot ~?" = Return only users without the specified permission
               - "All users" = Analyze all users

            2. **Data Filtering**: Select only data that precisely matches the query.
               - Include only relevant users in analysisResults
               - Completely exclude users unrelated to the query
               - When permission status is key, judge only by that permission

            3. **JSON Output**: Output filtered results in the specified JSON format.
               - analysisResults: Only users matching the query
               - Use only actual values from the provided **[Data]**
               - Respond in Korean for naturalLanguageAnswer field
            </instructions>
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("StudioQuery");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQueryFromRequest(request);
        String iamDataContext = extractIamDataContext(request, contextInfo);

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
        return appendFormatInstructions(String.format("""
            [Query]
            %s

            [Data]
            %s

            Generate complete StudioQueryResponse in JSON format.
            """, naturalQuery, contextInfo));
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
            return "Authorization Studio query";
        }

        return "No natural language query provided";
    }
}
