package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;

/**
 * Non-streaming template for IAM policy generation.
 * <p>
 * This template generates prompts for creating IAM policies based on
 * natural language requirements with structured JSON output.
 * Uses manual JSON schema to ensure consistent response structure
 * with {@link PolicyGenerationStreamingTemplate}.
 * </p>
 * <p>
 * Both streaming and non-streaming templates share the same JSON schema,
 * ensuring client compatibility regardless of the execution mode.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 * @see PolicyGenerationStreamingTemplate
 */
public class PolicyGenerationTemplate extends AbstractBasePromptTemplate {

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
     * This content is identical to PolicyGenerationStreamingTemplate for consistency.
     *
     * @return the domain-specific system prompt content
     */
    private String generateDomainSystemPrompt() {
        return """
            You are not a conversational AI, but an IAM policy generation API that outputs data only in the specified JSON format.

            Generate security policies based on natural language requirements including:
            - Role assignment and permission mapping
            - Condition configuration
            - AI-based action evaluation settings (allowedActions: ALLOW, CHALLENGE, ESCALATE, BLOCK)
            - Compliance verification

            **Required rules:**
            - Use only the IDs provided in the 'Available Items' section
            - Generate policies following the principle of least privilege
            - Meet appropriate security and compliance requirements
            - The "conditions" field must be a map with numeric condition template IDs from the condition list as keys and string arrays as values
            - Never use descriptive strings like "time.hour" as condition keys. Use only numeric IDs provided in the condition list
            - If no applicable conditions exist in the condition list, set "conditions" to an empty object {}
            """;
    }

    /**
     * Returns the manual JSON schema example for LLM guidance.
     * This schema is identical to PolicyGenerationStreamingTemplate for consistency.
     *
     * @return JSON schema example with field descriptions
     */
    private String getJsonSchemaExample() {
        return """
            {
              "policyData": {
                "policyName": "Actual policy name based on requirements",
                "description": "Actual policy description based on requirements",
                "effect": "ALLOW",
                "roleIds": [101, 102],
                "permissionIds": [201, 202],
                "conditions": {
                  "301": ["true"],
                  "302": ["192.168.1.0/24"]
                }
              },
              "roleIdToNameMap": {
                "101": "Team Manager",
                "102": "Document Handler"
              },
              "permissionIdToNameMap": {
                "201": "Document View",
                "202": "Document Edit"
              },
              "conditionIdToNameMap": {
                "301": "Within Business Hours",
                "302": "Internal Network"
              },
              "generatedAt": "2023-10-27T10:00:00Z",
              "version": "1.0.0"
            }
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("PolicyGeneration");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQueryFromRequest(request);
        PolicyGenerationItem.AvailableItems availableItems = extractAvailableItems(request);
        String iamDataContext = extractContextInfo(request, contextInfo);

        return buildUserPrompt(naturalQuery, availableItems, iamDataContext);
    }

    /**
     * Builds the user prompt with query, available items, and data context.
     *
     * @param naturalQuery the natural language query
     * @param availableItems the available roles, permissions, and conditions
     * @param contextInfo the IAM data context
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String naturalQuery,
                                   PolicyGenerationItem.AvailableItems availableItems,
                                   String contextInfo) {
        return String.format("""
            [Natural Language Requirements]
            %s

            [Available Items]
            %s

            [Data]
            %s

            Generate a complete PolicyResponse in JSON format.
            """, naturalQuery, formatAvailableItems(availableItems), contextInfo);
    }

    /**
     * Extracts the natural language query from the request.
     * <p>
     * This method provides PolicyGeneration-specific extraction logic,
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

        return "Natural language requirements were not provided";
    }

    /**
     * Extracts the available items from the request.
     *
     * @param request the AI request
     * @return the available items for policy generation
     */
    private PolicyGenerationItem.AvailableItems extractAvailableItems(AIRequest<? extends DomainContext> request) {
        return request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);
    }

    /**
     * Formats the available items for display in the prompt.
     * This logic is identical to PolicyGenerationStreamingTemplate for consistency.
     *
     * @param availableItems the available items to format
     * @return the formatted string representation
     */
    private String formatAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        if (availableItems == null) {
            return "No available item information was provided.";
        }
        StringBuilder info = new StringBuilder();
        if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
            info.append("**Role List:**\n");
            availableItems.roles().forEach(role ->
                    info.append(String.format("- %s (ID: %d)\n", role.name(), role.id())));
        }
        if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
            info.append("\n**Permission List:**\n");
            availableItems.permissions().forEach(permission -> {
                info.append(String.format("- %s (ID: %d)", permission.name(), permission.id()));
                if (permission.targetType() != null && permission.resourceIdentifier() != null) {
                    info.append(String.format(" [Protects: %s %s %s]",
                            permission.targetType(),
                            permission.httpMethod() != null ? permission.httpMethod() : "",
                            permission.resourceIdentifier()));
                }
                info.append("\n");
            });
        }
        if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
            info.append("\n**Condition List (You must use only these numeric IDs as keys for the \"conditions\" field):**\n");
            availableItems.conditions().forEach(condition ->
                    info.append(String.format("- ID: %d, Name: %s\n", condition.id(), condition.name())));
        }
        return !info.isEmpty() ? info.toString() : "No available items found.";
    }
}
