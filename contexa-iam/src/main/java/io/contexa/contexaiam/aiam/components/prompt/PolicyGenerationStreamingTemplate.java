package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractStreamingPromptTemplate;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import lombok.extern.slf4j.Slf4j;

/**
 * Streaming template for IAM policy generation.
 * <p>
 * This template generates prompts for creating IAM policies based on
 * natural language requirements with real-time streaming feedback
 * and structured JSON output.
 * </p>
 */
@Slf4j
public class PolicyGenerationStreamingTemplate extends AbstractStreamingPromptTemplate {

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
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
            - Always include a "reasoning" field explaining why you chose these specific roles, permissions, and conditions
            """;
    }

    @Override
    protected String getJsonSchemaExample() {
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
              "reasoning": "Explain why these roles, permissions, and conditions were selected based on the requirements.",
              "generatedAt": "2023-10-27T10:00:00Z",
              "version": "1.0.0"
            }
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("PolicyGenerationStreaming");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        PolicyGenerationItem.AvailableItems availableItems = extractAvailableItems(request);
        String naturalQuery = extractNaturalQuery(request);

        return buildUserPrompt(naturalQuery, availableItems, contextInfo);
    }

    /**
     * Builds the user prompt with policy generation details and execution instructions.
     *
     * @param naturalQuery the natural language requirements
     * @param availableItems the available roles, permissions, and conditions
     * @param contextInfo additional context information
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String naturalQuery, PolicyGenerationItem.AvailableItems availableItems, String contextInfo) {
        return String.format("""
            **Natural Language Requirements:**
            "%s"

            **Available Items (Use only the IDs and names from this list):**
            %s
            %s
            """, naturalQuery, formatAvailableItems(availableItems), buildUserPromptExecutionInstructions());
    }

    /**
     * Extracts the natural language query from the request.
     *
     * @param request the AI request
     * @return the natural language query or a default message
     */
    public String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        String naturalQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalQuery != null) {
            return naturalQuery;
        }
        return request.getContext() != null ? request.getContext().toString() : "Natural language requirements were not provided";
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
        return info.length() > 0 ? info.toString() : "No available items found.";
    }
}
