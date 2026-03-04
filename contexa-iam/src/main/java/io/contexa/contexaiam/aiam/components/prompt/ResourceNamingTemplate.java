package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Non-streaming template for resource naming suggestion generation.
 * <p>
 * This template generates prompts for converting technical identifiers
 * into business-friendly Korean names and descriptions.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 */
@Slf4j
public class ResourceNamingTemplate extends AbstractBasePromptTemplate {

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("ResourceNaming");
    }

    @Override
    public Class<?> getAIGenerationType() {
        return Map.class;
    }

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
     * Generates the domain-specific system prompt for resource naming.
     *
     * @return the domain-specific system prompt content
     */
    private String generateDomainSystemPrompt() {
        return """
            You are a resource naming specialist AI that converts technical identifiers into business-friendly names and descriptions.

            Important: The response must be in pure JSON format.
            Language: All names and descriptions must be written in English.
            Required: You must respond to all input items without exception.

            Absolute rules (system error on violation):
            1. Process 100% of input items - no exceptions
            2. The number of input items and output items must match exactly
            3. Each item must include both friendlyName and description
            4. Only pure JSON format allowed - no descriptive text
            5. Use clear and friendly names and descriptions
            6. Maintain the input order in the output

            Processing rules:
            - camelCase/snake_case -> human-readable name
            - URL path -> feature name (e.g., /admin/users -> User Management)
            - Method name -> action description (e.g., updateUser -> Update User Information)
            - CRUD operations -> clear verbs (Create, Read, Update, Delete)
            - API endpoints -> descriptive feature names
            - Technical terms -> business-friendly terms

            Fallback rules:
            When an item cannot be understood:
            - friendlyName: "[item name] feature"
            - description: "Resource that did not receive AI recommendation."
            - confidence: 0.3

            Required output:
            - suggestions: Array of ResourceNamingSuggestion objects
            - failedIdentifiers: Array of identifiers that could not be processed
            - stats: Processing statistics (item count, elapsed time)

            Each suggestion must include:
            - identifier: Original technical identifier
            - friendlyName: Business-friendly name
            - description: Clear description
            - confidence: AI confidence score (0.0-1.0)
            """;
    }

    /**
     * Returns the manual JSON schema example for resource naming response.
     *
     * @return JSON schema example with field descriptions
     */
    private String getJsonSchemaExample() {
        return """
            {
              "/admin/users": {
                "friendlyName": "User Management",
                "description": "Interface for viewing and managing all user accounts in the system."
              },
              "/api/groups": {
                "friendlyName": "Group API",
                "description": "API endpoint for creating, reading, updating, and deleting user group information."
              }
            }
            """;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {

        List<String> identifiers = request.getParameter("identifiers", List.class);

        if (identifiers == null || identifiers.isEmpty()) {
            log.error("Resource list is empty");
            return "Error: No resources to process";
        }

        return buildUserPromptFromIdentifiers(identifiers, contextInfo);
    }
    private String buildUserPromptFromIdentifiers(List<String> identifiers, String context) {
        StringBuilder userPrompt = new StringBuilder();

        if (context != null && !context.trim().isEmpty()) {
            userPrompt.append("**Reference context:**\n")
                     .append(context)
                     .append("\n\n");
        }

        userPrompt.append("**Required:** Respond to **exactly ").append(identifiers.size()).append("** items below **without any exception**!\n\n");
        userPrompt.append("**Important:** ").append(identifiers.size()).append(" inputs -> ").append(identifiers.size()).append(" outputs required. Missing items will cause system error!\n\n");

        IntStream.range(0, identifiers.size())
                .forEach(i -> {
                    userPrompt.append(i + 1)
                             .append(". ")
                             .append(identifiers.get(i))
                             .append("\n");
                });

        userPrompt.append("\n**Confirm again:** Provide friendlyName and description for **all ").append(identifiers.size()).append(" items** above!");

        return userPrompt.toString();
    }
}
