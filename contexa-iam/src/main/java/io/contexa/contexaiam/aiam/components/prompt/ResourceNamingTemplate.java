package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
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

    private static final int MAX_BATCH_SIZE = 20;

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("ResourceNaming");
    }

    @Override
    public PromptGovernanceDescriptor getPromptGovernanceDescriptor() {
        return new PromptGovernanceDescriptor(
                "ResourceNaming",
                "ResourceNaming",
                "1.0.0",
                "1.0",
                PromptReleaseStatus.PRODUCTION,
                "IAM Team",
                "N/A",
                "N/A",
                "N/A",
                "Initial governed release of the resource-naming prompt template.",
                List.of("claude-sonnet-4-6", "claude-opus-4-7"),
                getClass().getName());
    }

    @Override
    public Class<?> getAIGenerationType() {
        return Map.class;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String domainPrompt = generateDomainSystemPrompt(resolveLanguage(request));
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
    // Resolve the caller-requested output language from the AI request context.
    // Defaults to English when no ResourceNamingContext is attached.
    private String resolveLanguage(AIRequest<? extends DomainContext> request) {
        if (request == null) {
            return "English";
        }
        DomainContext context = request.getContext();
        if (context instanceof ResourceNamingContext namingContext && namingContext.isAllowKoreanNames()) {
            return "Korean";
        }
        return "English";
    }

    private String generateDomainSystemPrompt(String language) {
        return """
            You are a resource naming specialist AI that converts technical identifiers into business-friendly names and descriptions.

            Important: The response must be in pure JSON format.
            Language: All names and descriptions must be written in %s.
            Required: You must respond to all input items without exception.""".formatted(language) + """




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
            - friendlyName: Business-friendly name, max 50 characters
            - description: Clear description, max 300 characters
            - confidence: AI confidence score, a decimal between 0.0 and 1.0
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
              },
              "/api/users/{id}": {
                "friendlyName": "User Detail",
                "description": "Retrieve or update a single user account identified by the path parameter."
              },
              "/api/orders:POST": {
                "friendlyName": "Create Order",
                "description": "Submit a new order request into the commerce pipeline."
              },
              "/api/permissions:PATCH": {
                "friendlyName": "Update Permissions",
                "description": "Patch fine-grained permission grants on an existing subject."
              },
              "/api/reports?range=daily": {
                "friendlyName": "Daily Reports",
                "description": "Fetch pre-aggregated report snapshots scoped by the range query parameter."
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

        if (identifiers.size() > MAX_BATCH_SIZE) {
            log.error("ResourceNamingTemplate batch size {} exceeds recommended MAX_BATCH_SIZE={}. Prompt may breach the model token budget.",
                    identifiers.size(), MAX_BATCH_SIZE);
        }

        userPrompt.append("**Required:** Respond to **exactly ").append(identifiers.size()).append("** items below **without any exception**!\n\n");
        userPrompt.append("**Important:** ").append(identifiers.size()).append(" inputs -> ").append(identifiers.size()).append(" outputs required. Missing items will cause system error!\n\n");

        IntStream.range(0, identifiers.size())
                .forEach(i -> {
                    int ordinal = i + 1;
                    userPrompt.append(ordinal).append(". ")
                             .append("[RESOURCE_START_").append(ordinal).append("]\n")
                             .append(escapeForPrompt(identifiers.get(i)))
                             .append("\n[RESOURCE_END_").append(ordinal).append("]\n");
                });

        userPrompt.append("\n**Confirm again:** Provide friendlyName and description for **all ").append(identifiers.size()).append(" items** above!");

        return userPrompt.toString();
    }

    // Escape characters that could otherwise break the RESOURCE_START / RESOURCE_END marker structure
    // or be used as prompt-injection vectors inside an identifier payload.
    private String escapeForPrompt(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                    .replace("\r", "\\r")
                    .replace("\n", "\\n")
                    .replace("\"", "\\\"");
    }
}
