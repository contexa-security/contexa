package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

@Slf4j
public class ConditionTemplatePromptTemplate extends AbstractBasePromptTemplate {

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("ConditionTemplate");
    }

    @Override
    public Class<?> getAIGenerationType() {
        return Map.class;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String templateType = extractTemplateType(request);
        String domainPrompt = "specific".equals(templateType)
                ? generateSpecificDomainSystemPrompt()
                : generateUniversalDomainSystemPrompt();
        String jsonSchema = "specific".equals(templateType)
                ? getSpecificJsonSchemaExample()
                : getUniversalJsonSchemaExample();

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

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String templateType = extractTemplateType(request);
        if ("specific".equals(templateType)) {
            List<String> methodSignatures = request.getParameter("methodSignatures", List.class);
            if (methodSignatures != null && !methodSignatures.isEmpty()) {
                return buildBatchSpecificUserPrompt(methodSignatures, contextInfo);
            }
            String methodSignature = contextInfo != null ? contextInfo : "";
            return buildSingleSpecificUserPrompt(methodSignature);
        }
        return buildUniversalUserPrompt();
    }

    private String extractTemplateType(AIRequest<? extends DomainContext> request) {
        if (isContextType(request, ConditionTemplateContext.class)) {
            ConditionTemplateContext context = (ConditionTemplateContext) request.getContext();
            return context.getTemplateType();
        }
        String type = request.getParameter("templateType", String.class);
        return type != null ? type : "universal";
    }

    // =========================================================================
    // Universal condition prompt methods
    // =========================================================================

    private String generateUniversalDomainSystemPrompt() {
        return """
            You are a specialized AI for generating ABAC universal conditions that creates reusable access control conditions.

            Important: The response must be in pure JSON format only.
            Language: All names and descriptions must be written in English.

            **Universal conditions to generate (exactly 3 only):**
            1. isAuthenticated() - User authentication status check
            2. hasRole('ROLE_ADMIN') - Administrator role check
            3. Business hours access restriction (9AM-6PM)

            **Notes:**
            - Do not use the term "~permission". Use terms like "~status check", "~role check", "~access restriction"
            - Generate exactly 3 only
            - Do not use hasPermission() (prohibited in universal conditions)

            **Output format:**
            Return a JSON object. Keys are condition identifiers (in English), values are condition information objects.
            Each condition information must include:
            - name: English name without using the word "permission"
            - description: Clear English description
            - spelTemplate: SpEL expression without parameters
            - category: English category
            - classification: "UNIVERSAL"
            """;
    }

    private String getUniversalJsonSchemaExample() {
        return """
            {
              "isAuthenticated": {
                "name": "User Authentication Status Check",
                "description": "Condition that checks the user authentication status",
                "spelTemplate": "isAuthenticated()",
                "category": "Authentication Status",
                "classification": "UNIVERSAL"
              },
              "hasRole_ADMIN": {
                "name": "Administrator Role Check",
                "description": "Condition that checks whether the user has the administrator role",
                "spelTemplate": "hasRole('ROLE_ADMIN')",
                "category": "Role Status",
                "classification": "UNIVERSAL"
              },
              "workingHours": {
                "name": "Business Hours Access Restriction",
                "description": "Condition that allows access only during business hours (9AM-6PM)",
                "spelTemplate": "T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18",
                "category": "Time Restriction",
                "classification": "UNIVERSAL"
              }
            }
            """;
    }

    private String buildUniversalUserPrompt() {
        return """
            Generate exactly 3 universal conditions only:

            1. User Authentication Status Check - isAuthenticated()
            2. Administrator Role Check - hasRole('ROLE_ADMIN')
            3. Business Hours Access Restriction - T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18

            Strictly prohibited:
            - Generating 4 or more
            - Using hasPermission() (prohibited in universal conditions)
            - Using non-existent parameters
            - Outputting descriptive text
            - ```json code blocks
            - Preambles like "Sure", "Here is"

            Output requirements:
            - Exactly 3 universal conditions (key: condition identifier, value: condition information object)
            - All text in English
            - Never use the word "permission"

            Generate in JSON format.
            """;
    }

    // =========================================================================
    // Specific condition prompt methods
    // =========================================================================

    private String generateSpecificDomainSystemPrompt() {
        return """
            You are a specialized AI that analyzes Java method signatures to generate SpEL-based hasPermission conditions for ABAC (Attribute-Based Access Control).

            Important: The response must be in pure JSON format only.
            Required: You must respond for all input methods without exception.
            Language: Names and descriptions must be written in English.

                    <rules>
                    1.  **`hasPermission` function generation rules based on input patterns:**
                        * **ID parameter (e.g., `Long id`, `Long userId`):** Use 3 arguments in the format `hasPermission(#parameterName, 'RESOURCE_TYPE', 'ACTION')`.
                        * **Object parameter (e.g., `Group group`, `UserDto userDto`):** Use 2 arguments in the format `hasPermission(#parameterName, 'RESOURCE_TYPE_ACTION')`.
                    2.  The `name` field should be written in the format "ResourceType ~ Target Verification/Access Check". Never use the word "permission".
                    3.  If the input is a "method without parameters", return an empty condition for that key's value.
                    4.  Never use positional index references such as #p0, #p1. You must extract and use the parameter name from the method signature.
                        Correct example: hasPermission(#id, 'GROUP', 'READ'), hasPermission(#role, 'ROLE_CREATE')
                        Incorrect example: hasPermission(#p0, 'GROUP', 'READ')
                    </rules>

                    <examples>
                    <!-- ID parameter example -->
                    <example>
                      <input>getGroup(Long id)</input>
                      <output_key>"getGroup(Long id)"</output_key>
                      <output_value>
                      {
                        "name": "Group Retrieval Access Check",
                        "description": "Condition that checks READ access for a group with a specific ID",
                        "spelTemplate": "hasPermission(#id, 'GROUP', 'READ')",
                        "category": "Access Check",
                        "classification": "CONTEXT_DEPENDENT"
                      }
                      </output_value>
                    </example>

                    <!-- Object parameter example -->
                    <example>
                      <input>createGroup(Group group)</input>
                      <output_key>"createGroup(Group group)"</output_key>
                      <output_value>
                      {
                        "name": "Group Creation Target Verification",
                        "description": "Condition that verifies GROUP_CREATE access for the group being created",
                        "spelTemplate": "hasPermission(#group, 'GROUP_CREATE')",
                        "category": "Target Verification",
                        "classification": "CONTEXT_DEPENDENT"
                      }
                      </output_value>
                    </example>
                    </examples>

            **Output format:**
            Return a JSON object. Keys are method signatures (as-is from the original), values are condition information objects.

            Absolute rules (system error on violation):
            1. Process 100% of input methods - no exceptions
            2. The number of input items and output items must match exactly
            3. Each item must include all of: name, description, spelTemplate, category, classification
            4. Maintain the input order in the output

            Each condition information must include:
            - name: English name without using the word "permission"
            - description: Clear English description
            - spelTemplate: SpEL expression using hasPermission
            - category: English category ("Access Check" or "Target Verification")
            - classification: "CONTEXT_DEPENDENT"
            """;
    }

    private String getSpecificJsonSchemaExample() {
        return """
            {
              "getGroup(Long id)": {
                "name": "Group Retrieval Access Check",
                "description": "Condition that checks READ access for a group with a specific ID",
                "spelTemplate": "hasPermission(#id, 'GROUP', 'READ')",
                "category": "Access Check",
                "classification": "CONTEXT_DEPENDENT"
              },
              "createGroup(Group group)": {
                "name": "Group Creation Target Verification",
                "description": "Condition that verifies GROUP_CREATE access for the group being created",
                "spelTemplate": "hasPermission(#group, 'GROUP_CREATE')",
                "category": "Target Verification",
                "classification": "CONTEXT_DEPENDENT"
              }
            }
            """;
    }

    private String buildBatchSpecificUserPrompt(List<String> methodSignatures, String contextInfo) {
        StringBuilder prompt = new StringBuilder();

        if (contextInfo != null && !contextInfo.trim().isEmpty()) {
            prompt.append("**Reference Context:**\n")
                     .append(contextInfo)
                     .append("\n\n");
        }

        prompt.append("**Required:** Generate hasPermission conditions for **all** of the following **exactly ")
              .append(methodSignatures.size())
              .append("** method signatures **without any exceptions**!\n\n");
        prompt.append("**Important:** ")
              .append(methodSignatures.size())
              .append(" inputs -> ")
              .append(methodSignatures.size())
              .append(" outputs are required. Missing items will cause a system error!\n\n");

        IntStream.range(0, methodSignatures.size())
                .forEach(i -> prompt.append(i + 1)
                        .append(". ")
                        .append(methodSignatures.get(i))
                        .append("\n"));

        prompt.append("\nGeneration rules:\n");
        prompt.append("- ID parameter: hasPermission(#parameterName, 'RESOURCE_TYPE', 'ACTION')\n");
        prompt.append("- Object parameter: hasPermission(#parameterName, 'RESOURCE_TYPE_ACTION')\n");
        prompt.append("- No parameters: Set spelTemplate to an empty string\n");
        prompt.append("- Positional indices like #p0, #p1 are strictly prohibited. You must use actual parameter names (#id, #group, etc.)\n\n");

        prompt.append("Important notes:\n");
        prompt.append("- Write names and descriptions in English\n");
        prompt.append("- Never use the word \"permission\" in names\n\n");

        prompt.append("**Confirm once more:** Provide name, description, spelTemplate, category, classification for **all ")
              .append(methodSignatures.size())
              .append(" items** listed above!");

        return prompt.toString();
    }

    private String buildSingleSpecificUserPrompt(String methodSignature) {
        return String.format("""
            Analyze the following Java method signature and generate a specific condition template:

            Method signature:
            %s

            Generation rules:
            - ID parameter: hasPermission(#parameterName, 'RESOURCE_TYPE', 'ACTION')
            - Object parameter: hasPermission(#parameterName, 'RESOURCE_TYPE_ACTION')
            - No parameters: Set spelTemplate to an empty string
            - Positional indices like #p0, #p1 are strictly prohibited. You must use actual parameter names (#id, #group, etc.)

            Important notes:
            - Write names and descriptions in English
            - Never use the word "permission" in names
            - Keys must use the method signature exactly as-is from the original

            Generate in JSON format.
            """, methodSignature);
    }
}
