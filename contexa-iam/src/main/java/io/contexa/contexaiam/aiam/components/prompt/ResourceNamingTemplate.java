/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Non-streaming template for resource naming suggestion generation.
 * <p>
 * This template generates prompts for converting technical identifiers
 * into business-friendly names and descriptions.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 */
@Slf4j
public class ResourceNamingTemplate extends AbstractBasePromptTemplate {

    private static final int MAX_BATCH_SIZE = 50;

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
        String language = resolveLanguage(request);
        String domainPrompt = generateDomainSystemPrompt(language);
        String jsonSchema = getJsonSchemaExample(language);

        StringBuilder prompt = new StringBuilder();
        prompt.append(domainPrompt.trim());
        prompt.append("\n\n");
        prompt.append("<output_format>\n");
        prompt.append("The response must be one valid JSON object matching this identifier-keyed schema:\n");
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
        String languageInstruction = "Korean".equals(language)
                ? "All friendlyName and description values must be natural Korean for an IAM administrator."
                : "All friendlyName and description values must be natural English for an IAM administrator.";

        return """
            You are a resource naming specialist AI that converts server-side technical resource identifiers into business-friendly resource names and descriptions.

            Important: Return pure JSON only.
            %s
            Required: Process every input resource exactly once.

            Output contract:
            1. The top-level JSON object must use each original resource identifier as the key.
            2. Each value must contain friendlyName, description, and confidence.
            3. Do not add wrapper keys named "suggestions", "failedIdentifiers", "stats", "summary", or "metadata".
            4. The output item count must match the input item count exactly.
            5. Never output placeholder text or failure explanations as a successful resource name.

            Naming rules:
            - Convert URL paths into clear feature names.
            - Convert method signatures into clear business actions.
            - Use HTTP method, resource type, owner/controller, parameter types, return type, source location, and existing scanner hints as supporting context.
            - Prefer administrator-facing business terms over Java or framework terms.
            - Keep friendlyName within 50 characters.
            - Keep description within 300 characters.
            - confidence must be a decimal from 0.0 to 1.0.
            - If a resource is ambiguous, still infer the most useful neutral business name from the identifier and set a lower confidence.
            """.formatted(languageInstruction);
    }

    private String getJsonSchemaExample(String language) {
        if ("Korean".equals(language)) {
            return """
                {
                  "/contexa/admin/users": {
                    "friendlyName": "\uC0AC\uC6A9\uC790 \uAD00\uB9AC",
                    "description": "\uC0AC\uC6A9\uC790 \uACC4\uC815\uC744 \uC870\uD68C\uD558\uACE0 \uAD00\uB9AC\uD558\uB294 \uD654\uBA74\uC785\uB2C8\uB2E4.",
                    "confidence": 0.95
                  },
                  "/api/groups": {
                    "friendlyName": "\uADF8\uB8F9 API",
                    "description": "\uADF8\uB8F9 \uC815\uBCF4\uB97C \uAD00\uB9AC\uD558\uB294 API\uC785\uB2C8\uB2E4.",
                    "confidence": 0.92
                  },
                  "/api/users/{id}": {
                    "friendlyName": "\uC0AC\uC6A9\uC790 \uC0C1\uC138",
                    "description": "\uC0AC\uC6A9\uC790 ID\uB85C \uB2E8\uC77C \uC0AC\uC6A9\uC790 \uC815\uBCF4\uB97C \uC870\uD68C\uD558\uAC70\uB098 \uBCC0\uACBD\uD569\uB2C8\uB2E4.",
                    "confidence": 0.9
                  },
                  "/api/orders:POST": {
                    "friendlyName": "\uC8FC\uBB38 \uC0DD\uC131",
                    "description": "\uC0C8 \uC8FC\uBB38 \uC694\uCCAD\uC744 \uB4F1\uB85D\uD569\uB2C8\uB2E4.",
                    "confidence": 0.88
                  },
                  "/api/permissions:PATCH": {
                    "friendlyName": "\uAD8C\uD55C \uC218\uC815",
                    "description": "\uAD8C\uD55C \uC815\uBCF4\uB97C \uBD80\uBD84 \uC218\uC815\uD569\uB2C8\uB2E4.",
                    "confidence": 0.87
                  },
                  "io.contexa.example.UserService.updateUser(Long,UserForm)": {
                    "friendlyName": "\uC0AC\uC6A9\uC790 \uC815\uBCF4 \uC218\uC815",
                    "description": "\uC0AC\uC6A9\uC790 \uC815\uBCF4\uB97C \uAC31\uC2E0\uD558\uB294 \uC11C\uBE44\uC2A4 \uBA54\uC11C\uB4DC\uC785\uB2C8\uB2E4.",
                    "confidence": 0.86
                  }
                }
                """;
        }

        return """
            {
              "/contexa/admin/users": {
                "friendlyName": "User Management",
                "description": "Screen for administrators to view user accounts and start status or permission management.",
                "confidence": 0.95
              },
              "/api/groups": {
                "friendlyName": "Group API",
                "description": "API endpoint for reading, creating, updating, and deleting user group information.",
                "confidence": 0.92
              },
              "/api/users/{id}": {
                "friendlyName": "User Detail",
                "description": "Retrieve or update a single user account identified by the path parameter.",
                "confidence": 0.9
              },
              "/api/orders:POST": {
                "friendlyName": "Create Order",
                "description": "Submit a new order request into the order processing flow.",
                "confidence": 0.88
              },
              "/api/permissions:PATCH": {
                "friendlyName": "Update Permissions",
                "description": "Patch fine-grained permission grants on an existing subject.",
                "confidence": 0.87
              },
              "io.contexa.example.UserService.updateUser(Long,UserForm)": {
                "friendlyName": "Update User Information",
                "description": "Service method that updates account information from a user identifier and input form.",
                "confidence": 0.86
              }
            }
            """;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        List<Map<String, String>> resources = request.getParameter("resources", List.class);
        if (resources == null || resources.isEmpty()) {
            List<String> identifiers = request.getParameter("identifiers", List.class);
            if (identifiers == null || identifiers.isEmpty()) {
                log.error("Resource list is empty");
                return "Error: No resources to process";
            }
            resources = identifiers.stream()
                    .map(identifier -> Map.of("identifier", identifier == null ? "" : identifier))
                    .toList();
        }

        return buildUserPromptFromResources(resources, contextInfo);
    }

    private String buildUserPromptFromResources(List<Map<String, String>> resources, String context) {
        StringBuilder userPrompt = new StringBuilder();

        if (context != null && !context.trim().isEmpty()) {
            userPrompt.append("Reference context:\n")
                    .append(context)
                    .append("\n\n");
        }

        if (resources.size() > MAX_BATCH_SIZE) {
            log.error("ResourceNamingTemplate batch size {} exceeds recommended MAX_BATCH_SIZE={}. Prompt may breach the model token budget.",
                    resources.size(), MAX_BATCH_SIZE);
        }

        userPrompt.append("Required: respond with exactly ").append(resources.size())
                .append(" top-level JSON properties, one for each original identifier below.\n");
        userPrompt.append("Do not add any top-level wrapper object around the identifier-keyed result.\n\n");

        IntStream.range(0, resources.size())
                .forEach(i -> appendResourceBlock(userPrompt, i + 1, resources.get(i)));

        userPrompt.append("\nConfirm: every identifier above must appear exactly once as a top-level JSON key.");

        return userPrompt.toString();
    }

    private void appendResourceBlock(StringBuilder userPrompt, int ordinal, Map<String, String> resource) {
        userPrompt.append(ordinal).append(". ")
                .append("[RESOURCE_START_").append(ordinal).append("]\n");
        appendField(userPrompt, "identifier", resource.get("identifier"), true);
        appendField(userPrompt, "resourceType", resource.get("resourceType"), false);
        appendField(userPrompt, "httpMethod", resource.get("httpMethod"), false);
        appendField(userPrompt, "owner", resource.get("owner"), false);
        appendField(userPrompt, "scannerFriendlyNameHint", resource.get("scannerFriendlyNameHint"), false);
        appendField(userPrompt, "scannerDescriptionHint", resource.get("scannerDescriptionHint"), false);
        appendField(userPrompt, "parameterTypes", resource.get("parameterTypes"), false);
        appendField(userPrompt, "returnType", resource.get("returnType"), false);
        appendField(userPrompt, "apiDocsUrl", resource.get("apiDocsUrl"), false);
        appendField(userPrompt, "sourceCodeLocation", resource.get("sourceCodeLocation"), false);
        userPrompt.append("[RESOURCE_END_").append(ordinal).append("]\n");
    }

    private void appendField(StringBuilder userPrompt, String name, String value, boolean required) {
        if (!required && (value == null || value.isBlank())) {
            return;
        }
        userPrompt.append(name).append(": ")
                .append(escapeForPrompt(value))
                .append("\n");
    }

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