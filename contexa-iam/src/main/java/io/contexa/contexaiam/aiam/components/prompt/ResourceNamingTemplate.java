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
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingStructuredOutput;
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

    private static final int MAX_BATCH_SIZE = 100;

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
        return ResourceNamingStructuredOutput.class;
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
        prompt.append("The response must be one valid JSON object matching this fixed schema:\n");
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
            1. Return a JSON object with a suggestions array.
            2. Each suggestions item must contain identifier, friendlyName, description, and confidence.
            3. identifier must exactly match one original input identifier.
            4. Do not use resource identifiers as top-level JSON keys.
            5. Do not add top-level keys named failedIdentifiers, stats, summary, or metadata.
            6. The suggestions item count must match the input item count exactly.
            7. Never output placeholder text or failure explanations as a successful resource name.

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
                  "suggestions": [
                    {
                      "identifier": "/contexa/admin/users",
                      "friendlyName": "사용자 관리",
                      "description": "사용자 계정을 조회하고 관리하는 화면입니다.",
                      "confidence": 0.95
                    },
                    {
                      "identifier": "/api/groups",
                      "friendlyName": "그룹 API",
                      "description": "그룹 정보를 관리하는 API입니다.",
                      "confidence": 0.92
                    },
                    {
                      "identifier": "/api/users/{id}",
                      "friendlyName": "사용자 상세",
                      "description": "사용자 ID로 단일 사용자 정보를 조회하거나 변경합니다.",
                      "confidence": 0.9
                    },
                    {
                      "identifier": "/api/orders:POST",
                      "friendlyName": "주문 생성",
                      "description": "새 주문 요청을 등록합니다.",
                      "confidence": 0.88
                    },
                    {
                      "identifier": "/api/permissions:PATCH",
                      "friendlyName": "권한 수정",
                      "description": "권한 정보를 부분 수정합니다.",
                      "confidence": 0.87
                    },
                    {
                      "identifier": "io.contexa.example.UserService.updateUser(Long,UserForm)",
                      "friendlyName": "사용자 정보 수정",
                      "description": "사용자 정보를 갱신하는 서비스 메서드입니다.",
                      "confidence": 0.86
                    }
                  ]
                }
                """;
        }

        return """
            {
              "suggestions": [
                {
                  "identifier": "/contexa/admin/users",
                  "friendlyName": "User Management",
                  "description": "Screen for administrators to view user accounts and start status or permission management.",
                  "confidence": 0.95
                },
                {
                  "identifier": "/api/groups",
                  "friendlyName": "Group API",
                  "description": "API endpoint for reading, creating, updating, and deleting user group information.",
                  "confidence": 0.92
                },
                {
                  "identifier": "/api/users/{id}",
                  "friendlyName": "User Detail",
                  "description": "Retrieve or update a single user account identified by the path parameter.",
                  "confidence": 0.9
                },
                {
                  "identifier": "/api/orders:POST",
                  "friendlyName": "Create Order",
                  "description": "Submit a new order request into the order processing flow.",
                  "confidence": 0.88
                },
                {
                  "identifier": "/api/permissions:PATCH",
                  "friendlyName": "Update Permissions",
                  "description": "Patch fine-grained permission grants on an existing subject.",
                  "confidence": 0.87
                },
                {
                  "identifier": "io.contexa.example.UserService.updateUser(Long,UserForm)",
                  "friendlyName": "Update User Information",
                  "description": "Service method that updates account information from a user identifier and input form.",
                  "confidence": 0.86
                }
              ]
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
                .append(" objects in the suggestions array, one for each original identifier below.\n");
        userPrompt.append("Every suggestions[].identifier value must exactly match an input identifier.\n");
        userPrompt.append("Do not use URL paths or method signatures as top-level JSON property names.\n\n");

        IntStream.range(0, resources.size())
                .forEach(i -> appendResourceBlock(userPrompt, i + 1, resources.get(i)));

        userPrompt.append("\nConfirm: every identifier above must appear exactly once in suggestions[].identifier.");

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
