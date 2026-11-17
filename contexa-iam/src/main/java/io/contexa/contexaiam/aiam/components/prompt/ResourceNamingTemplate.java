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
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptDocuments;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptDrawing;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionPin;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingStructuredOutput;
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Non-streaming template for resource naming suggestion generation.
 * <p>
 * This template generates prompts for converting technical identifiers into business-friendly names and descriptions.
 * Every sentence of the prompt is the version's (plan 3.11): the version the resolver chooses for the prompt, else the
 * product document {@code prompt-versions/ResourceNaming}. The code fills in the language, the resources and their
 * count.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 */
@Slf4j
public class ResourceNamingTemplate extends AbstractBasePromptTemplate implements VersionedPrompt {

    /** The prompt key, the template key the prompt is called by. */
    public static final String PROMPT = "ResourceNaming";
    /** The product releases this build ships, the latest last. */
    public static final List<String> RELEASES = List.of("2026.11.17");

    private static final int MAX_BATCH_SIZE = 100;
    private static final ProductPromptDocuments DOCUMENTS =
            new ProductPromptDocuments(ResourceNamingTemplate.class, PROMPT, RELEASES);
    private static final PromptGovernanceDescriptor DESCRIPTOR = new PromptGovernanceDescriptor(
            PROMPT,
            PROMPT,
            "1.0.0",
            "1.0",
            PromptReleaseStatus.PRODUCTION,
            "IAM Team",
            "N/A",
            "N/A",
            "N/A",
            "Initial governed release of the resource-naming prompt template.",
            List.of("claude-sonnet-4-6", "claude-opus-4-7"),
            ResourceNamingTemplate.class.getName());

    private final PromptVersionPin pin = new PromptVersionPin();
    private PromptVersionInUse versions = PromptVersionInUse.productOnly();

    /** The versions the template reads; without them it draws the product document. */
    public void setPromptVersions(PromptVersionInUse versions) {
        this.versions = Objects.requireNonNull(versions, "versions");
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType(PROMPT);
    }

    @Override
    public PromptGovernanceDescriptor getPromptGovernanceDescriptor() {
        return pin.last(this::choose).describe(DESCRIPTOR);
    }

    @Override
    public Class<?> getAIGenerationType() {
        return ResourceNamingStructuredOutput.class;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return system(version(request), korean(request), systemMetadata);
    }

    private static String system(AssembledPrompt version, boolean korean, String systemMetadata) {
        Set<String> conditions = korean ? Set.of("korean") : Set.of();
        Map<String, String> values = Map.of("language",
                VersionedTemplateDrawing.item(version, "json-only", korean ? "korean" : "english"));
        return VersionedTemplateDrawing.jsonSystem(version, conditions, values, systemMetadata);
    }

    private static boolean korean(AIRequest<? extends DomainContext> request) {
        return request != null && request.getContext() instanceof ResourceNamingContext namingContext
                && namingContext.isAllowKoreanNames();
    }

    @Override
    @SuppressWarnings("unchecked")
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        List<Map<String, String>> resources = request.getParameter("resources", List.class);
        if (resources == null || resources.isEmpty()) {
            List<String> identifiers = request.getParameter("identifiers", List.class);
            if (identifiers == null || identifiers.isEmpty()) {
                log.error("Resource list is empty");
                return user(version(request), List.of(), contextInfo);
            }
            resources = identifiers.stream()
                    .map(identifier -> Map.of("identifier", identifier == null ? "" : identifier))
                    .toList();
        }
        if (resources.size() > MAX_BATCH_SIZE) {
            log.warn("ResourceNamingTemplate batch size {} exceeds recommended MAX_BATCH_SIZE={}. Prompt may breach the model token budget.",
                    resources.size(), MAX_BATCH_SIZE);
        }
        return user(version(request), resources, contextInfo);
    }

    private static String user(AssembledPrompt version, List<Map<String, String>> resources, String context) {
        Map<String, String> values = new LinkedHashMap<>();
        Set<String> conditions;
        if (resources.isEmpty()) {
            conditions = Set.of("no-resources");
        }
        else {
            boolean withContext = context != null && !context.trim().isEmpty();
            conditions = withContext ? Set.of("resources", "context") : Set.of("resources");
            values.put("context", withContext ? context : "");
            values.put("count", String.valueOf(resources.size()));
            StringBuilder blocks = new StringBuilder();
            for (int index = 0; index < resources.size(); index++) {
                appendResourceBlock(blocks, index + 1, resources.get(index));
            }
            values.put("resources", blocks.toString());
        }
        return VersionedTemplateDrawing.withoutLastBreak(PromptDrawing.user(version, conditions, values));
    }

    private static void appendResourceBlock(StringBuilder userPrompt, int ordinal, Map<String, String> resource) {
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

    private static void appendField(StringBuilder userPrompt, String name, String value, boolean required) {
        if (!required && (value == null || value.isBlank())) {
            return;
        }
        userPrompt.append(name).append(": ")
                .append(escapeForPrompt(value))
                .append("\n");
    }

    private static String escapeForPrompt(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\"", "\\\"");
    }

    private AssembledPrompt version(AIRequest<? extends DomainContext> request) {
        return pin.of(request, this::choose).version();
    }

    private PromptVersionInUse.Choice choose() {
        return versions.choose(PROMPT, DOCUMENTS.product(), null);
    }

    // ----- the prompt's versions (plan 3.11) -----

    @Override
    public String prompt() {
        return PROMPT;
    }

    @Override
    public List<ProductPromptRelease> productReleases() {
        return DOCUMENTS.releases();
    }

    @Override
    public AssembledPrompt product() {
        return DOCUMENTS.product();
    }

    @Override
    public PromptGovernanceDescriptor registryDescriptor() {
        return DESCRIPTOR;
    }

    @Override
    public Example example(AssembledPrompt version) {
        List<Map<String, String>> resources = List.of(
                Map.of("identifier", "/api/users/{id}", "resourceType", "URL", "httpMethod", "GET"),
                Map.of("identifier", "io.contexa.example.UserService.updateUser(Long,UserForm)"));
        return new Example(system(version, false, null), user(version, resources, null));
    }
}
