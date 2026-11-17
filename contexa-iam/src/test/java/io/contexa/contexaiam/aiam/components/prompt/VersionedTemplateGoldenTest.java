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

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Plan 6-7: the four IAM templates draw from their product documents the very prompts the code drew before the move,
 * letter for letter, for every case of their inputs (the golden prompts under {@code prompt-versions-golden}).
 */
class VersionedTemplateGoldenTest {

    @SuppressWarnings({"unchecked", "rawtypes"})
    static AIRequest<? extends DomainContext> request(DomainContext context, Map<String, Object> parameters,
                                                      String naturalQuery) {
        AIRequest request = mock(AIRequest.class);
        when(request.getContext()).thenReturn(context);
        when(request.getNaturalLanguageQuery()).thenReturn(naturalQuery);
        when(request.getParameter(anyString(), any(Class.class))).thenAnswer(call -> parameters.get(call.getArgument(0)));
        return request;
    }

    static PolicyGenerationItem.AvailableItems items() {
        return new PolicyGenerationItem.AvailableItems(
                List.of(new PolicyGenerationItem.RoleItem(101L, "Team Manager", "Manages the team"),
                        new PolicyGenerationItem.RoleItem(102L, "Document Handler", null)),
                List.of(new PolicyGenerationItem.PermissionItem(201L, "Read documents", null, "URL", "/api/documents", "GET"),
                        new PolicyGenerationItem.PermissionItem(202L, "Export", null, "METHOD", "io.contexa.Export.run()", null),
                        new PolicyGenerationItem.PermissionItem(203L, "Plain", null, null, null, null)),
                List.of(new PolicyGenerationItem.ConditionItem(301L, "Within Business Hours", null, true),
                        new PolicyGenerationItem.ConditionItem(302L, "Internal Network", null, true)));
    }

    /** The prompts of the cases, drawn by the templates now. */
    static Map<String, String> cases() {
        Map<String, String> cases = new LinkedHashMap<>();
        ResourceNamingTemplate naming = new ResourceNamingTemplate();
        ResourceNamingContext english = new ResourceNamingContext();
        english.setAllowKoreanNames(false);
        ResourceNamingContext korean = new ResourceNamingContext();
        korean.setAllowKoreanNames(true);
        Map<String, Object> resources = new LinkedHashMap<>();
        resources.put("resources", List.of(
                new LinkedHashMap<>(Map.of("identifier", "/api/users/{id}", "resourceType", "URL", "httpMethod", "GET",
                        "owner", "UserController", "scannerFriendlyNameHint", "User detail",
                        "scannerDescriptionHint", "Reads \"one\" user\nby id", "parameterTypes", "Long",
                        "returnType", "UserDto", "apiDocsUrl", "/docs#users", "sourceCodeLocation", "C:\\src\\User.java")),
                Map.of("identifier", "io.contexa.example.UserService.updateUser(Long,UserForm)")));
        cases.put("ResourceNaming/system-english", naming.generateSystemPrompt(request(english, Map.of(), null), null));
        cases.put("ResourceNaming/system-korean-context", naming.generateSystemPrompt(request(korean, Map.of(), null),
                "meta line one\nmeta line two"));
        cases.put("ResourceNaming/system-no-request", naming.generateSystemPrompt(null, "  "));
        cases.put("ResourceNaming/user-resources-context", naming.generateUserPrompt(request(english, resources, null),
                "Reference about the users module"));
        cases.put("ResourceNaming/user-identifiers", naming.generateUserPrompt(request(english,
                Map.of("identifiers", List.of("/api/groups", "/api/orders:POST")), null), "  "));
        cases.put("ResourceNaming/user-empty", naming.generateUserPrompt(request(english, Map.of(), null), null));

        PolicyGenerationTemplate policy = new PolicyGenerationTemplate();
        cases.put("PolicyGeneration/system", policy.generateSystemPrompt(request(null, Map.of(), null), null));
        cases.put("PolicyGeneration/system-context", policy.generateSystemPrompt(request(null, Map.of(), null),
                "system metadata"));
        cases.put("PolicyGeneration/user-full", policy.generateUserPrompt(request(null,
                Map.of("availableItems", items(), "iamDataContext", "IAM data: 3 roles"), "Let managers read documents"),
                "similar policy A"));
        cases.put("PolicyGeneration/user-data-only", policy.generateUserPrompt(request(null,
                Map.of("availableItems", new PolicyGenerationItem.AvailableItems(List.of(), List.of(), List.of()),
                        "iamDataContext", "IAM data only"), null), null));
        cases.put("PolicyGeneration/user-rag-only", policy.generateUserPrompt(request(null,
                Map.of("naturalLanguageQuery", "From the parameter"), null), "rag only"));
        cases.put("PolicyGeneration/user-nothing", policy.generateUserPrompt(request(null, Map.of(), null), null));

        PolicyGenerationStreamingTemplate streaming = new PolicyGenerationStreamingTemplate();
        cases.put("PolicyGenerationStreaming/system", streaming.generateSystemPrompt(request(null, Map.of(), null), null));
        cases.put("PolicyGenerationStreaming/system-context", streaming.generateSystemPrompt(request(null, Map.of(), null),
                "system metadata"));
        cases.put("PolicyGenerationStreaming/user-full", streaming.generateUserPrompt(request(null,
                Map.of("availableItems", items(), "iamDataContext", "IAM data: 3 roles",
                        "naturalLanguageQuery", "Let managers read documents"), null), "similar policy A"));
        cases.put("PolicyGenerationStreaming/user-plain", streaming.generateUserPrompt(request(null,
                Map.of("naturalLanguageQuery", "Only a query"), null), null));
        cases.put("PolicyGenerationStreaming/user-empty-items", streaming.generateUserPrompt(request(null,
                Map.of("naturalLanguageQuery", "Empty items",
                        "availableItems", new PolicyGenerationItem.AvailableItems(null, null, null)), null), "  "));

        ConditionTemplatePromptTemplate condition = new ConditionTemplatePromptTemplate();
        ConditionTemplateContext universal = new ConditionTemplateContext("universal", null, null);
        ConditionTemplateContext specific = new ConditionTemplateContext("specific", "/api/groups", "getGroup(Long id)");
        cases.put("ConditionTemplate/system-universal", condition.generateSystemPrompt(request(universal, Map.of(), null), null));
        cases.put("ConditionTemplate/system-specific-context", condition.generateSystemPrompt(request(specific, Map.of(), null),
                "metadata"));
        cases.put("ConditionTemplate/system-parameter", condition.generateSystemPrompt(request(null,
                Map.of("templateType", "specific"), null), null));
        cases.put("ConditionTemplate/user-universal", condition.generateUserPrompt(request(universal, Map.of(), null), "ctx"));
        cases.put("ConditionTemplate/user-batch-context", condition.generateUserPrompt(request(specific,
                Map.of("methodSignatures", List.of("getGroup(Long id)", "createGroup(Group group)", "listAll()")), null),
                "Reference about groups"));
        cases.put("ConditionTemplate/user-batch", condition.generateUserPrompt(request(specific,
                Map.of("methodSignatures", List.of("deleteRole(Long roleId)")), null), "  "));
        cases.put("ConditionTemplate/user-single", condition.generateUserPrompt(request(specific, Map.of(), null),
                "updateUser(Long id, UserForm form)"));
        cases.put("ConditionTemplate/user-single-empty", condition.generateUserPrompt(request(specific, Map.of(), null), null));
        return cases;
    }

    @TestFactory
    Stream<DynamicTest> everyCaseDrawsTheGoldenPrompt() {
        Map<String, String> cases = cases();
        assertThat(cases).hasSize(25);
        return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(),
                () -> assertThat(entry.getValue()).isEqualTo(golden(entry.getKey()))));
    }

    static String golden(String name) throws IOException {
        try (InputStream input = VersionedTemplateGoldenTest.class.getClassLoader()
                .getResourceAsStream("prompt-versions-golden/" + name + ".txt")) {
            assertThat(input).as(name).isNotNull();
            // A checkout may turn the golden files' line breaks into CRLF; the prompts break lines with LF.
            return new String(input.readAllBytes(), StandardCharsets.UTF_8).replace("\r\n", "\n");
        }
    }
}
