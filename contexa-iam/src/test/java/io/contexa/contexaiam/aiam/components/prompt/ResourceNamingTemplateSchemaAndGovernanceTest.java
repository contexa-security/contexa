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
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingStructuredOutput;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("ResourceNamingTemplate schema, governance, batch size")
class ResourceNamingTemplateSchemaAndGovernanceTest {

    private ResourceNamingTemplate template;

    @BeforeEach
    void setUp() {
        template = new ResourceNamingTemplate();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private AIRequest<? extends DomainContext> request(List<String> identifiers) {
        AIRequest req = mock(AIRequest.class);
        when(req.getParameter("identifiers", List.class)).thenReturn(identifiers);
        return req;
    }

    @Test
    @DisplayName("ResourceNaming uses DTO structured output, not dynamic top-level map keys")
    void aiGenerationType_usesStructuredResponseDto() {
        assertThat(template.getAIGenerationType()).isEqualTo(ResourceNamingStructuredOutput.class);
    }

    @Test
    @DisplayName("System prompt schema block communicates friendlyName/description length and confidence range")
    void systemPrompt_advertisesFieldConstraints() {
        String systemPrompt = template.generateSystemPrompt(request(List.of("/api/x")), null);

        assertThat(systemPrompt)
                .as("schema must declare friendlyName length constraint")
                .contains("friendlyName")
                .contains("50");
        assertThat(systemPrompt)
                .as("schema must declare description length constraint")
                .contains("description")
                .contains("300");
        assertThat(systemPrompt)
                .as("schema must declare confidence range")
                .contains("confidence")
                .contains("0.0")
                .contains("1.0");
    }

    @Test
    @DisplayName("System prompt fixes the response contract to a suggestions array schema")
    void systemPrompt_usesSuggestionsArrayContractWithoutFallbackText() {
        String systemPrompt = template.generateSystemPrompt(request(List.of("/api/x")), null);

        assertThat(systemPrompt)
                .contains("suggestions array")
                .contains("identifier")
                .contains("Do not use resource identifiers as top-level JSON keys")
                .contains("failedIdentifiers")
                .doesNotContain("identifier-keyed")
                .doesNotContain("Resource that did not receive AI recommendation.")
                .doesNotContain("[item name] feature");
    }

    @Test
    @DisplayName("User prompt requires exact identifier matching inside suggestions array")
    void userPrompt_requiresExactIdentifierMatchingInsideSuggestionsArray() {
        String userPrompt = template.generateUserPrompt(request(List.of("/api/orders")), null);

        assertThat(userPrompt)
                .contains("suggestions array")
                .contains("suggestions[].identifier")
                .contains("/api/orders")
                .contains("Do not use URL paths or method signatures as top-level JSON property names");
    }

    @Test
    @DisplayName("Governance descriptor overrides default owner and version for the ResourceNaming prompt")
    void governanceDescriptor_overridesOwnerAndVersion() {
        PromptGovernanceDescriptor descriptor = template.getPromptGovernanceDescriptor();

        assertThat(descriptor.owner())
                .as("owner must be explicitly assigned for audit purposes")
                .containsIgnoringCase("IAM");
        assertThat(descriptor.promptVersion())
                .as("version must follow semantic versioning")
                .matches("\\d+\\.\\d+\\.\\d+");
    }

    @Test
    @DisplayName("Batch larger than MAX_BATCH_SIZE emits an error log without throwing")
    void batchSize_overMax_doesNotThrow() {
        List<String> oversized = IntStream.range(0, 55)
                .mapToObj(i -> "/api/resource-" + i)
                .toList();

        String userPrompt = template.generateUserPrompt(request(oversized), null);

        assertThat(userPrompt).contains("[RESOURCE_START_55]", "[RESOURCE_END_55]");
    }
}
