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
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("ResourceNamingTemplate language selection and few-shot examples")
class ResourceNamingTemplateLanguageTest {

    private ResourceNamingTemplate template;

    @BeforeEach
    void setUp() {
        template = new ResourceNamingTemplate();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private AIRequest<? extends DomainContext> requestWithContext(ResourceNamingContext context) {
        AIRequest req = mock(AIRequest.class);
        when(req.getContext()).thenReturn(context);
        when(req.getParameter("identifiers", List.class)).thenReturn(List.of("/api/x"));
        return req;
    }

    @Test
    @DisplayName("allowKoreanNames=true produces a system prompt that instructs Korean output")
    void allowKoreanNames_true_usesKoreanLanguageInstruction() {
        ResourceNamingContext context = new ResourceNamingContext();
        context.setAllowKoreanNames(true);

        String systemPrompt = template.generateSystemPrompt(requestWithContext(context), null);

        assertThat(systemPrompt)
                .as("allowKoreanNames=true must propagate into the domain prompt")
                .containsIgnoringCase("Korean");
    }

    @Test
    @DisplayName("allowKoreanNames=false produces a system prompt that instructs English output")
    void allowKoreanNames_false_usesEnglishLanguageInstruction() {
        ResourceNamingContext context = new ResourceNamingContext();
        context.setAllowKoreanNames(false);

        String systemPrompt = template.generateSystemPrompt(requestWithContext(context), null);

        assertThat(systemPrompt).containsIgnoringCase("English");
    }

    @Test
    @DisplayName("Few-shot example schema lists at least five representative identifiers")
    void schema_includesAtLeastFiveFewShotExamples() {
        ResourceNamingContext context = new ResourceNamingContext();
        String systemPrompt = template.generateSystemPrompt(requestWithContext(context), null);

        long slashCount = systemPrompt.lines()
                .filter(line -> line.contains("\"identifier\"") && line.contains("\"/"))
                .count();

        assertThat(slashCount)
                .as("schema block should contain at least five path identifiers so the few-shot set covers list/detail/action variants")
                .isGreaterThanOrEqualTo(5);
    }
}
