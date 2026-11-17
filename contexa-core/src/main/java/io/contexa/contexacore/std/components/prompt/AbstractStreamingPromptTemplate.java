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
package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import org.springframework.ai.converter.BeanOutputConverter;

/**
 * Abstract base class for all streaming prompt templates.
 * <p>
 * This class extends {@link AbstractBasePromptTemplate} and enforces the streaming protocol: the JSON result of the
 * answer is put between the {@code ===JSON_START===} and {@code ===JSON_END===} markers the streaming parser reads.
 * The sentences of the prompt are the subclass's (plan 3.11: they come from the prompt's version); this class puts the
 * schema between the markers and assembles the system prompt in its fixed order.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 * @see StreamingProtocol
 */
public abstract class AbstractStreamingPromptTemplate extends AbstractBasePromptTemplate {

    /**
     * Generates the complete system prompt with streaming protocol.
     * <p>
     * This method is final and cannot be overridden by subclasses. It assembles, in this order: the domain-specific
     * system prompt, the streaming instructions (the protocol, the JSON output rules and what precedes the schema),
     * the JSON schema example between the markers, and the context information.
     * </p>
     *
     * @param request        the AI request containing domain context
     * @param systemMetadata system metadata to include in the prompt
     * @return the complete system prompt with protocol instructions
     */
    @Override
    public final String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        StringBuilder prompt = new StringBuilder();
        prompt.append(generateDomainSystemPrompt(request, systemMetadata).trim());
        prompt.append('\n').append(streamingInstructions(request));
        prompt.append(buildJsonSchemaSection(getJsonSchemaExample(request)));
        if (systemMetadata != null && !systemMetadata.isBlank()) {
            prompt.append('\n').append(contextHeading(request)).append('\n').append(systemMetadata).append('\n');
        }
        return prompt.toString();
    }

    /**
     * Generates the domain-specific system prompt, without the streaming instructions, the schema or the markers.
     *
     * @param request        the AI request containing domain context
     * @param systemMetadata system metadata for additional context
     * @return the domain-specific system prompt content
     */
    protected abstract String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata);

    /**
     * The streaming instructions that follow the domain prompt: the protocol of the answer (natural language first,
     * then the JSON between the markers), the JSON output rules and the sentence that introduces the schema, with
     * {@link StreamingProtocol#JSON_START_MARKER} and {@link StreamingProtocol#JSON_END_MARKER} in place. It ends on a
     * line break.
     *
     * @param request the AI request
     * @return the streaming instructions
     */
    protected abstract String streamingInstructions(AIRequest<? extends DomainContext> request);

    /**
     * The heading of the host's context information at the end of the system prompt.
     *
     * @param request the AI request
     * @return the heading line
     */
    protected abstract String contextHeading(AIRequest<? extends DomainContext> request);

    /**
     * Returns the JSON schema example for the expected output, without the markers.
     * <p>
     * Note: If {@link #getOutputConverter()} returns a non-null converter, this method's return value is ignored and
     * the converter's format is used instead.
     * </p>
     *
     * @param request the AI request
     * @return the JSON schema example as a string (without markers)
     */
    protected abstract String getJsonSchemaExample(AIRequest<? extends DomainContext> request);

    /**
     * Returns an optional BeanOutputConverter for type-safe JSON schema generation.
     *
     * @return the output converter, or null to use {@link #getJsonSchemaExample(AIRequest)}
     */
    protected BeanOutputConverter<?> getOutputConverter() {
        return null;
    }

    @Override
    public abstract TemplateType getSupportedType();

    @Override
    public abstract String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo);

    /** The JSON schema between the markers, after a blank line. */
    private String buildJsonSchemaSection(String jsonSchema) {
        BeanOutputConverter<?> converter = getOutputConverter();
        String schema = (converter != null) ? converter.getFormat() : jsonSchema;
        return "\n" + StreamingProtocol.JSON_START_MARKER + "\n" + schema.trim() + "\n"
                + StreamingProtocol.JSON_END_MARKER + "\n";
    }
}
