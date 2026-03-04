package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import org.springframework.ai.converter.BeanOutputConverter;

/**
 * Abstract base class for all streaming prompt templates.
 * <p>
 * This class extends {@link AbstractBasePromptTemplate} and enforces the
 * streaming protocol by automatically including the required marker protocol
 * prompts in the system prompt. Subclasses only need to implement
 * domain-specific prompts and JSON schema examples.
 * </p>
 * <p>
 * All streaming templates MUST use the JSON_DELIMITER strategy with
 * {@code ===JSON_START===} and {@code ===JSON_END===} markers.
 * </p>
 * <p>
 * Inherited utilities from {@link AbstractBasePromptTemplate}:
 * <ul>
 *   <li>{@code extractNaturalQuery()} - Extract natural language queries</li>
 *   <li>{@code extractIamDataContext()} - Extract IAM data context</li>
 *   <li>{@code isContextType()} - Check context type</li>
 * </ul>
 * </p>
 *
 * @see AbstractBasePromptTemplate
 * @see StreamingProtocol
 */
public abstract class AbstractStreamingPromptTemplate extends AbstractBasePromptTemplate {

    /**
     * Generates the complete system prompt with streaming protocol.
     * <p>
     * This method is final and cannot be overridden by subclasses.
     * It automatically assembles:
     * <ol>
     *   <li>Domain-specific system prompt</li>
     *   <li>Streaming protocol instructions</li>
     *   <li>JSON output rules</li>
     *   <li>JSON schema example with markers</li>
     *   <li>Context information</li>
     * </ol>
     * </p>
     *
     * @param request the AI request containing domain context
     * @param systemMetadata system metadata to include in the prompt
     * @return the complete system prompt with protocol instructions
     */
    @Override
    public final String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String domainPrompt = generateDomainSystemPrompt(request, systemMetadata);
        String protocolPrompt = buildProtocolPrompt();
        String jsonSchemaSection = buildJsonSchemaSection(getJsonSchemaExample());
        String contextSection = buildContextSection(systemMetadata);

        return assembleSystemPrompt(domainPrompt, protocolPrompt, jsonSchemaSection, contextSection);
    }

    /**
     * Generates the domain-specific system prompt.
     * <p>
     * Subclasses must implement this method to provide their domain-specific
     * system prompt content. This should NOT include:
     * <ul>
     *   <li>Streaming protocol instructions</li>
     *   <li>JSON output rules</li>
     *   <li>JSON schema examples</li>
     *   <li>Marker instructions</li>
     * </ul>
     * These are automatically added by the abstract class.
     * </p>
     *
     * @param request the AI request containing domain context
     * @param systemMetadata system metadata for additional context
     * @return the domain-specific system prompt content
     */
    protected abstract String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata);

    /**
     * Returns the JSON schema example for the expected output.
     * <p>
     * Subclasses must implement this method to provide their domain-specific
     * JSON schema example. The example should be a valid JSON object without
     * any markers - markers are automatically added by the abstract class.
     * </p>
     * <p>
     * Note: If {@link #getOutputConverter()} returns a non-null converter,
     * this method's return value is ignored and the converter's format is used instead.
     * </p>
     *
     * @return the JSON schema example as a string (without markers)
     */
    protected abstract String getJsonSchemaExample();

    /**
     * Returns the BeanOutputConverter for automatic JSON schema generation.
     * <p>
     * When this method returns a non-null converter, its {@code getFormat()} output
     * is used instead of {@link #getJsonSchemaExample()}. This ensures consistency
     * between streaming and non-streaming templates that share the same response type.
     * </p>
     * <p>
     * Default implementation returns null to maintain backward compatibility
     * with existing subclasses that use {@link #getJsonSchemaExample()}.
     * </p>
     *
     * @return the BeanOutputConverter instance, or null to use getJsonSchemaExample()
     */
    protected BeanOutputConverter<?> getOutputConverter() {
        return null;
    }

    /**
     * Returns the template type identifier.
     *
     * @return the template type for this streaming template
     */
    @Override
    public abstract TemplateType getSupportedType();

    /**
     * Generates the user prompt for the AI request.
     * <p>
     * Subclasses must implement this method to provide their domain-specific
     * user prompt. The user prompt should include:
     * <ul>
     *   <li>The specific query or request details</li>
     *   <li>Any context information relevant to the domain</li>
     *   <li>Instructions for the analysis process</li>
     *   <li>Reminder about JSON output requirements</li>
     * </ul>
     * </p>
     *
     * @param request the AI request containing domain context
     * @param contextInfo additional context information
     * @return the domain-specific user prompt
     */
    @Override
    public abstract String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo);

    /**
     * Builds the streaming protocol instructions prompt.
     * <p>
     * This method constructs the standardized protocol instructions that
     * explain the two-phase streaming process (natural language analysis
     * followed by JSON output).
     * </p>
     *
     * @return the protocol instructions prompt
     */
    private String buildProtocolPrompt() {
        return String.format("""

            **Unified Mode - Streaming Analysis Process + Final JSON Result**

            **[Absolute Language Rules]**
            - All natural language text must be written in Korean (Hangul) only.
            - Never use Chinese characters, Chinese, or Japanese.
            - English is allowed only for technical terms (e.g., API, JSON, URL).

            **[Phase 1] Real-time Streaming of Natural Language Analysis:**
            - Explain the analysis process step by step in **Korean (Hangul)**.
            - In this phase, never output JSON format or code blocks.

            **[Phase 2] Final JSON Data Output:**
            - Once all analysis is complete, output a pure JSON object between the "%s" marker and the "%s" marker.
            - The JSON object must start with `{` and end with `}`.
            """,
            StreamingProtocol.JSON_START_MARKER,
            StreamingProtocol.JSON_END_MARKER);
    }

    /**
     * Builds the JSON output rules section.
     * <p>
     * This method constructs the comprehensive rules for JSON output
     * that must be strictly followed by the LLM.
     * </p>
     *
     * @return the JSON output rules prompt
     */
    private String buildJsonOutputRules() {
        return """

            **Absolute Rules for JSON Output (must be strictly followed):**
            1.  **No comments allowed:** Never include `//` or `/* */` style comments inside JSON.
            2.  **No markdown:** Do not wrap JSON data in markdown code blocks like `json`.
            3.  **No post-processing text:** After the last `}` character of the JSON object, never output any additional text such as line breaks, explanations, or summaries.
            4.  **Perfect structure:** Follow the JSON structure specified below exactly without omitting or adding a single field.
            5.  **Array format compliance:** Array fields must always be in array (`[]`) format. Output an empty array even if there is no content.
            6.  **Quotation marks:** All keys and string values must be wrapped in double quotes (`"`). Numbers and boolean values are exceptions.
            7.  **Comma rules are mandatory:**
                - Always put a comma (`,`) between objects in an array.
                - Always put a comma (`,`) between fields in an object.
                - If there is a next field after closing `]` of an array, always put a comma. Example: `"nodes": [...],` `"edges": [...]`
                - Do not put a comma after the last element.
            8.  **Array closing required:** All arrays must be closed with `]`. Opening and closing brackets must match like `"nodes": [...]`.
            9.  **JSON validation:** Always verify that the JSON syntax is valid before output. It must be parseable by `JSON.parse()`.
            """;
    }

    /**
     * Builds the JSON schema section with markers.
     * <p>
     * This method wraps the JSON schema with the required streaming protocol markers.
     * If a BeanOutputConverter is provided via {@link #getOutputConverter()},
     * its format is used instead of the provided jsonSchema parameter.
     * </p>
     *
     * @param jsonSchema the fallback JSON schema example (used when no converter is available)
     * @return the complete JSON schema section with markers
     */
    private String buildJsonSchemaSection(String jsonSchema) {
        BeanOutputConverter<?> converter = getOutputConverter();
        String schema = (converter != null) ? converter.getFormat() : jsonSchema;

        return String.format("""

            **Below is the complete JSON structure you must output. You must follow this structure exactly.**

            %s
            %s
            %s
            """,
            StreamingProtocol.JSON_START_MARKER,
            schema.trim(),
            StreamingProtocol.JSON_END_MARKER);
    }

    /**
     * Builds the context information section.
     * <p>
     * This method formats the system metadata as context information
     * for the LLM to use during analysis.
     * </p>
     *
     * @param systemMetadata the system metadata to include
     * @return the formatted context section
     */
    private String buildContextSection(String systemMetadata) {
        if (systemMetadata == null || systemMetadata.isBlank()) {
            return "";
        }
        return String.format("""

            **Context Information:**
            %s
            """, systemMetadata);
    }

    /**
     * Assembles all prompt components into the final system prompt.
     * <p>
     * This method combines all the individual prompt sections in the
     * correct order to create the complete system prompt.
     * </p>
     *
     * @param domainPrompt the domain-specific system prompt
     * @param protocolPrompt the streaming protocol instructions
     * @param jsonSchemaSection the JSON schema with markers
     * @param contextSection the context information section
     * @return the complete assembled system prompt
     */
    private String assembleSystemPrompt(String domainPrompt, String protocolPrompt,
                                        String jsonSchemaSection, String contextSection) {
        StringBuilder prompt = new StringBuilder();

        prompt.append(domainPrompt.trim());
        prompt.append(protocolPrompt);
        prompt.append(buildJsonOutputRules());
        prompt.append(jsonSchemaSection);

        if (!contextSection.isEmpty()) {
            prompt.append(contextSection);
        }

        return prompt.toString();
    }

    /**
     * Helper method to build user prompt execution instructions.
     * <p>
     * Subclasses can use this method to append standardized execution
     * instructions to their user prompts.
     * </p>
     *
     * @return the execution instructions for user prompts
     */
    protected String buildUserPromptExecutionInstructions() {
        return String.format("""

            **Important Execution Instructions (must be strictly followed):**
            1.  First, explain the analysis process step by step in **Korean (Hangul)**. (Absolutely no JSON format, no Chinese characters/Chinese)
            2.  Once all analysis is complete, start with the %s marker, output JSON data, and end with the %s marker.

            **[Important] JSON output is mandatory. Ending a response without JSON output is considered a failure.**

            **Begin natural language analysis in Korean (Hangul) now, and output JSON results when analysis is complete:**
            """,
            StreamingProtocol.JSON_START_MARKER,
            StreamingProtocol.JSON_END_MARKER);
    }
}
