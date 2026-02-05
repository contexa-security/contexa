package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.springframework.ai.converter.BeanOutputConverter;

/**
 * Abstract base class for non-streaming prompt templates with BeanOutputConverter support.
 * <p>
 * This class extends {@link AbstractBasePromptTemplate} and provides standardized
 * integration with Spring AI's {@link BeanOutputConverter} for automatic JSON schema
 * generation. This ensures response structure consistency across templates that share
 * the same response type.
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Automatic JSON schema generation via BeanOutputConverter</li>
 *   <li>Type-safe response class binding</li>
 *   <li>Consistent format instructions across templates</li>
 *   <li>Shared utilities from AbstractBasePromptTemplate</li>
 * </ul>
 * </p>
 * <p>
 * Usage example:
 * <pre>{@code
 * public class MyTemplate extends AbstractStandardPromptTemplate<MyResponse> {
 *
 *     public MyTemplate() {
 *         super(MyResponse.class);
 *     }
 *
 *     @Override
 *     protected String generateDomainSystemPrompt(AIRequest<?> request, String systemMetadata) {
 *         return "Your domain-specific system prompt...";
 *     }
 *
 *     @Override
 *     public TemplateType getSupportedType() {
 *         return new TemplateType("MyTemplate");
 *     }
 *
 *     @Override
 *     public String generateUserPrompt(AIRequest<?> request, String contextInfo) {
 *         return "Your user prompt...";
 *     }
 * }
 * }</pre>
 * </p>
 *
 * @param <T> the response type for this template
 * @see AbstractBasePromptTemplate
 * @see AbstractStreamingPromptTemplate
 * @see BeanOutputConverter
 */
public abstract class AbstractStandardPromptTemplate<T> extends AbstractBasePromptTemplate {

    private final BeanOutputConverter<T> converter;
    private final Class<T> responseType;

    /**
     * Creates a new AbstractStandardPromptTemplate with the specified response type.
     *
     * @param responseType the class of the response type for JSON schema generation
     */
    protected AbstractStandardPromptTemplate(Class<T> responseType) {
        this.responseType = responseType;
        this.converter = new BeanOutputConverter<>(responseType);
    }

    /**
     * Generates the complete system prompt with format instructions.
     * <p>
     * This method assembles:
     * <ol>
     *   <li>Domain-specific system prompt</li>
     *   <li>JSON format instructions from BeanOutputConverter</li>
     *   <li>System metadata context</li>
     * </ol>
     * </p>
     *
     * @param request the AI request containing domain context
     * @param systemMetadata system metadata to include in the prompt
     * @return the complete system prompt with format instructions
     */
    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String domainPrompt = generateDomainSystemPrompt(request, systemMetadata);
        String formatInstructions = getFormatInstructions();

        return assembleSystemPrompt(domainPrompt, formatInstructions, systemMetadata);
    }

    /**
     * Generates the domain-specific system prompt.
     * <p>
     * Subclasses must implement this method to provide their domain-specific
     * system prompt content. This should NOT include:
     * <ul>
     *   <li>JSON format instructions (added automatically)</li>
     *   <li>System metadata (added automatically)</li>
     * </ul>
     * </p>
     *
     * @param request the AI request containing domain context
     * @param systemMetadata system metadata for additional context
     * @return the domain-specific system prompt content
     */
    protected abstract String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata);

    /**
     * Returns the template type identifier.
     *
     * @return the template type for this standard template
     */
    @Override
    public abstract TemplateType getSupportedType();

    /**
     * Generates the user prompt for the AI request.
     * <p>
     * Subclasses must implement this method to provide their domain-specific
     * user prompt. Consider using {@link #appendFormatInstructions(String)}
     * to include JSON format instructions in the user prompt.
     * </p>
     *
     * @param request the AI request containing domain context
     * @param contextInfo additional context information
     * @return the domain-specific user prompt
     */
    @Override
    public abstract String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo);

    /**
     * Returns the BeanOutputConverter for this template.
     * <p>
     * The converter can be used to:
     * <ul>
     *   <li>Get format instructions via {@code getFormat()}</li>
     *   <li>Parse responses via {@code convert()}</li>
     * </ul>
     * </p>
     *
     * @return the BeanOutputConverter instance
     */
    public BeanOutputConverter<T> getConverter() {
        return converter;
    }

    /**
     * Returns the response type class for this template.
     *
     * @return the response type class
     */
    public Class<T> getResponseType() {
        return responseType;
    }

    /**
     * Returns the JSON format instructions from the BeanOutputConverter.
     * <p>
     * This includes the JSON schema generated from the response type class,
     * which ensures consistency with streaming templates using the same
     * response type.
     * </p>
     *
     * @return the JSON format instructions
     */
    protected String getFormatInstructions() {
        return converter.getFormat();
    }

    /**
     * Appends format instructions to the given prompt.
     * <p>
     * Convenience method for adding format instructions to user prompts.
     * </p>
     *
     * @param prompt the base prompt
     * @return the prompt with format instructions appended
     */
    protected String appendFormatInstructions(String prompt) {
        return prompt + "\n\n" + getFormatInstructions();
    }

    /**
     * Returns the AI generation type class.
     * <p>
     * This method returns the response type class, which can be used
     * by the AI processing pipeline for type-safe response handling.
     * </p>
     *
     * @return the response type class
     */
    @Override
    public Class<?> getAIGenerationType() {
        return responseType;
    }

    /**
     * Assembles all prompt components into the final system prompt.
     *
     * @param domainPrompt the domain-specific system prompt
     * @param formatInstructions the JSON format instructions
     * @param systemMetadata the system metadata
     * @return the complete assembled system prompt
     */
    private String assembleSystemPrompt(String domainPrompt, String formatInstructions, String systemMetadata) {
        StringBuilder prompt = new StringBuilder();

        prompt.append(domainPrompt.trim());

        if (formatInstructions != null && !formatInstructions.isBlank()) {
            prompt.append("\n\n");
            prompt.append("<output_format>\n");
            prompt.append(formatInstructions);
            prompt.append("\n</output_format>");
        }

        if (systemMetadata != null && !systemMetadata.isBlank()) {
            prompt.append("\n\n");
            prompt.append("<context>\n");
            prompt.append(systemMetadata);
            prompt.append("\n</context>");
        }

        return prompt.toString();
    }
}
