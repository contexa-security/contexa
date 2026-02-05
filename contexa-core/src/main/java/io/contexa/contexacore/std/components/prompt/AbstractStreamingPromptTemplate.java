package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;

/**
 * Abstract base class for all streaming prompt templates.
 * <p>
 * This class enforces the streaming protocol by automatically including
 * the required marker protocol prompts in the system prompt. Subclasses
 * only need to implement domain-specific prompts and JSON schema examples.
 * </p>
 * <p>
 * All streaming templates MUST use the JSON_DELIMITER strategy with
 * {@code ===JSON_START===} and {@code ===JSON_END===} markers.
 * </p>
 *
 * @see StreamingProtocol
 */
public abstract class AbstractStreamingPromptTemplate implements PromptTemplate {

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
     *
     * @return the JSON schema example as a string (without markers)
     */
    protected abstract String getJsonSchemaExample();

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

            **통합 모드 - 스트리밍 분석 과정 + 최종 JSON 결과**

            **[1단계] 자연어 분석 과정 실시간 스트리밍:**
            - 사용자의 요청을 분석하는 과정을 단계별로 **한국어**로 설명합니다.
            - 이 단계에서는 절대 JSON 형식이나 코드 블록을 출력해서는 안 됩니다.

            **[2단계] 최종 JSON 데이터 출력:**
            - 모든 분석이 완료되면, "%s" 마커와 "%s" 마커 사이에 순수한 JSON 객체를 출력해야 합니다.
            - JSON 객체는 반드시 `{`로 시작하여 `}`로 끝나야 합니다.
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

            **JSON 출력에 대한 절대 규칙 (반드시 준수할 것):**
            1.  **주석 절대 금지:** JSON 내부에 `//` 또는 `/* */` 형태의 주석을 절대로 포함하지 마세요.
            2.  **마크다운 금지:** JSON 데이터를 `json`과 같은 마크다운 코드 블록으로 감싸지 마세요.
            3.  **후처리 텍스트 금지:** JSON 객체의 마지막 `}` 문자 이후에는 어떠한 줄바꿈, 설명, 요약 등 추가 텍스트도 절대 출력하지 마세요.
            4.  **완벽한 구조:** 아래에 명시된 JSON 구조를 단 하나의 필드도 빠뜨리거나 추가하지 말고 완벽하게 따르세요.
            5.  **배열 형식 준수:** 배열 필드는 반드시 배열(`[]`) 형식이어야 합니다. 내용이 없더라도 빈 배열로 출력하세요.
            6.  **따옴표 주의:** 모든 키와 문자열 값은 큰따옴표(`"`)로 감싸야 합니다. 숫자 및 boolean 값은 예외입니다.
            7.  **쉼표 규칙 필수:**
                - 배열 내 객체들 사이에 반드시 쉼표(`,`)를 넣으세요.
                - 객체 내 필드들 사이에 반드시 쉼표(`,`)를 넣으세요.
                - 배열을 닫는 `]` 뒤에 다음 필드가 있으면 반드시 쉼표를 넣으세요. 예: `"nodes": [...],` `"edges": [...]`
                - 마지막 요소 뒤에는 쉼표를 넣지 마세요.
            8.  **배열 닫기 필수:** 모든 배열은 반드시 `]`로 닫아야 합니다. `"nodes": [...]`처럼 열고 닫는 괄호가 일치해야 합니다.
            9.  **JSON 검증:** 출력 전 JSON 구문이 유효한지 반드시 확인하세요. `JSON.parse()`로 파싱 가능해야 합니다.
            """;
    }

    /**
     * Builds the JSON schema section with markers.
     * <p>
     * This method wraps the provided JSON schema example with the
     * required streaming protocol markers.
     * </p>
     *
     * @param jsonSchema the JSON schema example to wrap
     * @return the complete JSON schema section with markers
     */
    private String buildJsonSchemaSection(String jsonSchema) {
        return String.format("""

            **아래는 당신이 출력해야 할 완벽한 JSON 구조입니다. 이 구조를 반드시 따르세요.**

            %s
            %s
            %s
            """,
            StreamingProtocol.JSON_START_MARKER,
            jsonSchema.trim(),
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

            **컨텍스트 정보:**
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

            **중요 실행 지시 (반드시 준수):**
            1.  먼저, 분석 과정을 **한국어**로 단계별로 설명합니다. (JSON 형식 절대 사용 금지)
            2.  모든 분석이 끝나면, 반드시 %s 마커로 시작하여 JSON 데이터를 출력하고 %s 마커로 종료합니다.

            **[중요] JSON 출력은 필수입니다. JSON 출력 없이 응답을 종료하면 실패로 간주됩니다.**

            **지금부터 한국어로 자연어 분석을 시작하고, 분석이 끝나면 반드시 JSON 결과를 출력하세요:**
            """,
            StreamingProtocol.JSON_START_MARKER,
            StreamingProtocol.JSON_END_MARKER);
    }
}
