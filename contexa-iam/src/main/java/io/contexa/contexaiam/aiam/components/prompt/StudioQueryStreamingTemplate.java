package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractStreamingPromptTemplate;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

/**
 * Streaming template for IAM Studio query analysis.
 * <p>
 * This template generates prompts for analyzing IAM permission queries
 * with real-time streaming feedback and structured JSON output.
 * </p>
 */
@Slf4j
public class StudioQueryStreamingTemplate extends AbstractStreamingPromptTemplate {

    private final BeanOutputConverter<StudioQueryResponse> converter =
            new BeanOutputConverter<>(StudioQueryResponse.class);

    @Override
    protected BeanOutputConverter<?> getOutputConverter() {
        return converter;
    }

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 IAM 권한 분석 API입니다.

            사용자 권한 질의를 분석하여 다음을 포함한 종합 결과를 제공합니다:
            - 사용자 및 그룹의 권한 분석
            - 역할 및 권한 매핑
            - 그래프 표현을 위한 시각화 데이터
            - 실행 가능한 권장 사항

            **[필수] 반드시 준수**
            엣지의 source/target은 반드시 nodes 배열에 존재하는 노드 ID와 정확히 일치해야 함
            """;
    }

    /**
     * Returns an empty string as the JSON schema is now provided by BeanOutputConverter.
     * This method is retained for backward compatibility with AbstractStreamingPromptTemplate.
     *
     * @return empty string (schema is provided via getOutputConverter())
     */
    @Override
    protected String getJsonSchemaExample() {
        return "";
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("StudioQueryStreaming");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQuery(request, "자연어 질의가 제공되지 않았습니다");
        String actualContextInfo = extractIamDataContext(request, contextInfo);

        return buildUserPrompt(naturalQuery, actualContextInfo);
    }

    /**
     * Builds the user prompt with query details and execution instructions.
     *
     * @param query the natural language query
     * @param scope the analysis scope (IAM data context)
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String query, String scope) {
        return String.format("""
            **권한 분석 질의:**
            "%s"

            **분석 범위:**
            %s
            %s
            """, query, scope, buildUserPromptExecutionInstructions());
    }
}
