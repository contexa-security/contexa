package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Non-streaming template for resource naming suggestion generation.
 * <p>
 * This template generates prompts for converting technical identifiers
 * into business-friendly Korean names and descriptions.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 */
@Slf4j
public class ResourceNamingTemplate extends AbstractBasePromptTemplate {

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("ResourceNaming");
    }

    @Override
    public Class<?> getAIGenerationType() {
        return Map.class;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String domainPrompt = generateDomainSystemPrompt();
        String jsonSchema = getJsonSchemaExample();

        StringBuilder prompt = new StringBuilder();
        prompt.append(domainPrompt.trim());
        prompt.append("\n\n");
        prompt.append("<output_format>\n");
        prompt.append("응답은 반드시 다음 스키마와 일치하는 유효한 JSON 객체여야 합니다:\n");
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

    /**
     * Generates the domain-specific system prompt for resource naming.
     *
     * @return the domain-specific system prompt content
     */
    private String generateDomainSystemPrompt() {
        return """
            당신은 기술적 식별자를 비즈니스 친화적인 한국어 이름과 설명으로 변환하는 리소스 네이밍 전문 AI입니다.

            중요: 응답은 반드시 순수 JSON 형식이어야 합니다.
            언어: 모든 이름과 설명은 반드시 한국어로 작성하세요.
            필수: 입력된 모든 항목에 대해 예외 없이 응답해야 합니다.

            절대 규칙 (위반 시 시스템 오류):
            1. 입력 항목의 100%를 처리하세요 - 예외 없음
            2. 입력 항목 수와 출력 항목 수가 정확히 일치해야 합니다
            3. 각 항목에 반드시 friendlyName과 description을 모두 포함해야 합니다
            4. 순수 JSON 형식만 허용 - 설명 텍스트 금지
            5. 명확하고 친화적인 한국어 이름과 설명을 사용하세요
            6. 출력에서 입력 순서를 유지하세요

            처리 규칙:
            - camelCase/snake_case -> 읽기 쉬운 한국어
            - URL 경로 -> 기능 이름 (예: /admin/users -> 사용자 관리)
            - 메서드명 -> 동작 설명 (예: updateUser -> 사용자 정보 수정)
            - CRUD 작업 -> 명확한 동사 (생성, 조회, 수정, 삭제)
            - API 엔드포인트 -> 설명적 기능 이름
            - 기술 용어 -> 비즈니스 친화적 용어

            대체 규칙:
            항목을 이해할 수 없는 경우:
            - friendlyName: "[항목명] 기능"
            - description: "AI 추천을 받지 못한 리소스입니다."
            - confidence: 0.3

            필수 출력:
            - suggestions: ResourceNamingSuggestion 객체 배열
            - failedIdentifiers: 처리하지 못한 식별자 배열
            - stats: 처리 통계 (항목 수, 소요 시간)

            각 제안에 포함되어야 하는 항목:
            - identifier: 원본 기술 식별자
            - friendlyName: 비즈니스 친화적 한국어 이름
            - description: 명확한 한국어 설명
            - confidence: AI 신뢰도 점수 (0.0-1.0)
            """;
    }

    /**
     * Returns the manual JSON schema example for resource naming response.
     *
     * @return JSON schema example with field descriptions
     */
    private String getJsonSchemaExample() {
        return """
            {
              "/admin/users": {
                "friendlyName": "사용자 관리",
                "description": "시스템 내 모든 사용자 계정을 조회하고 관리할 수 있는 인터페이스입니다."
              },
              "/api/groups": {
                "friendlyName": "그룹 API",
                "description": "사용자 그룹 정보를 생성, 조회, 수정, 삭제할 수 있는 API 엔드포인트입니다."
              }
            }
            """;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {

        List<String> identifiers = request.getParameter("identifiers", List.class);

        if (identifiers == null || identifiers.isEmpty()) {
            log.error("Resource list is empty");
            return "오류: 처리할 리소스가 없습니다";
        }

        return buildUserPromptFromIdentifiers(identifiers, contextInfo);
    }
    private String buildUserPromptFromIdentifiers(List<String> identifiers, String context) {
        StringBuilder userPrompt = new StringBuilder();

        if (context != null && !context.trim().isEmpty()) {
            userPrompt.append("**참고 컨텍스트:**\n")
                     .append(context)
                     .append("\n\n");
        }

        userPrompt.append("**필수 요구사항:** 다음 **정확히 ").append(identifiers.size()).append("개** 항목에 대해 **모두 예외 없이** 응답하세요!\n\n");
        userPrompt.append("**중요:** ").append(identifiers.size()).append("개 입력 -> ").append(identifiers.size()).append("개 출력이 되어야 합니다. 누락 시 시스템 오류!\n\n");

        IntStream.range(0, identifiers.size())
                .forEach(i -> {
                    userPrompt.append(i + 1)
                             .append(". ")
                             .append(identifiers.get(i))
                             .append("\n");
                });

        userPrompt.append("\n**다시 한번 확인:** 위의 **모든 ").append(identifiers.size()).append("개 항목**에 대해 friendlyName과 description을 제공하세요!");

        return userPrompt.toString();
    }
}
