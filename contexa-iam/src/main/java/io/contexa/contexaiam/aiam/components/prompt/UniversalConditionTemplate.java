package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;

/**
 * Non-streaming template for universal condition template generation.
 * <p>
 * This template generates prompts for creating reusable ABAC universal
 * conditions (isAuthenticated, hasRole, business hours). It produces
 * exactly 3 universal conditions with structured JSON output.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 */
public class UniversalConditionTemplate extends AbstractBasePromptTemplate {

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("UniversalCondition");
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
     * Generates the domain-specific system prompt for universal condition generation.
     *
     * @return the domain-specific system prompt content
     */
    private String generateDomainSystemPrompt() {
        return """
            당신은 재사용 가능한 접근 제어 조건을 생성하는 ABAC 범용 조건 생성 전문 AI입니다.

            중요: 응답은 반드시 ConditionTemplateGenerationResponse 스키마와 일치하는 순수 JSON 형식이어야 합니다.
            언어: 모든 이름과 설명은 반드시 한국어로 작성하세요.

            **필수 JSON 응답 형식:**
            [
              {
                "name": "사용자 인증 상태 확인",
                "description": "사용자 인증 상태를 확인하는 조건",
                "spelTemplate": "isAuthenticated()",
                "category": "인증 상태",
                "classification": "UNIVERSAL"
              }
            ]

            **생성할 범용 조건 (정확히 3개만):**
            1. isAuthenticated() - 사용자 인증 상태 확인
            2. hasRole('ROLE_ADMIN') - 관리자 역할 확인
            3. 업무시간 접근 제한 (9시-18시)

            **주의사항:**
            - "~권한" 용어 사용 금지 (시스템 크래시!)
            - "~상태 확인", "~역할 확인", "~접근 제한" 용어 사용
            - 정확히 3개만 생성

            올바른 범용 네이밍 예시:
            - "사용자 인증 상태 확인" <- 올바름
            - "관리자 역할 확인" <- 올바름
            - "업무시간 접근 제한" <- 올바름

            필수 출력:
            - templateResult: 정확히 3개의 범용 조건 템플릿을 포함하는 JSON 문자열
            - templateType: 이 템플릿 유형은 "universal"
            - resourceIdentifier: null (범용 조건에는 해당 없음)
            - processingMetadata: 생성 프로세스에 대한 메타데이터

            templateResult 내 각 템플릿에 포함되어야 하는 항목:
            - name: "권한" 단어를 사용하지 않는 한국어 이름
            - description: 명확한 한국어 설명
            - spelTemplate: 파라미터 없는 SpEL 표현식
            - category: 한국어 카테고리
            - classification: "UNIVERSAL"
            """;
    }

    /**
     * Returns the manual JSON schema example for ConditionTemplateGenerationResponse.
     *
     * @return JSON schema example with field descriptions
     */
    private String getJsonSchemaExample() {
        return """
            {
              "templateResult": "[{\\"name\\": \\"사용자 인증 상태 확인\\", \\"description\\": \\"사용자 인증 상태를 확인하는 조건\\", \\"spelTemplate\\": \\"isAuthenticated()\\", \\"category\\": \\"인증 상태\\", \\"classification\\": \\"UNIVERSAL\\"}]",
              "templateType": "universal",
              "resourceIdentifier": null,
              "processingMetadata": {
                "generatedAt": 1698400000000
              }
            }
            """;
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        return buildUserPrompt();
    }

    /**
     * Builds the user prompt for universal condition generation.
     *
     * @return the formatted user prompt
     */
    private String buildUserPrompt() {
        return """
            정확히 3개의 범용 조건만 생성하세요:

            1. 사용자 인증 상태 확인 - isAuthenticated()
            2. 관리자 역할 확인 - hasRole('ROLE_ADMIN')
            3. 업무시간 접근 제한 - T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18

            절대 금지:
            - 4개 이상 생성
            - hasPermission() 사용 (범용 조건에서는 금지)
            - 존재하지 않는 파라미터 사용

            **절대적 출력 제약:**
            - 반드시 JSON 배열만 출력하세요
            - 설명 텍스트 절대 금지
            - ```json 코드블록 절대 금지
            - "물론입니다", "아래는" 같은 서두 절대 금지

            ConditionTemplateGenerationResponse 생성 시 포함 사항:
            - templateResult에 정확히 3개의 범용 조건
            - templateType: "universal"
            - 모든 텍스트는 한국어로
            - "권한" 단어 절대 사용 금지
            - 범용 조건에서 hasPermission() 절대 사용 금지

            완전한 ConditionTemplateGenerationResponse를 JSON 형식으로 생성하세요.
            """;
    }
}
