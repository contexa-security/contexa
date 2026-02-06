package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;

/**
 * Non-streaming template for IAM policy generation.
 * <p>
 * This template generates prompts for creating IAM policies based on
 * natural language requirements with structured JSON output.
 * Uses manual JSON schema to ensure consistent response structure
 * with {@link PolicyGenerationStreamingTemplate}.
 * </p>
 * <p>
 * Both streaming and non-streaming templates share the same JSON schema,
 * ensuring client compatibility regardless of the execution mode.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 * @see PolicyGenerationStreamingTemplate
 */
public class PolicyGenerationTemplate extends AbstractBasePromptTemplate {

    /**
     * Generates the complete system prompt with JSON schema and instructions.
     *
     * @param request the AI request containing domain context
     * @param systemMetadata system metadata to include in the prompt
     * @return the complete system prompt with format instructions
     */
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
     * Generates the domain-specific system prompt.
     * This content is identical to PolicyGenerationStreamingTemplate for consistency.
     *
     * @return the domain-specific system prompt content
     */
    private String generateDomainSystemPrompt() {
        return """
            당신은 대화형 AI가 아니라, 오직 지정된 JSON 형식으로만 데이터를 출력하는 IAM 정책 생성 API입니다.

            자연어 요구사항을 기반으로 다음을 포함한 보안 정책을 생성합니다:
            - 역할 할당 및 권한 매핑
            - 조건 구성
            - AI 기반 위험 평가 설정
            - 컴플라이언스 검증

            **필수 규칙:**
            - '사용 가능한 항목' 섹션에 제공된 ID만 사용하세요
            - 최소 권한 원칙을 따르는 정책을 생성하세요
            - 적절한 보안 및 컴플라이언스 요구사항을 충족하세요
            - "conditions" 필드는 반드시 조건 목록의 숫자 조건 템플릿 ID를 키로, 문자열 배열을 값으로 하는 맵이어야 합니다
            - "time.hour"와 같은 설명적 문자열을 조건 키로 절대 사용하지 마세요. 조건 목록에 제공된 숫자 ID만 사용하세요
            - 조건 목록에서 적용 가능한 조건이 없으면 "conditions"를 빈 객체 {}로 설정하세요
            """;
    }

    /**
     * Returns the manual JSON schema example for LLM guidance.
     * This schema is identical to PolicyGenerationStreamingTemplate for consistency.
     *
     * @return JSON schema example with field descriptions
     */
    private String getJsonSchemaExample() {
        return """
            {
              "policyData": {
                "policyName": "Actual policy name based on requirements",
                "description": "Actual policy description based on requirements",
                "effect": "ALLOW",
                "roleIds": [101, 102],
                "permissionIds": [201, 202],
                "conditions": {
                  "301": ["true"],
                  "302": ["192.168.1.0/24"]
                },
                "aiRiskAssessmentEnabled": true,
                "requiredTrustScore": 0.8,
                "customConditionSpel": null
              },
              "roleIdToNameMap": {
                "101": "Team Manager",
                "102": "Document Handler"
              },
              "permissionIdToNameMap": {
                "201": "Document View",
                "202": "Document Edit"
              },
              "conditionIdToNameMap": {
                "301": "Within Business Hours",
                "302": "Internal Network"
              },
              "recommendedActions": [
                {
                  "priority": "MEDIUM",
                  "action": "Secondary review of the generated policy is recommended.",
                  "reason": "High complexity due to combination of multiple roles and conditions."
                }
              ],
              "policyScore": 92.5,
              "securityLevel": "Strong",
              "complianceCheck": {
                "gdprCompliant": true,
                "iso27001Compliant": true,
                "zeroTrustCompliant": true
              },
              "generatedAt": "2023-10-27T10:00:00Z",
              "version": "1.0.0"
            }
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("PolicyGeneration");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalQuery = extractNaturalQueryFromRequest(request);
        PolicyGenerationItem.AvailableItems availableItems = extractAvailableItems(request);
        String iamDataContext = extractContextInfo(request, contextInfo);

        return buildUserPrompt(naturalQuery, availableItems, iamDataContext);
    }

    /**
     * Builds the user prompt with query, available items, and data context.
     *
     * @param naturalQuery the natural language query
     * @param availableItems the available roles, permissions, and conditions
     * @param contextInfo the IAM data context
     * @return the formatted user prompt
     */
    private String buildUserPrompt(String naturalQuery,
                                   PolicyGenerationItem.AvailableItems availableItems,
                                   String contextInfo) {
        return String.format("""
            [자연어 요구사항]
            %s

            [사용 가능한 항목]
            %s

            [Data]
            %s

            완전한 PolicyResponse를 JSON 형식으로 생성하세요.
            """, naturalQuery, formatAvailableItems(availableItems), contextInfo);
    }

    /**
     * Extracts the natural language query from the request.
     * <p>
     * This method provides PolicyGeneration-specific extraction logic,
     * falling back to default values when no query is found.
     * </p>
     *
     * @param request the AI request
     * @return the natural language query or a default message
     */
    private String extractNaturalQueryFromRequest(AIRequest<? extends DomainContext> request) {
        String naturalQuery = extractNaturalQuery(request);

        if (naturalQuery != null && !naturalQuery.equals("Natural language query was not provided")) {
            return naturalQuery;
        }

        return "자연어 요구사항이 제공되지 않았습니다";
    }

    /**
     * Extracts the available items from the request.
     *
     * @param request the AI request
     * @return the available items for policy generation
     */
    private PolicyGenerationItem.AvailableItems extractAvailableItems(AIRequest<? extends DomainContext> request) {
        return request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);
    }

    /**
     * Formats the available items for display in the prompt.
     * This logic is identical to PolicyGenerationStreamingTemplate for consistency.
     *
     * @param availableItems the available items to format
     * @return the formatted string representation
     */
    private String formatAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        if (availableItems == null) {
            return "사용 가능한 항목 정보가 제공되지 않았습니다.";
        }
        StringBuilder info = new StringBuilder();
        if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
            info.append("**역할 목록:**\n");
            availableItems.roles().forEach(role ->
                    info.append(String.format("- %s (ID: %d)\n", role.name(), role.id())));
        }
        if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
            info.append("\n**권한 목록:**\n");
            availableItems.permissions().forEach(permission ->
                    info.append(String.format("- %s (ID: %d)\n", permission.name(), permission.id())));
        }
        if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
            info.append("\n**조건 목록 (\"conditions\" 필드의 키로 반드시 이 숫자 ID만 사용하세요):**\n");
            availableItems.conditions().forEach(condition ->
                    info.append(String.format("- ID: %d, Name: %s\n", condition.id(), condition.name())));
        }
        return !info.isEmpty() ? info.toString() : "사용 가능한 항목이 없습니다.";
    }
}
