package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

@Slf4j
public class ConditionTemplatePromptTemplate extends AbstractBasePromptTemplate {

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("ConditionTemplate");
    }

    @Override
    public Class<?> getAIGenerationType() {
        return Map.class;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String templateType = extractTemplateType(request);
        String domainPrompt = "specific".equals(templateType)
                ? generateSpecificDomainSystemPrompt()
                : generateUniversalDomainSystemPrompt();
        String jsonSchema = "specific".equals(templateType)
                ? getSpecificJsonSchemaExample()
                : getUniversalJsonSchemaExample();

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

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String templateType = extractTemplateType(request);
        if ("specific".equals(templateType)) {
            List<String> methodSignatures = request.getParameter("methodSignatures", List.class);
            if (methodSignatures != null && !methodSignatures.isEmpty()) {
                return buildBatchSpecificUserPrompt(methodSignatures, contextInfo);
            }
            String methodSignature = contextInfo != null ? contextInfo : "";
            return buildSingleSpecificUserPrompt(methodSignature);
        }
        return buildUniversalUserPrompt();
    }

    private String extractTemplateType(AIRequest<? extends DomainContext> request) {
        if (isContextType(request, ConditionTemplateContext.class)) {
            ConditionTemplateContext context = (ConditionTemplateContext) request.getContext();
            return context.getTemplateType();
        }
        String type = request.getParameter("templateType", String.class);
        return type != null ? type : "universal";
    }

    // =========================================================================
    // Universal condition prompt methods
    // =========================================================================

    private String generateUniversalDomainSystemPrompt() {
        return """
            당신은 재사용 가능한 접근 제어 조건을 생성하는 ABAC 범용 조건 생성 전문 AI입니다.

            중요: 응답은 반드시 순수 JSON 형식이어야 합니다.
            언어: 모든 이름과 설명은 반드시 한국어로 작성하세요.

            **생성할 범용 조건 (정확히 3개만):**
            1. isAuthenticated() - 사용자 인증 상태 확인
            2. hasRole('ROLE_ADMIN') - 관리자 역할 확인
            3. 업무시간 접근 제한 (9시-18시)

            **주의사항:**
            - "~권한" 용어 사용 금지. "~상태 확인", "~역할 확인", "~접근 제한" 용어 사용
            - 정확히 3개만 생성
            - hasPermission() 사용 금지 (범용 조건에서는 금지)

            **출력 형식:**
            JSON 객체를 반환하세요. 키는 조건의 식별자(영문), 값은 조건 정보 객체입니다.
            각 조건 정보에 포함되어야 하는 항목:
            - name: "권한" 단어를 사용하지 않는 한국어 이름
            - description: 명확한 한국어 설명
            - spelTemplate: 파라미터 없는 SpEL 표현식
            - category: 한국어 카테고리
            - classification: "UNIVERSAL"
            """;
    }

    private String getUniversalJsonSchemaExample() {
        return """
            {
              "isAuthenticated": {
                "name": "사용자 인증 상태 확인",
                "description": "사용자 인증 상태를 확인하는 조건",
                "spelTemplate": "isAuthenticated()",
                "category": "인증 상태",
                "classification": "UNIVERSAL"
              },
              "hasRole_ADMIN": {
                "name": "관리자 역할 확인",
                "description": "관리자 역할을 가진 사용자인지 확인하는 조건",
                "spelTemplate": "hasRole('ROLE_ADMIN')",
                "category": "역할 상태",
                "classification": "UNIVERSAL"
              },
              "workingHours": {
                "name": "업무시간 접근 제한",
                "description": "업무시간(9시~18시) 내에만 접근을 허용하는 조건",
                "spelTemplate": "T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18",
                "category": "시간 제한",
                "classification": "UNIVERSAL"
              }
            }
            """;
    }

    private String buildUniversalUserPrompt() {
        return """
            정확히 3개의 범용 조건만 생성하세요:

            1. 사용자 인증 상태 확인 - isAuthenticated()
            2. 관리자 역할 확인 - hasRole('ROLE_ADMIN')
            3. 업무시간 접근 제한 - T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18

            절대 금지:
            - 4개 이상 생성
            - hasPermission() 사용 (범용 조건에서는 금지)
            - 존재하지 않는 파라미터 사용
            - 설명 텍스트 출력
            - ```json 코드블록
            - "물론입니다", "아래는" 같은 서두

            출력 시 포함 사항:
            - 정확히 3개의 범용 조건 (키: 조건 식별자, 값: 조건 정보 객체)
            - 모든 텍스트는 한국어로
            - "권한" 단어 절대 사용 금지

            JSON 형식으로 생성하세요.
            """;
    }

    // =========================================================================
    // Specific condition prompt methods
    // =========================================================================

    private String generateSpecificDomainSystemPrompt() {
        return """
            당신은 Java 메서드 시그니처를 분석하여 ABAC(속성 기반 접근 제어)용 SpEL 기반 hasPermission 조건을 생성하는 전문 AI입니다.

            중요: 응답은 반드시 순수 JSON 형식이어야 합니다.
            필수: 입력된 모든 메서드에 대해 예외 없이 응답해야 합니다.
            언어: 이름과 설명은 반드시 한국어로 작성하세요.

                    <rules>
                    1.  **입력 패턴에 따른 `hasPermission` 함수 생성 규칙:**
                        * **ID 파라미터 (예: `Long id`, `Long userId`):** `hasPermission(#파라미터명, '리소스종류', '액션')` 형식으로 3개의 인자를 사용합니다.
                        * **객체 파라미터 (예: `Group group`, `UserDto userDto`):** `hasPermission(#파라미터명, '리소스종류_액션')` 형식으로 2개의 인자를 사용합니다.
                    2.  `name` 필드는 "리소스종류 ~ 대상 검증/접근 확인" 형식으로 작성합니다. "권한" 단어는 절대 사용하지 마세요.
                    3.  입력이 "파라미터가 없는 메서드"인 경우, 해당 키의 값에 빈 조건을 반환합니다.
                    4.  #p0, #p1 등 positional index 참조는 절대 사용하지 마세요. 반드시 메서드 시그니처에서 파라미터명을 추출하여 사용하세요.
                        올바른 예: hasPermission(#id, 'GROUP', 'READ'), hasPermission(#role, 'ROLE_CREATE')
                        잘못된 예: hasPermission(#p0, 'GROUP', 'READ')
                    </rules>

                    <examples>
                    <!-- ID 파라미터 예시 -->
                    <example>
                      <input>getGroup(Long id)</input>
                      <output_key>"getGroup(Long id)"</output_key>
                      <output_value>
                      {
                        "name": "그룹 조회 접근 확인",
                        "description": "특정 ID의 그룹에 대한 READ 접근을 확인하는 조건",
                        "spelTemplate": "hasPermission(#id, 'GROUP', 'READ')",
                        "category": "접근 확인",
                        "classification": "CONTEXT_DEPENDENT"
                      }
                      </output_value>
                    </example>

                    <!-- 객체 파라미터 예시 -->
                    <example>
                      <input>createGroup(Group group)</input>
                      <output_key>"createGroup(Group group)"</output_key>
                      <output_value>
                      {
                        "name": "그룹 생성 대상 검증",
                        "description": "생성하려는 그룹에 대한 GROUP_CREATE 접근을 검증하는 조건",
                        "spelTemplate": "hasPermission(#group, 'GROUP_CREATE')",
                        "category": "대상 검증",
                        "classification": "CONTEXT_DEPENDENT"
                      }
                      </output_value>
                    </example>
                    </examples>

            **출력 형식:**
            JSON 객체를 반환하세요. 키는 메서드 시그니처(원문 그대로), 값은 조건 정보 객체입니다.

            절대 규칙 (위반 시 시스템 오류):
            1. 입력 메서드의 100%를 처리하세요 - 예외 없음
            2. 입력 항목 수와 출력 항목 수가 정확히 일치해야 합니다
            3. 각 항목에 반드시 name, description, spelTemplate, category, classification을 모두 포함해야 합니다
            4. 출력에서 입력 순서를 유지하세요

            각 조건 정보에 포함되어야 하는 항목:
            - name: "권한" 단어를 사용하지 않는 한국어 이름
            - description: 명확한 한국어 설명
            - spelTemplate: hasPermission을 사용하는 SpEL 표현식
            - category: 한국어 카테고리 ("접근 확인" 또는 "대상 검증")
            - classification: "CONTEXT_DEPENDENT"
            """;
    }

    private String getSpecificJsonSchemaExample() {
        return """
            {
              "getGroup(Long id)": {
                "name": "그룹 조회 접근 확인",
                "description": "특정 ID의 그룹에 대한 READ 접근을 확인하는 조건",
                "spelTemplate": "hasPermission(#id, 'GROUP', 'READ')",
                "category": "접근 확인",
                "classification": "CONTEXT_DEPENDENT"
              },
              "createGroup(Group group)": {
                "name": "그룹 생성 대상 검증",
                "description": "생성하려는 그룹에 대한 GROUP_CREATE 접근을 검증하는 조건",
                "spelTemplate": "hasPermission(#group, 'GROUP_CREATE')",
                "category": "대상 검증",
                "classification": "CONTEXT_DEPENDENT"
              }
            }
            """;
    }

    private String buildBatchSpecificUserPrompt(List<String> methodSignatures, String contextInfo) {
        StringBuilder prompt = new StringBuilder();

        if (contextInfo != null && !contextInfo.trim().isEmpty()) {
            prompt.append("**참고 컨텍스트:**\n")
                     .append(contextInfo)
                     .append("\n\n");
        }

        prompt.append("**필수 요구사항:** 다음 **정확히 ")
              .append(methodSignatures.size())
              .append("개** 메서드 시그니처에 대해 **모두 예외 없이** hasPermission 조건을 생성하세요!\n\n");
        prompt.append("**중요:** ")
              .append(methodSignatures.size())
              .append("개 입력 -> ")
              .append(methodSignatures.size())
              .append("개 출력이 되어야 합니다. 누락 시 시스템 오류!\n\n");

        IntStream.range(0, methodSignatures.size())
                .forEach(i -> prompt.append(i + 1)
                        .append(". ")
                        .append(methodSignatures.get(i))
                        .append("\n"));

        prompt.append("\n생성 규칙:\n");
        prompt.append("- ID 파라미터: hasPermission(#파라미터명, '리소스종류', '액션')\n");
        prompt.append("- 객체 파라미터: hasPermission(#파라미터명, '리소스종류_액션')\n");
        prompt.append("- 파라미터 없음: spelTemplate을 빈 문자열로 설정\n");
        prompt.append("- #p0, #p1 등 positional index 절대 금지. 반드시 실제 파라미터명(#id, #group 등)을 사용하세요\n\n");

        prompt.append("중요 사항:\n");
        prompt.append("- 이름과 설명은 한국어로 작성하세요\n");
        prompt.append("- 이름에 \"권한\" 단어를 절대 사용하지 마세요\n\n");

        prompt.append("**다시 한번 확인:** 위의 **모든 ")
              .append(methodSignatures.size())
              .append("개 항목**에 대해 name, description, spelTemplate, category, classification을 제공하세요!");

        return prompt.toString();
    }

    private String buildSingleSpecificUserPrompt(String methodSignature) {
        return String.format("""
            다음 Java 메서드 시그니처를 분석하고 특정 조건 템플릿을 생성하세요:

            메서드 시그니처:
            %s

            생성 규칙:
            - ID 파라미터: hasPermission(#파라미터명, '리소스종류', '액션')
            - 객체 파라미터: hasPermission(#파라미터명, '리소스종류_액션')
            - 파라미터 없음: spelTemplate을 빈 문자열로 설정
            - #p0, #p1 등 positional index 절대 금지. 반드시 실제 파라미터명(#id, #group 등)을 사용하세요

            중요 사항:
            - 이름과 설명은 한국어로 작성하세요
            - 이름에 "권한" 단어를 절대 사용하지 마세요
            - 키는 반드시 메서드 시그니처 원문 그대로 사용하세요

            JSON 형식으로 생성하세요.
            """, methodSignature);
    }
}
