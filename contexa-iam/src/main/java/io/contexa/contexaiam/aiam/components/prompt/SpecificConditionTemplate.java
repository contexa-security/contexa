package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
public class SpecificConditionTemplate implements PromptTemplate {

    private final BeanOutputConverter<ConditionTemplateGenerationResponse> converter = 
        new BeanOutputConverter<>(ConditionTemplateGenerationResponse.class);

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("SpecificCondition");
    }
    
    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            당신은 Java 메서드 시그니처를 분석하여 ABAC(속성 기반 접근 제어)용 SpEL 기반 hasPermission 조건을 생성하는 전문 AI입니다.

            중요: 응답은 반드시 ConditionTemplateGenerationResponse 스키마와 일치하는 순수 JSON 형식이어야 합니다.
            언어: 이름과 설명은 반드시 한국어로 작성하세요.

                    <rules>
                    1.  **입력 패턴에 따른 `hasPermission` 함수 생성 규칙:**
                        * **ID 파라미터 (예: `Long id`, `Long userId`):** `hasPermission(#파라미터명, '리소스종류', '액션')` 형식으로 3개의 인자를 사용합니다.
                        * **객체 파라미터 (예: `Group group`, `UserDto userDto`):** `hasPermission(#파라미터명, '리소스종류_액션')` 형식으로 2개의 인자를 사용합니다.
                    2.  `name` 필드는 "리소스종류 ~ 대상 검증/접근 확인" 형식으로 작성합니다. "권한" 단어는 절대 사용하지 마세요.
                    3.  입력이 "파라미터가 없는 메서드"인 경우, 빈 배열 `[]`을 반환합니다.
                    4.  응답은 JSON 배열 외에 어떤 텍스트도 포함해서는 안 됩니다.
                    </rules>

                    <examples>
                    <!-- ID 파라미터 예시 -->
                    <example>
                      <input>getGroup(Long id)</input>
                      <output>
                      [
                        {
                          "name": "그룹 조회 접근 확인",
                          "description": "특정 ID의 그룹에 대한 READ 접근을 확인하는 조건",
                          "spelTemplate": "hasPermission(#id, 'GROUP', 'READ')",
                          "category": "접근 확인",
                          "classification": "CONTEXT_DEPENDENT"
                        }
                      ]
                      </output>
                    </example>

                    <!-- 객체 파라미터 예시 -->
                    <example>
                      <input>createGroup(Group group)</input>
                      <output>
                      [
                        {
                          "name": "그룹 생성 대상 검증",
                          "description": "생성하려는 그룹에 대한 GROUP_CREATE 접근을 검증하는 조건",
                          "spelTemplate": "hasPermission(#group, 'GROUP_CREATE')",
                          "category": "대상 검증",
                          "classification": "CONTEXT_DEPENDENT"
                        }
                      ]
                      </output>
                    </example>
                    </examples>
                    
            %s

            필수 출력:
            - templateResult: 조건 템플릿 배열을 포함하는 JSON 문자열
            - templateType: 이 템플릿 유형은 "specific"
            - resourceIdentifier: 분석 대상 메서드 시그니처
            - processingMetadata: 생성 프로세스에 대한 메타데이터

            templateResult 내 각 템플릿에 포함되어야 하는 항목:
            - name: "권한" 단어를 사용하지 않는 한국어 이름
            - description: 명확한 한국어 설명
            - spelTemplate: hasPermission을 사용하는 SpEL 표현식
            - category: 한국어 카테고리 ("접근 확인" 또는 "대상 검증")
            - classification: "CONTEXT_DEPENDENT"

            %s
        """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }
    
    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String methodSignature = contextInfo != null ? contextInfo : "";
        
        String conditionRequest = String.format("""
            다음 Java 메서드 시그니처를 분석하고 특정 조건 템플릿을 생성하세요:

            메서드 시그니처:
            %s

            생성 요구사항:
            1. 메서드 시그니처를 분석하여 다음을 식별하세요:
               - 메서드명과 작업 유형
               - 파라미터 (ID 파라미터 vs 객체 파라미터)
               - 접근 대상 리소스 유형

            2. 다음 기준에 따라 hasPermission 조건을 생성하세요:
               - ID 파라미터: hasPermission(#파라미터명, '리소스종류', '액션')
               - 객체 파라미터: hasPermission(#파라미터명, '리소스종류_액션')
               - 파라미터 없음: 빈 배열 [] 반환

            3. ConditionTemplateGenerationResponse 생성 시 포함 사항:
               - templateResult: 조건 JSON 배열
               - templateType: "specific"
               - resourceIdentifier: 메서드 시그니처
               - 적절한 메타데이터

            중요 사항:
            - 이름과 설명은 한국어로 작성하세요
            - 이름에 "권한" 단어를 절대 사용하지 마세요
            - 정확한 hasPermission 패턴을 따르세요
            - 파라미터가 없는 메서드는 빈 배열을 반환하세요

            완전한 ConditionTemplateGenerationResponse를 JSON 형식으로 생성하세요.
            """, methodSignature);

        return conditionRequest + "\n\n" + converter.getFormat();
    }

    public BeanOutputConverter<ConditionTemplateGenerationResponse> getConverter() {
        return converter;
    }
} 