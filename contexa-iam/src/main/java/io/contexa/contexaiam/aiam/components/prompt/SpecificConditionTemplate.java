package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
@PromptTemplateConfig(
    key = "generateSpecificConditionTemplates",
    aliases = {"specific_condition_template", "specific_condition", "특화조건"},
    description = "Spring AI Structured Output Specific Condition Template"
)
public class SpecificConditionTemplate implements PromptTemplate {

    private final BeanOutputConverter<ConditionTemplateGenerationResponse> converter = 
        new BeanOutputConverter<>(ConditionTemplateGenerationResponse.class);
    
    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            You are an AI specialized in analyzing Java method signatures to generate SpEL-based hasPermission conditions for ABAC (Attribute-Based Access Control).
            
            IMPORTANT: Response must be in PURE JSON format matching the ConditionTemplateGenerationResponse schema.
            Language: Names and descriptions must be in Korean (한국어).

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
            
            Required Output:
            - templateResult: JSON string containing array of condition templates
            - templateType: "specific" for this template type
            - resourceIdentifier: The method signature being analyzed
            - processingMetadata: Metadata about the generation process
            
            Each template in templateResult must include:
            - name: Korean name without "권한" word
            - description: Clear Korean description
            - spelTemplate: SpEL expression using hasPermission
            - category: Korean category ("접근 확인" or "대상 검증")
            - classification: "CONTEXT_DEPENDENT"
            
            %s
        """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }
    
    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String methodSignature = contextInfo != null ? contextInfo : "";
        
        String conditionRequest = String.format("""
            Analyze the following Java method signature and generate specific condition templates:
            
            Method Signature:
            %s
            
            Generation Requirements:
            1. Parse the method signature to identify:
               - Method name and operation type
               - Parameters (ID parameters vs Object parameters)
               - Resource type being accessed
            
            2. Generate hasPermission conditions based on:
               - ID parameters: hasPermission(#paramName, 'RESOURCE_TYPE', 'ACTION')
               - Object parameters: hasPermission(#paramName, 'RESOURCE_ACTION')
               - No parameters: Return empty array []
            
            3. Create ConditionTemplateGenerationResponse with:
               - templateResult: JSON array of conditions
               - templateType: "specific"
               - resourceIdentifier: The method signature
               - Appropriate metadata
            
            Important:
            - Use Korean for names and descriptions
            - Never use the word "권한" in names
            - Follow the exact hasPermission patterns
            - Return empty array for parameterless methods
            
            Generate complete ConditionTemplateGenerationResponse in JSON format.
            """, methodSignature);

        return conditionRequest + "\n\n" + converter.getFormat();
    }

    public BeanOutputConverter<ConditionTemplateGenerationResponse> getConverter() {
        return converter;
    }
} 