package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
public class UniversalConditionTemplate implements PromptTemplate {

    private final BeanOutputConverter<ConditionTemplateGenerationResponse> converter = 
        new BeanOutputConverter<>(ConditionTemplateGenerationResponse.class);

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("UniversalCondition");
    }
    
    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            You are an ABAC Universal Condition Generation Expert AI specialized in creating reusable access control conditions.
            
            IMPORTANT: Response must be in PURE JSON format matching the ConditionTemplateGenerationResponse schema.
            Language: All names and descriptions must be in Korean (한국어).
        
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
        
        🏆 올바른 범용 네이밍 예시:
        - "사용자 인증 상태 확인" ← 올바름
        - "관리자 역할 확인" ← 올바름  
        - "업무시간 접근 제한" ← 올바름
        
        %s
        
        Required Output:
        - templateResult: JSON string containing exactly 3 universal condition templates
        - templateType: "universal" for this template type  
        - resourceIdentifier: null (not applicable for universal conditions)
        - processingMetadata: Metadata about the generation process
        
        Each template in templateResult must include:
        - name: Korean name without "권한" word
        - description: Clear Korean description
        - spelTemplate: SpEL expression without parameters
        - category: Korean category
        - classification: "UNIVERSAL"
        
        %s
        """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }
    
    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String conditionRequest = String.format("""
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
        
        Generate ConditionTemplateGenerationResponse with:
        - Exactly 3 universal conditions in templateResult
        - templateType: "universal"
        - All text in Korean
        - Never use the word "권한"
        - Never use hasPermission() in universal conditions
        
        Generate complete ConditionTemplateGenerationResponse in JSON format.
        """);

        return conditionRequest + "\n\n" + converter.getFormat();
    }

    public BeanOutputConverter<ConditionTemplateGenerationResponse> getConverter() {
        return converter;
    }
} 