package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.IntStream;

/**
 * 🏷️ 리소스 네이밍 제안 프롬프트 템플릿
 *
 * Spring AI BeanOutputConverter를 활용한 구조화된 출력:
 * - 자동 JSON 스키마 생성
 * - 타입 안전 변환
 * - 표준화된 포맷 지시
 * - 성능 최적화
 *
 * Spring AI 공식 패턴 준수
 * 
 * 네이밍 변환:
 * - 기술적 용어를 비즈니스 친화적 한글로 변환
 * - URL 경로를 기능명으로 변환
 * - 메서드명을 동작 설명으로 변환
 * - 100% 응답 보장 (누락 없음)
 */
@Slf4j
@Component
@PromptTemplateConfig(
    key = "resource_naming_suggestion",
    aliases = {"resource_naming", "리소스네이밍"},
    description = "Spring AI Structured Output Resource Naming Template"
)
public class ResourceNamingTemplate implements PromptTemplate {
    
    // Spring AI BeanOutputConverter를 사용한 포맷 생성
    private final BeanOutputConverter<ResourceNamingSuggestionResponse> converter = 
        new BeanOutputConverter<>(ResourceNamingSuggestionResponse.class);

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        // Spring AI의 포맷 지시사항 자동 생성
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            You are a Resource Naming Expert AI specialized in converting technical identifiers into business-friendly Korean names and descriptions.
            
            IMPORTANT: Response must be in PURE JSON format matching the ResourceNamingSuggestionResponse schema.
            Language: All names and descriptions must be in Korean (한국어).
            CRITICAL: You MUST respond to ALL input items without exception.
            
            Absolute Rules (System Error if violated):
            1. Process 100%% of input items - no exceptions
            2. Input count MUST equal output count exactly
            3. Each item MUST have both friendlyName and description
            4. Pure JSON format only - no explanatory text
            5. Use clear, friendly Korean names and descriptions
            6. Maintain input order in output
            
            Processing Rules:
            - camelCase/snake_case → Readable Korean
            - URL paths → Function names (e.g., /admin/users → 사용자 관리)
            - Method names → Action descriptions (e.g., updateUser → 사용자 정보 수정)
            - CRUD operations → Clear verbs (생성, 조회, 수정, 삭제)
            - API endpoints → Descriptive function names
            - Technical terms → Business-friendly terms
            
            Fallback Rule:
            If an item cannot be understood:
            - friendlyName: "[item name] 기능"
            - description: "AI 추천을 받지 못한 리소스입니다."
            - confidence: 0.3
            
            %s
            
            Required Output:
            - suggestions: Array of ResourceNamingSuggestion objects
            - failedIdentifiers: Array of identifiers that couldn't be processed
            - stats: Processing statistics with counts and timing
            
            Each suggestion must include:
            - identifier: Original technical identifier
            - friendlyName: Business-friendly Korean name
            - description: Clear Korean description
            - confidence: AI confidence score (0.0-1.0)
            
            %s
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        // AIRequest에서 리소스 정보 추출
        @SuppressWarnings("unchecked")
        List<String> identifiers = request.getParameter("identifiers", List.class);
        
        if (identifiers == null || identifiers.isEmpty()) {
            log.warn("리소스 목록이 비어있습니다");
            return "오류: 처리할 리소스가 없습니다";
        }

        String namingRequest = buildUserPromptFromIdentifiers(identifiers, contextInfo);
        
        // BeanOutputConverter의 포맷 지시사항을 다시 추가 (강조)
        return namingRequest + "\n\n" + converter.getFormat();
    }

    /**
     * 구버전 호환: 직접 ResourceNamingSuggestionRequest 처리
     */
    public PromptGenerationResult generatePrompt(ResourceNamingSuggestionRequest request, String context) {
        if (request.getResources() == null || request.getResources().isEmpty()) {
            log.warn("리소스 목록이 비어있습니다");
            return PromptGenerationResult.builder()
                    .systemPrompt("오류: 처리할 리소스가 없습니다")
                    .userPrompt("오류")
                    .build();
        }

        String systemPrompt = buildSystemPrompt();
        String userPrompt = buildUserPrompt(request.getResources(), context);
        
        log.debug("ResourceNaming 프롬프트 생성 완료 - 리소스 수: {}", request.getResources().size());
        
        return PromptGenerationResult.builder()
                .systemPrompt(systemPrompt)
                .userPrompt(userPrompt)
                .build();
    }

    /**
     * BeanOutputConverter 반환 (파이프라인에서 사용)
     */
    public BeanOutputConverter<ResourceNamingSuggestionResponse> getConverter() {
        return converter;
    }
    
    /**
     * 구버전과 동일한 시스템 프롬프트 (한글 네이밍 전문가) - 레거시 호환용
     */
    private String buildSystemPrompt() {
        return """
            당신은 소프트웨어의 기술적 용어를 일반 비즈니스 사용자가 이해하기 쉬운 이름과 설명으로 만드는 네이밍 전문가입니다.
            
            **절대적 필수 규칙 - 위반 시 시스템 오류 발생:**
            1. 입력받은 모든 항목(identifier)에 대해 100% 예외 없이 응답해야 합니다
            2. 입력 항목 수와 출력 항목 수가 정확히 일치해야 합니다
            3. 각 항목마다 반드시 friendlyName과 description을 모두 제공해야 합니다
            4. 순수한 JSON 형식으로만 응답하세요 (설명 텍스트 없음)
            5. 한글로 친화적이고 명확한 이름과 설명을 작성하세요
            6. 입력된 순서대로 모든 항목을 응답하세요
            
            **중요:** 만약 특정 항목을 이해할 수 없다면, 다음과 같이 응답하세요:
            - friendlyName: "[항목명] 기능"  
            - description: "AI 추천을 받지 못한 리소스입니다."
            
            **처리 규칙:**
            - camelCase나 snake_case는 읽기 쉬운 한글로 변환
            - URL 경로는 기능 이름으로 변환 (예: /admin/users → 사용자 관리)
            - 메서드명은 동작을 나타내는 한글로 변환 (예: updateUser → 사용자 정보 수정)
            - CRUD 작업은 명확한 동사 사용 (생성, 조회, 수정, 삭제)
            
            **응답 형식 예시 (정확히 이 형태를 따르세요):**
            ```json
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
            ```
            
            **최종 검증:** 응답하기 전에 입력 항목 수와 출력 항목 수가 동일한지 반드시 확인하세요!
            """;
    }

    /**
     * 구버전 완전 이식: 사용자 프롬프트 생성 (소유자 정보 제외)
     */
    private String buildUserPrompt(List<ResourceNamingSuggestionRequest.ResourceItem> resources, String context) {
        StringBuilder userPrompt = new StringBuilder();
        
        // RAG 컨텍스트가 있으면 추가
        if (context != null && !context.trim().isEmpty()) {
            userPrompt.append("**참고 컨텍스트:**\n")
                     .append(context)
                     .append("\n\n");
        }
        
        // 강력한 지시사항과 함께 항목 수 명시
        userPrompt.append("**필수 요구사항:** 다음 **정확히 ").append(resources.size()).append("개** 항목에 대해 **모두 예외 없이** 응답하세요!\n\n");
        userPrompt.append("**중요:** ").append(resources.size()).append("개 입력 → ").append(resources.size()).append("개 출력이 되어야 합니다. 누락 시 시스템 오류!\n\n");
        
        IntStream.range(0, resources.size())
                .forEach(i -> {
                    ResourceNamingSuggestionRequest.ResourceItem resource = resources.get(i);
                    userPrompt.append(i + 1)
                             .append(". ")
                             .append(resource.getIdentifier())
                             .append("\n");
                });
        
        userPrompt.append("\n**다시 한번 확인:** 위의 **모든 ").append(resources.size()).append("개 항목**에 대해 friendlyName과 description을 제공하세요!");
        
        return userPrompt.toString();
    }

    /**
     * AIRequest identifiers에서 프롬프트 생성
     */
    private String buildUserPromptFromIdentifiers(List<String> identifiers, String context) {
        StringBuilder userPrompt = new StringBuilder();
        
        // RAG 컨텍스트가 있으면 추가
        if (context != null && !context.trim().isEmpty()) {
            userPrompt.append("**참고 컨텍스트:**\n")
                     .append(context)
                     .append("\n\n");
        }
        
        // 강력한 지시사항과 함께 항목 수 명시
        userPrompt.append("**필수 요구사항:** 다음 **정확히 ").append(identifiers.size()).append("개** 항목에 대해 **모두 예외 없이** 응답하세요!\n\n");
        userPrompt.append("**중요:** ").append(identifiers.size()).append("개 입력 → ").append(identifiers.size()).append("개 출력이 되어야 합니다. 누락 시 시스템 오류!\n\n");
        
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

    public String getTemplateName() {
        return "resource-naming";
    }

    public String getTemplateVersion() {
        return "1.0";
    }
} 