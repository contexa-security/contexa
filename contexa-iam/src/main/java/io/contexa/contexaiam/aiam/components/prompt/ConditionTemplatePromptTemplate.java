package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacore.std.components.prompt.PromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptTemplateConfig;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 🔀 조건 템플릿 생성 통합 프롬프트 템플릿
 * 
 * Spring AI BeanOutputConverter를 활용한 구조화된 출력:
 * - 자동 JSON 스키마 생성
 * - 타입 안전 변환
 * - 표준화된 포맷 지시
 * - 성능 최적화
 *
 * Spring AI 공식 패턴 준수
 * 
 * 라우터 패턴:
 * - templateType에 따라 UniversalConditionTemplate 또는 SpecificConditionTemplate 선택
 * - 각 템플릿은 독립적인 BeanOutputConverter 사용
 * - 통합된 응답 구조 유지
 */
@Slf4j
@Component
@PromptTemplateConfig(
    key = "conditionTemplateGeneration",
    aliases = {"condition_template_generation"},
    description = "Spring AI Structured Output Condition Template Generation Router"
)
public class ConditionTemplatePromptTemplate implements PromptTemplate {
    
    // Spring AI BeanOutputConverter를 사용한 포맷 생성
    private final BeanOutputConverter<ConditionTemplateGenerationResponse> converter = 
        new BeanOutputConverter<>(ConditionTemplateGenerationResponse.class);
    
    private final UniversalConditionTemplate universalTemplate;
    private final SpecificConditionTemplate specificTemplate;
    
    @Autowired
    public ConditionTemplatePromptTemplate(UniversalConditionTemplate universalTemplate,
                                         SpecificConditionTemplate specificTemplate) {
        this.universalTemplate = universalTemplate;
        this.specificTemplate = specificTemplate;
        log.info("🎉 ConditionTemplatePromptTemplate Bean 생성 완료!");
        log.info("  - universalTemplate: {}", universalTemplate.getClass().getSimpleName());
        log.info("  - specificTemplate: {}", specificTemplate.getClass().getSimpleName());
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String templateType = extractTemplateType(request);
        
        if ("universal".equals(templateType)) {
            log.debug("범용 조건 템플릿 프롬프트 선택");
            return universalTemplate.generateSystemPrompt(request, systemMetadata);
        } else {
            log.debug("특화 조건 템플릿 프롬프트 선택");
            return specificTemplate.generateSystemPrompt(request, systemMetadata);
        }
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String templateType = extractTemplateType(request);
        
        if ("universal".equals(templateType)) {
            return universalTemplate.generateUserPrompt(request, contextInfo);
        } else {
            // 특화 조건은 methodInfo가 contextInfo로 전달됨
            return specificTemplate.generateUserPrompt(request, contextInfo);
        }
    }

    /**
     * 요청에서 템플릿 타입 추출
     */
    private String extractTemplateType(AIRequest<? extends DomainContext> request) {
        if (request instanceof ConditionTemplateGenerationRequest) {
            ConditionTemplateGenerationRequest ctgRequest = (ConditionTemplateGenerationRequest) request;
            String templateType = ctgRequest.getTemplateType();
            log.debug("ConditionTemplateGenerationRequest에서 templateType 추출: {}", templateType);
            return templateType;
        }
        
        // 파라미터에서 추출 시도
        String templateType = request.getParameter("templateType", String.class);
        if (templateType != null) {
            log.debug("파라미터에서 templateType 추출: {}", templateType);
            return templateType;
        }
        
        // 기본값
        log.warn("templateType을 찾을 수 없음, 기본값 'universal' 사용");
        return "universal";
    }
    
    /**
     * BeanOutputConverter 반환 (파이프라인에서 사용)
     * 라우터 역할이지만 통합된 응답 구조를 사용
     */
    public BeanOutputConverter<ConditionTemplateGenerationResponse> getConverter() {
        return converter;
    }
} 