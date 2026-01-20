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


@Slf4j
@PromptTemplateConfig(
    key = "conditionTemplateGeneration",
    aliases = {"condition_template_generation"},
    description = "Spring AI Structured Output Condition Template Generation Router"
)
public class ConditionTemplatePromptTemplate implements PromptTemplate {
    
    
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
            
            return specificTemplate.generateUserPrompt(request, contextInfo);
        }
    }

    
    private String extractTemplateType(AIRequest<? extends DomainContext> request) {
        if (request instanceof ConditionTemplateGenerationRequest) {
            ConditionTemplateGenerationRequest ctgRequest = (ConditionTemplateGenerationRequest) request;
            String templateType = ctgRequest.getTemplateType();
            log.debug("ConditionTemplateGenerationRequest에서 templateType 추출: {}", templateType);
            return templateType;
        }
        
        
        String templateType = request.getParameter("templateType", String.class);
        if (templateType != null) {
            log.debug("파라미터에서 templateType 추출: {}", templateType);
            return templateType;
        }
        
        
        log.warn("templateType을 찾을 수 없음, 기본값 'universal' 사용");
        return "universal";
    }
    
    
    public BeanOutputConverter<ConditionTemplateGenerationResponse> getConverter() {
        return converter;
    }
} 