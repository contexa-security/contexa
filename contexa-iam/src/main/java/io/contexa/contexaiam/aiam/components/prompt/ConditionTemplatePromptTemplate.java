package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.beans.factory.annotation.Autowired;

@Slf4j
public class ConditionTemplatePromptTemplate implements PromptTemplate {

    private final BeanOutputConverter<ConditionTemplateGenerationResponse> converter =
            new BeanOutputConverter<>(ConditionTemplateGenerationResponse.class);

    private final UniversalConditionTemplate universalTemplate;
    private final SpecificConditionTemplate specificTemplate;

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("ConditionTemplate");
    }

    @Autowired
    public ConditionTemplatePromptTemplate(UniversalConditionTemplate universalTemplate,
                                           SpecificConditionTemplate specificTemplate) {
        this.universalTemplate = universalTemplate;
        this.specificTemplate = specificTemplate;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        String templateType = extractTemplateType(request);

        if ("universal".equals(templateType)) {
            return universalTemplate.generateSystemPrompt(request, systemMetadata);
        } else {
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
            return templateType;
        }

        String templateType = request.getParameter("templateType", String.class);
        if (templateType != null) {
            return templateType;
        }

        log.warn("templateType을 찾을 수 없음, 기본값 'universal' 사용");
        return "universal";
    }

    public BeanOutputConverter<ConditionTemplateGenerationResponse> getConverter() {
        return converter;
    }
} 