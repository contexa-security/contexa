package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateGenerationLab;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class ConditionTemplateDiagnosisStrategy extends AbstractAIStrategy<ConditionTemplateContext, ConditionTemplateGenerationResponse> {

    public ConditionTemplateDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return DiagnosisType.CONDITION_TEMPLATE;
    }

    @Override
    public int getPriority() {
        return 15;
    }

    @Override
    protected void validateRequest(AIRequest<ConditionTemplateContext> request) throws DiagnosisException {
        if (request == null) {
            throw new DiagnosisException("CONDITION_TEMPLATE", "NULL_REQUEST", "요청이 null입니다");
        }

        String templateType = request.getParameter("templateType", String.class);
        if (templateType == null || templateType.trim().isEmpty()) {
            throw new DiagnosisException("CONDITION_TEMPLATE", "MISSING_TEMPLATE_TYPE",
                    "templateType 파라미터가 필요합니다");
        }

        if ("specific".equals(templateType)) {
            String resourceIdentifier = request.getParameter("resourceIdentifier", String.class);
            if (resourceIdentifier == null || resourceIdentifier.trim().isEmpty()) {
                throw new DiagnosisException("CONDITION_TEMPLATE", "MISSING_RESOURCE_IDENTIFIER",
                        "특화 조건 템플릿에는 resourceIdentifier가 필요합니다");
            }
        }
    }

    @Override
    protected Class<?> getLabType() {
        return ConditionTemplateGenerationLab.class;
    }

    @Override
    protected Object buildLabRequest(AIRequest<ConditionTemplateContext> request) {
        
        String generationType = request.getParameter("generationType", String.class);
        
        if ("specific".equals(generationType)) {
            String resourceIdentifier = request.getParameter("resourceIdentifier", String.class);
            String methodInfo = request.getParameter("methodInfo", String.class);
            return new SpecificTemplateRequest(resourceIdentifier, methodInfo);
        } else {
            return new UniversalTemplateRequest();
        }
    }

    @Override
    protected ConditionTemplateGenerationResponse processLabExecution(Object lab, Object labRequest, AIRequest<ConditionTemplateContext> request) throws Exception {
        AILab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> conditionTemplateGenerationLab = (ConditionTemplateGenerationLab) lab;
        ConditionTemplateGenerationResponse response;

        if (labRequest instanceof UniversalTemplateRequest universalTemplateRequest) {
            ConditionTemplateGenerationRequest conditionTemplateLabRequest =
                    new ConditionTemplateGenerationRequest(true);
            response = conditionTemplateGenerationLab.process(conditionTemplateLabRequest);
            
        } else if (labRequest instanceof SpecificTemplateRequest specificTemplateRequest) {
            ConditionTemplateGenerationRequest conditionTemplateLabRequest =
                    new ConditionTemplateGenerationRequest(false, "specific", specificTemplateRequest.resourceIdentifier, specificTemplateRequest.methodInfo);
            response = conditionTemplateGenerationLab.process(conditionTemplateLabRequest);

                    } else {
            throw new DiagnosisException("CONDITION_TEMPLATE", "INVALID_REQUEST_TYPE",
                    "알 수 없는 요청 타입: " + labRequest.getClass().getSimpleName());
        }

        return response;
    }

    @Override
    protected Mono<ConditionTemplateGenerationResponse> processLabExecutionAsync(Object lab, Object labRequest, AIRequest<ConditionTemplateContext> originRequest) {

        AILab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> conditionTemplateGenerationLab = (ConditionTemplateGenerationLab) lab;

        if (labRequest instanceof UniversalTemplateRequest) {
            ConditionTemplateGenerationRequest conditionTemplateLabRequest =
                    new ConditionTemplateGenerationRequest(true);
            return conditionTemplateGenerationLab.processAsync(conditionTemplateLabRequest);

        } else if (labRequest instanceof SpecificTemplateRequest specificTemplateRequest) {
            ConditionTemplateGenerationRequest conditionTemplateLabRequest =
                    new ConditionTemplateGenerationRequest(false, "specific", specificTemplateRequest.resourceIdentifier, specificTemplateRequest.methodInfo);
            return conditionTemplateGenerationLab.processAsync(conditionTemplateLabRequest);

        } else {
            return Mono.error(new DiagnosisException("CONDITION_TEMPLATE", "INVALID_REQUEST_TYPE",
                    "알 수 없는 요청 타입: " + labRequest.getClass().getSimpleName()));
        }
    }

    private static class UniversalTemplateRequest {
        
    }

    private static class SpecificTemplateRequest {
        final String resourceIdentifier;
        final String methodInfo;

        SpecificTemplateRequest(String resourceIdentifier, String methodInfo) {
            this.resourceIdentifier = resourceIdentifier;
            this.methodInfo = methodInfo;
        }
    }

    @Override
    protected PipelineConfig getPipelineConfig() {
        
        return PipelineConfig.builder()
                .contextRetrieval(PipelineConfig.ContextRetrievalStrategy.OPTIONAL)
                .postProcessing(PipelineConfig.PostProcessingStrategy.DYNAMIC)
                .description("조건 템플릿 생성 - 빠른 응답 지향")
                .build();
    }
}
