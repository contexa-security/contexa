package io.contexa.contexaiam.aiam.strategy;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.strategy.AbstractAIStrategy;
import io.contexa.contexacore.std.strategy.DiagnosisException;
import io.contexa.contexacore.std.strategy.PipelineConfig;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateGenerationLab;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import reactor.core.publisher.Mono;

public class ConditionTemplateDiagnosisStrategy
        extends AbstractAIStrategy<ConditionTemplateContext, ConditionTemplateGenerationResponse> {

    public ConditionTemplateDiagnosisStrategy(AILabFactory labFactory) {
        super(labFactory);
    }

    @Override
    public DiagnosisType getSupportedType() {
        return new DiagnosisType("ConditionTemplate");
    }

    @Override
    public int getPriority() {
        return 15;
    }

    @Override
    protected void validateRequest(AIRequest<ConditionTemplateContext> request) throws DiagnosisException {
        if (request == null) {
            throw new DiagnosisException("CONDITION_TEMPLATE", "NULL_REQUEST",
                    "Request is null");
        }

        ConditionTemplateContext context = request.getContext();
        if (context == null || context.getTemplateType() == null) {
            throw new DiagnosisException("CONDITION_TEMPLATE", "MISSING_TEMPLATE_TYPE",
                    "templateType is required in context");
        }

        if ("specific".equals(context.getTemplateType())) {
            boolean hasSingleResource = context.getResourceIdentifier() != null
                    && !context.getResourceIdentifier().trim().isEmpty();
            boolean hasBatchResource = context.getResourceBatch() != null
                    && !context.getResourceBatch().isEmpty();
            if (!hasSingleResource && !hasBatchResource) {
                throw new DiagnosisException("CONDITION_TEMPLATE", "MISSING_RESOURCE_IDENTIFIER",
                        "resourceIdentifier or resourceBatch is required for specific condition templates");
            }
        }
    }

    @Override
    protected Class<?> getLabType() {
        return ConditionTemplateGenerationLab.class;
    }

    @Override
    protected Object convertLabRequest(AIRequest<ConditionTemplateContext> request) {
        return new ConditionTemplateGenerationRequest(request.getContext());
    }

    @Override
    protected ConditionTemplateGenerationResponse processLabExecution(
            Object lab, Object labRequest, AIRequest<ConditionTemplateContext> request) throws Exception {
        AILab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> conditionLab =
                (ConditionTemplateGenerationLab) lab;
        ConditionTemplateGenerationRequest conditionRequest = (ConditionTemplateGenerationRequest) labRequest;

        return conditionLab.process(conditionRequest);
    }

    @Override
    protected Mono<ConditionTemplateGenerationResponse> processLabExecutionAsync(
            Object lab, Object labRequest, AIRequest<ConditionTemplateContext> originRequest) {
        AILab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> conditionLab =
                (ConditionTemplateGenerationLab) lab;
        ConditionTemplateGenerationRequest conditionRequest = (ConditionTemplateGenerationRequest) labRequest;

        return conditionLab.processAsync(conditionRequest);
    }

    @Override
    protected PipelineConfig getPipelineConfig() {
        return PipelineConfig.builder()
                .contextRetrieval(PipelineConfig.ContextRetrievalStrategy.OPTIONAL)
                .postProcessing(PipelineConfig.PostProcessingStrategy.DYNAMIC)
                .description("Condition template generation - fast response oriented")
                .build();
    }
}
