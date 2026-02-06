package io.contexa.contexaiam.aiam.labs.condition;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.components.retriever.ConditionTemplateContextRetriever;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
public class ConditionTemplateGenerationLab extends AbstractIAMLab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> {

    private final PipelineOrchestrator orchestrator;
    private final ConditionTemplateVectorService vectorService;

    public ConditionTemplateGenerationLab(PipelineOrchestrator orchestrator,
                                          ConditionTemplateVectorService vectorService) {
        super("ConditionTemplateGeneration", "2.0", LabSpecialization.RECOMMENDATION_SYSTEM);
        this.orchestrator = orchestrator;
        this.vectorService = vectorService;
    }

    @Override
    protected ConditionTemplateGenerationResponse doProcess(ConditionTemplateGenerationRequest request) throws Exception {
        if (request.isUniversal()) {
            return generateUniversalConditionTemplatesAsync().block();
        } else {
            return generateSpecificConditionTemplatesAsync(
                    request.getResourceIdentifier(),
                    request.getMethodInfo()
            ).block();
        }
    }

    @Override
    protected Mono<ConditionTemplateGenerationResponse> doProcessAsync(ConditionTemplateGenerationRequest request) {
        if (request.isUniversal()) {
            return generateUniversalConditionTemplatesAsync();
        } else {
            return generateSpecificConditionTemplatesAsync(
                    request.getResourceIdentifier(),
                    request.getMethodInfo()
            );
        }
    }

    private Mono<ConditionTemplateGenerationResponse> generateUniversalConditionTemplatesAsync() {

        try {
            ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(true);
            vectorService.storeTemplateGenerationRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(this::createUniversalTemplateRequest)
                .flatMap(aiRequest -> {
                    PipelineConfiguration config = createConditionTemplatePipelineConfig();
                    return orchestrator.execute(aiRequest, config, ConditionTemplateGenerationResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        return ConditionTemplateGenerationResponse.failure(
                                "universal",
                                null,
                                "Pipeline returned null response"
                        );
                    }

                    try {
                        ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(true);
                        vectorService.storeGeneratedTemplates(request, (ConditionTemplateGenerationResponse) response);
                    } catch (Exception e) {
                        log.error("벡터 저장소 결과 저장 실패", e);
                    }

                    return (ConditionTemplateGenerationResponse) response;
                })
                .onErrorResume(error -> {
                    log.error("AI 범용 템플릿 비동기 생성 실패", error);
                    String errorMsg = error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString();
                    return Mono.just(ConditionTemplateGenerationResponse.failure(
                            "universal",
                            null,
                            "Exception: " + errorMsg
                    ));
                });
    }

    private Mono<ConditionTemplateGenerationResponse> generateSpecificConditionTemplatesAsync(String resourceIdentifier, String methodInfo) {

        try {
            ConditionTemplateGenerationRequest request = ConditionTemplateGenerationRequest.forSpecificTemplate(resourceIdentifier, methodInfo);
            vectorService.storeTemplateGenerationRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(() -> createSpecificTemplateRequest(resourceIdentifier, methodInfo))
                .flatMap(aiRequest -> {
                    PipelineConfiguration config = createConditionTemplatePipelineConfig();
                    return orchestrator.execute(aiRequest, config, ConditionTemplateGenerationResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        return ConditionTemplateGenerationResponse.failure(
                                "specific",
                                resourceIdentifier,
                                "Pipeline returned null response"
                        );
                    }
                    try {
                        ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(true);
                        vectorService.storeGeneratedTemplates(request, (ConditionTemplateGenerationResponse) response);
                    } catch (Exception e) {
                        log.error("벡터 저장소 결과 저장 실패", e);
                    }

                    return (ConditionTemplateGenerationResponse) response;
                })
                .onErrorResume(error -> {
                    log.error("AI 특화 조건 비동기 생성 실패: {}", resourceIdentifier, error);
                    String errorMsg = error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString();
                    return Mono.just(ConditionTemplateGenerationResponse.failure(
                            "specific",
                            resourceIdentifier,
                            "Exception: " + errorMsg
                    ));
                });
    }

    private PipelineConfiguration createConditionTemplatePipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(30)
                .build();
    }

    private AIRequest<ConditionTemplateContext> createUniversalTemplateRequest() {
        ConditionTemplateContext context = ConditionTemplateContext.forUniversalTemplate();
        AIRequest<ConditionTemplateContext> request = new AIRequest<>(context, new TemplateType("ConditionTemplate"), new DiagnosisType("ConditionTemplate"));
        request.withParameter("templateType", "universal");

        return request;
    }

    private AIRequest<ConditionTemplateContext> createSpecificTemplateRequest(String resourceIdentifier, String methodInfo) {
        ConditionTemplateContext context = ConditionTemplateContext.forSpecificTemplate(resourceIdentifier, methodInfo);

        AIRequest<ConditionTemplateContext> request = new AIRequest<>(context, new TemplateType("ConditionTemplate"), new DiagnosisType("ConditionTemplate"));
        ;

        request.withParameter("templateType", "specific");
        request.withParameter("resourceIdentifier", resourceIdentifier);
        request.withParameter("methodInfo", methodInfo);

        return request;
    }
}
