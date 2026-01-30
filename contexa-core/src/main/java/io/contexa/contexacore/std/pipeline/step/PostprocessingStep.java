package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
public class PostprocessingStep implements PipelineStep {

    private final List<DomainResponseProcessor> domainProcessors;

    @Autowired
    public PostprocessingStep(Optional<List<DomainResponseProcessor>> processors) {
        this.domainProcessors = processors
                .orElse(List.of())
                .stream()
                .sorted(Comparator.comparingInt(DomainResponseProcessor::getOrder))
                .toList();

    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            Class<?> targetResponseType = context.getMetadata("targetResponseType", Class.class);
            Object parsedResponse = context.getStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, Object.class);

            if (parsedResponse == null ||
                    (parsedResponse instanceof String && ((String) parsedResponse).trim().isEmpty())) {
                log.error("[{}] Response is empty, creating enhanced fallback response", getStepName());
                return createEnhancedFallbackResponse(request, context);
            }
            Object wrappedResponse;
            if (targetResponseType != null && targetResponseType.isInstance(parsedResponse)) {
                wrappedResponse = parsedResponse;
            } else {
                wrappedResponse = tryWrapWithDomainProcessor(parsedResponse, request, context);
            }

            enrichWithMetadata(wrappedResponse, request, context);
            context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, wrappedResponse);
            return wrappedResponse;

        });
    }

    private <T extends DomainContext> Object tryWrapWithDomainProcessor(
            Object parsedResponse, AIRequest<T> request, PipelineExecutionContext context) {

        String templateKey = PromptGenerator.determineTemplateKey(request);

        if (templateKey == null) {
            return parsedResponse;
        }

        for (DomainResponseProcessor processor : domainProcessors) {
            if (processor.supports(templateKey) ||
                    processor.supportsType(parsedResponse.getClass())) {

                try {
                    return processor.wrapResponse(
                            parsedResponse,
                            context
                    );

                } catch (Exception e) {
                    log.error("[{}] Domain processor execution failed: {}", getStepName(), e.getMessage(), e);
                }
            }
        }

        return parsedResponse;
    }

    private void enrichWithMetadata(Object response, AIRequest<?> request, PipelineExecutionContext context) {

        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("executionTimeMs", executionTime);
        }

        context.addMetadata("status", "SUCCESS");
        context.addMetadata("completedAt", System.currentTimeMillis());
    }

    private Object createMinimalFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {
        DefaultAIResponse fallback = new DefaultAIResponse(
                request.getRequestId() != null ? request.getRequestId() : "unknown",
                "{\"status\":\"no_response\"}"
        );

        context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
        context.addMetadata("status", "FALLBACK");

        return fallback;
    }

    private Object createEnhancedFallbackResponse(AIRequest<?> request, PipelineExecutionContext context) {

        String error = context.getMetadata("error", String.class);
        String lastStage = context.getMetadata("lastCompletedStage", String.class);
        Long startTime = context.getMetadata("startTime", Long.class);

        String message = error != null ? error : "Unable to generate analysis result";
        if (lastStage != null) {
            message += " (Last completed stage: " + lastStage + ")";
        }

        Map<String, Object> fallbackData = new HashMap<>();
        fallbackData.put("status", "FALLBACK");
        fallbackData.put("message", message);
        fallbackData.put("timestamp", System.currentTimeMillis());
        fallbackData.put("requestId", request.getRequestId());
        if (lastStage != null) {
            fallbackData.put("lastCompletedStage", lastStage);
        }
        if (startTime != null) {
            fallbackData.put("processingTimeMs", System.currentTimeMillis() - startTime);
        }

        try {

            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String jsonResponse = mapper.writeValueAsString(fallbackData);

            DefaultAIResponse fallback = new DefaultAIResponse(
                    request.getRequestId() != null ? request.getRequestId() : "unknown",
                    jsonResponse
            );

            context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
            context.addMetadata("status", "FALLBACK");

            return fallback;
        } catch (Exception e) {
            log.error("[{}] Failed to create fallback response", getStepName(), e);

            return createMinimalFallbackResponse(request, context);
        }
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.POSTPROCESSING;
    }

    @Override
    public int getOrder() {
        return 6;
    }
}