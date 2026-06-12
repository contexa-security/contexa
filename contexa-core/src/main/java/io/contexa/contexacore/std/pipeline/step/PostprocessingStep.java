/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.pipeline.step;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

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
            long stepStartTime = System.currentTimeMillis();
            Class<?> targetResponseType = context.getMetadata("targetResponseType", Class.class);
            Object parsedResponse = context.getStepResult(PipelineConfiguration.PipelineStep.RESPONSE_PARSING, Object.class);
            boolean strictPostprocessingRequired = resolveStrictPostprocessingRequired(request, context);

            if (parsedResponse == null ||
                    (parsedResponse instanceof String && ((String) parsedResponse).trim().isEmpty())) {
                log.error("[{}] Response is empty, creating enhanced fallback response", getStepName());
                if (strictPostprocessingRequired) {
                    throw new IllegalStateException("Strict postprocessing required but parsed response is empty");
                }
                return createEnhancedFallbackResponse(request, context);
            }
            Object wrappedResponse;
            if (targetResponseType != null && targetResponseType.isInstance(parsedResponse)) {
                wrappedResponse = parsedResponse;
            } else {
                wrappedResponse = tryWrapWithDomainProcessor(parsedResponse, request, context, strictPostprocessingRequired);
                if (strictPostprocessingRequired
                        && targetResponseType != null
                        && !targetResponseType.isInstance(wrappedResponse)) {
                    throw new IllegalStateException(
                            "Strict postprocessing required but wrapped response did not match target type: "
                                    + targetResponseType.getName());
                }
            }

            enrichWithMetadata(wrappedResponse, request, context);
            context.addMetadata("postprocessingLatencyMs", System.currentTimeMillis() - stepStartTime);
            context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, wrappedResponse);
            return wrappedResponse;

        });
    }

    private <T extends DomainContext> Object tryWrapWithDomainProcessor(
            Object parsedResponse,
            AIRequest<T> request,
            PipelineExecutionContext context,
            boolean strictPostprocessingRequired) {

        String templateKey = PromptGenerator.determineTemplateKey(request);

        if (templateKey == null) {
            if (strictPostprocessingRequired) {
                throw new IllegalStateException("Strict postprocessing required but template key is unavailable");
            }
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
                    if (strictPostprocessingRequired) {
                        throw new IllegalStateException("Strict postprocessing failed", e);
                    }
                }
            }
        }

        if (strictPostprocessingRequired) {
            throw new IllegalStateException(
                    "Strict postprocessing required but no domain response processor matched the parsed response");
        }
        return parsedResponse;
    }

    private boolean resolveStrictPostprocessingRequired(AIRequest<?> request, PipelineExecutionContext context) {
        if (request != null && request.getParameters().containsKey("strictResponsePostprocessing")) {
            Object value = request.getParameters().get("strictResponsePostprocessing");
            if (value instanceof Boolean bool) {
                return bool;
            }
            if (value != null) {
                return Boolean.parseBoolean(value.toString());
            }
        }
        Boolean metadataValue = context != null ? context.getMetadata("strictResponsePostprocessing", Boolean.class) : null;
        return Boolean.TRUE.equals(metadataValue);
    }

    private void enrichWithMetadata(Object response, AIRequest<?> request, PipelineExecutionContext context) {

        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long executionTime = System.currentTimeMillis() - startTime;
            context.addMetadata("executionTimeMs", executionTime);
        }

        context.addMetadata("status", "SUCCESS");
        context.addMetadata("completedAt", System.currentTimeMillis());

        if (response instanceof AIResponse aiResponse) {
            for (String key : PromptRuntimeTelemetrySupport.runtimeTelemetryKeys()) {
                Object value = context.getMetadata(key, Object.class);
                if (value != null) {
                    aiResponse.withMetadata(key, value);
                }
            }
        }
    }

    private Object createMinimalFallbackResponse(PipelineExecutionContext context) {
        DefaultAIResponse fallback = new DefaultAIResponse(
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

            ObjectMapper mapper = new ObjectMapper();
            String jsonResponse = mapper.writeValueAsString(fallbackData);

            DefaultAIResponse fallback = new DefaultAIResponse(jsonResponse);

            context.addStepResult(PipelineConfiguration.PipelineStep.POSTPROCESSING, fallback);
            context.addMetadata("status", "FALLBACK");

            return fallback;
        } catch (Exception e) {
            log.error("[{}] Failed to create fallback response", getStepName(), e);

            return createMinimalFallbackResponse(context);
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
