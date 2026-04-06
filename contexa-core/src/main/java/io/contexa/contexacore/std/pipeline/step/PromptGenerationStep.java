package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class PromptGenerationStep implements PipelineStep {

    private final PromptGenerator promptGenerator;

    public PromptGenerationStep(PromptGenerator promptGenerator) {
        this.promptGenerator = promptGenerator;
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(
            AIRequest<T> request,
            PipelineExecutionContext context) {

        return Mono.fromCallable(() -> {

            ContextRetriever.ContextRetrievalResult contextResult =
                    context.getStepResult(
                            PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL,
                            ContextRetriever.ContextRetrievalResult.class
                    );

            String systemMetadata = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PREPROCESSING,
                    String.class
            );

            String contextInfo = contextResult != null ? contextResult.getContextInfo() : "";
            String metadata = systemMetadata != null ? systemMetadata : "";
            PromptGenerationResult promptResult = promptGenerator.generatePrompt(request, contextInfo, metadata);

            Class<?> aiGenerationType = promptGenerator.getAIGenerationType(request);
            if (aiGenerationType != null) {
                context.addMetadata("aiGenerationType", aiGenerationType);
            }
            if (promptResult.getPromptExecutionMetadata() != null) {
                context.addMetadata("promptExecutionMetadata", promptResult.getPromptExecutionMetadata());
                promptResult.getPromptExecutionMetadata()
                        .toMetadataMap()
                        .forEach(context::addMetadata);
            }
            captureSecurityDecisionPromptLineage(request, promptResult);
            context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, promptResult);

            return promptResult;
        });
    }

    @Override
    public PipelineConfiguration.PipelineStep getConfigStep() {
        return PipelineConfiguration.PipelineStep.PROMPT_GENERATION;
    }

    @Override
    public <T extends DomainContext> boolean canExecute(AIRequest<T> request) {
        return request != null && promptGenerator != null;
    }

    @Override
    public int getOrder() {
        return 3;
    }

    private <T extends DomainContext> void captureSecurityDecisionPromptLineage(
            AIRequest<T> request,
            PromptGenerationResult promptResult
    ) {
        if (request == null || promptResult == null) {
            return;
        }
        T domainContext = request.getContext();
        if (!(domainContext instanceof SecurityDecisionContext securityDecisionContext)) {
            return;
        }
        SecurityEvent securityEvent = securityDecisionContext.getSecurityEvent();
        if (securityEvent == null) {
            return;
        }
        Map<String, Object> metadata = ensureMutableMetadata(securityEvent);
        putIfPresent(metadata, "systemPrompt", promptResult.getSystemPrompt());
        putIfPresent(metadata, "userPrompt", promptResult.getUserPrompt());
        putIfPresent(metadata, "rawSystemPrompt", promptResult.getRawSystemPrompt());
        putIfPresent(metadata, "rawUserPrompt", promptResult.getRawUserPrompt());
        if (promptResult.getMetadata() != null) {
            copyIfPresent(promptResult.getMetadata(), metadata, "promptKey");
            copyIfPresent(promptResult.getMetadata(), metadata, "templateKey");
            copyIfPresent(promptResult.getMetadata(), metadata, "promptVersion");
            copyIfPresent(promptResult.getMetadata(), metadata, "promptHash");
            copyIfPresent(promptResult.getMetadata(), metadata, "systemPromptHash");
            copyIfPresent(promptResult.getMetadata(), metadata, "userPromptHash");
            copyIfPresent(promptResult.getMetadata(), metadata, "rawPromptHash");
            copyIfPresent(promptResult.getMetadata(), metadata, "rawSystemPromptHash");
            copyIfPresent(promptResult.getMetadata(), metadata, "rawUserPromptHash");
        }
    }

    private Map<String, Object> ensureMutableMetadata(SecurityEvent securityEvent) {
        Map<String, Object> current = securityEvent.getMetadata();
        if (current == null) {
            Map<String, Object> fresh = new LinkedHashMap<>();
            securityEvent.setMetadata(fresh);
            return fresh;
        }
        if (current instanceof LinkedHashMap<?, ?>) {
            return current;
        }
        Map<String, Object> copied = new LinkedHashMap<>(current);
        securityEvent.setMetadata(copied);
        return copied;
    }

    private void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        if (source == null || target == null || key == null) {
            return;
        }
        Object value = source.get(key);
        if (value != null) {
            target.putIfAbsent(key, value);
        }
    }

    private void putIfPresent(Map<String, Object> target, String key, String value) {
        if (target == null || key == null || value == null || value.isBlank()) {
            return;
        }
        target.put(key, value);
    }
}

