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

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptFieldLineageAnalysis;
import io.contexa.contexacore.std.components.prompt.PromptFieldLineageAnalyzer;
import io.contexa.contexacore.std.components.prompt.PromptFieldStateLedger;
import io.contexa.contexacore.std.components.prompt.PromptFieldStateLedgerFactory;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptSourceContextSnapshot;
import io.contexa.contexacore.std.components.prompt.PromptSourceContextSnapshotFactory;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

import java.util.LinkedHashMap;
import java.util.Map;

public class PromptEvidenceComposer {

    private final PromptGenerator promptGenerator;

    public PromptEvidenceComposer(PromptGenerator promptGenerator) {
        this.promptGenerator = promptGenerator;
    }

    public <T extends DomainContext> PromptEvidenceComposition compose(
            AIRequest<T> request,
            PipelineExecutionContext context
    ) {
        long stepStartTime = System.currentTimeMillis();

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
        captureSecurityDecisionPromptLineage(request, context, promptResult);
        context.addMetadata("promptBuildLatencyMs", System.currentTimeMillis() - stepStartTime);
        context.addStepResult(PipelineConfiguration.PipelineStep.PROMPT_GENERATION, promptResult);

        return new PromptEvidenceComposition(promptResult, context);
    }

    public boolean canCompose() {
        return promptGenerator != null;
    }

    private <T extends DomainContext> void captureSecurityDecisionPromptLineage(
            AIRequest<T> request,
            PipelineExecutionContext context,
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
        PromptSourceContextSnapshot sourceSnapshot = PromptSourceContextSnapshotFactory.capture(securityDecisionContext);
        putMetadataMap(metadata, context, sourceSnapshot.toMetadataMap());
        putIfPresent(metadata, "systemPrompt", promptResult.getSystemPrompt());
        putIfPresent(metadata, "userPrompt", promptResult.getUserPrompt());
        putIfPresent(metadata, "rawSystemPrompt", promptResult.getRawSystemPrompt());
        putIfPresent(metadata, "rawUserPrompt", promptResult.getRawUserPrompt());
        PromptFieldLineageAnalysis fieldLineage = PromptFieldLineageAnalyzer.analyze(
                promptResult.getRawUserPrompt(),
                promptResult.getUserPrompt());
        putMetadataMap(metadata, context, fieldLineage.toMetadataMap());
        PromptFieldStateLedger fieldStateLedger = PromptFieldStateLedgerFactory.create(sourceSnapshot, fieldLineage);
        putMetadataMap(metadata, context, fieldStateLedger.toMetadataMap());
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
            copyIfPresent(promptResult.getMetadata(), metadata, "promptCacheSystemStable");
            copyIfPresent(promptResult.getMetadata(), metadata, "promptCacheSystemHash");
            copyIfPresent(promptResult.getMetadata(), metadata, "promptCacheContextMode");
            copyIfPresent(promptResult.getMetadata(), metadata, "pqaReferencePrompt");
            copyIfPresent(promptResult.getMetadata(), metadata, "pqaRawPromptRole");
            copyIfPresent(promptResult.getMetadata(), metadata, "pqaPromptCachePolicy");
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

    private void putMetadataMap(
            Map<String, Object> eventMetadata,
            PipelineExecutionContext context,
            Map<String, Object> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            eventMetadata.put(entry.getKey(), entry.getValue());
            if (context != null) {
                context.addMetadata(entry.getKey(), entry.getValue());
            }
        }
    }

    public record PromptEvidenceComposition(
            PromptGenerationResult promptResult,
            PipelineExecutionContext executionContext
    ) {
    }
}
