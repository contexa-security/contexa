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
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.properties.TieredStrategyProperties;
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
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class PromptEvidenceComposer {

    private final PromptGenerator promptGenerator;
    private final TieredStrategyProperties tieredStrategyProperties;

    public PromptEvidenceComposer(PromptGenerator promptGenerator) {
        this(promptGenerator, new TieredStrategyProperties());
    }

    public PromptEvidenceComposer(PromptGenerator promptGenerator, TieredStrategyProperties tieredStrategyProperties) {
        this.promptGenerator = promptGenerator;
        this.tieredStrategyProperties = tieredStrategyProperties != null
                ? tieredStrategyProperties
                : new TieredStrategyProperties();
    }

    public <T extends DomainContext> PromptEvidenceComposition compose(
            AIRequest<T> request,
            PipelineExecutionContext context) {
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

        copyPromptMetadata(promptResult, metadata, context);
        putPromptLength(metadata, context, "systemPromptLength", promptResult.getSystemPrompt());
        putPromptLength(metadata, context, "userPromptLength", promptResult.getUserPrompt());
        putPromptLength(metadata, context, "totalPromptLength", joinPrompts(promptResult.getSystemPrompt(), promptResult.getUserPrompt()));
        putPromptLength(metadata, context, "rawSystemPromptLength", promptResult.getRawSystemPrompt());
        putPromptLength(metadata, context, "rawUserPromptLength", promptResult.getRawUserPrompt());
        putPromptLength(metadata, context, "rawTotalPromptLength", joinPrompts(promptResult.getRawSystemPrompt(), promptResult.getRawUserPrompt()));

        if (!shouldCaptureFullLineage(metadata)) {
            putMetadataValue(metadata, context, "promptLineageCaptureMode", "LIGHTWEIGHT_RUNTIME");
            putMetadataValue(metadata, context, "promptRuntimeTelemetryLinked", Boolean.TRUE);
            putMetadataValue(metadata, context, "promptRuntimeTelemetryLayer", "LIGHTWEIGHT_RUNTIME");
            return;
        }
        putMetadataValue(metadata, context, "promptLineageCaptureMode", "FULL_OFFICIAL_VERIFICATION");

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
    }

    private boolean shouldCaptureFullLineage(Map<String, Object> metadata) {
        TieredStrategyProperties.PromptRuntime promptRuntime = tieredStrategyProperties.getPromptRuntime();
        if (promptRuntime == null || !promptRuntime.isTelemetryEnabled()) {
            return false;
        }
        TieredStrategyProperties.PromptRuntime.PromptLineageCaptureMode mode = promptRuntime.getLineageCaptureMode();
        if (mode == null) {
            mode = TieredStrategyProperties.PromptRuntime.PromptLineageCaptureMode.OFFICIAL_VERIFICATION;
        }
        return switch (mode) {
            case ALWAYS -> true;
            case DISABLED -> false;
            case OFFICIAL_VERIFICATION -> hasOfficialVerificationMarker(metadata);
        };
    }

    private boolean hasOfficialVerificationMarker(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return false;
        }
        return metadata.keySet().stream()
                .filter(key -> key != null && !key.isBlank())
                .anyMatch(this::isOfficialVerificationMarker);
    }

    private boolean isOfficialVerificationMarker(String key) {
        if (key.startsWith("officialVerification") || key.contains("OfficialVerification")) {
            return true;
        }
        return key.startsWith("pqaOfficial")
                || key.startsWith("pqaRuntimeOfficial")
                || key.startsWith("pqaVerificationRun")
                || key.startsWith("pqaOfficialVerification");
    }

    private void copyPromptMetadata(
            PromptGenerationResult promptResult,
            Map<String, Object> eventMetadata,
            PipelineExecutionContext context) {
        if (promptResult == null || promptResult.getMetadata() == null || promptResult.getMetadata().isEmpty()) {
            return;
        }
        for (Map.Entry<String, Object> entry : promptResult.getMetadata().entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            eventMetadata.putIfAbsent(entry.getKey(), entry.getValue());
            if (context != null) {
                context.addMetadata(entry.getKey(), eventMetadata.get(entry.getKey()));
            }
        }
    }

    private String joinPrompts(String first, String second) {
        if (first == null || first.isBlank()) {
            return second;
        }
        if (second == null || second.isBlank()) {
            return first;
        }
        return first + "\n" + second;
    }

    private void putPromptLength(
            Map<String, Object> eventMetadata,
            PipelineExecutionContext context,
            String key,
            String prompt) {
        if (prompt == null) {
            return;
        }
        putMetadataValue(eventMetadata, context, key, prompt.length());
    }

    private void putMetadataValue(
            Map<String, Object> eventMetadata,
            PipelineExecutionContext context,
            String key,
            Object value) {
        if (eventMetadata == null || key == null || value == null) {
            return;
        }
        eventMetadata.put(key, value);
        if (context != null) {
            context.addMetadata(key, value);
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

