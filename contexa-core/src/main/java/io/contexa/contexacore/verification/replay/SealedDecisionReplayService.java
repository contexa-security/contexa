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
package io.contexa.contexacore.verification.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.tiered.prompt.PastRecordLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.strategy.SealedDecisionReplayStrategy;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * A sealed decision drawn again with a chosen bundle and asked once (V-2.2 of the v21 plan), to measure a bundle on the
 * inputs real decisions were made on without running the applications again. The prompt is drawn from the sealed
 * inputs and the baselines the caller gives (those the decision was drawn against), through the engine's prompt
 * template, pipeline and first-layer request options; the answer is returned and nothing else follows from it.
 */
@Slf4j
public class SealedDecisionReplayService {

    private final SecurityDecisionStandardPromptTemplate promptTemplate;
    private final PipelineOrchestrator pipelineOrchestrator;
    private final BaselineLearningService baselineLearningService;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry;
    private final Supplier<ModelSelectionStrategy> modelSelectionStrategy;
    private final MinimumActionRules.Settings minimumActionSettings;
    private final String minimumActionMode;
    private final CanonicalSecurityContextSerializer serializer;
    private final ObjectMapper objectMapper;

    public SealedDecisionReplayService(SecurityDecisionStandardPromptTemplate promptTemplate,
                                       PipelineOrchestrator pipelineOrchestrator,
                                       BaselineLearningService baselineLearningService,
                                       TieredStrategyProperties tieredStrategyProperties,
                                       StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
                                       Supplier<ModelSelectionStrategy> modelSelectionStrategy,
                                       MinimumActionRules.Settings minimumActionSettings,
                                       String minimumActionMode,
                                       CanonicalSecurityContextSerializer serializer,
                                       ObjectMapper objectMapper) {
        this.promptTemplate = promptTemplate;
        this.pipelineOrchestrator = pipelineOrchestrator;
        this.baselineLearningService = baselineLearningService;
        this.tieredStrategyProperties = tieredStrategyProperties;
        this.structuredOutputCapabilityRegistry = structuredOutputCapabilityRegistry;
        this.modelSelectionStrategy = modelSelectionStrategy;
        this.minimumActionSettings = minimumActionSettings;
        this.minimumActionMode = minimumActionMode;
        this.serializer = serializer;
        this.objectMapper = objectMapper;
    }

    /**
     * What one replay answered.
     *
     * @param replayedRequestId the request the sealed package belongs to
     * @param replayId          the replay's own request id, under which the engine recorded the model call
     * @param packageId         the sealed package
     * @param bundleVersion     the bundle the prompt was drawn with
     * @param action            the action the answer gave, null on a failure
     * @param reason            the reason the answer gave
     * @param reasonCodes       the reason codes with the fact IDs they cite
     * @param hypotheses        the explanations a v21 answer weighed
     * @param unresolvedFindings what a v21 answer still said wrongly after its retry, or null
     * @param telemetry         the runtime telemetry of the call (tokens, retries, model, timings)
     * @param elapsedMs         the wall time of the replay
     * @param failure           why the replay gave no answer, or null
     */
    public record Result(String replayedRequestId, String replayId, String packageId, String bundleVersion,
                         String action, String reason, List<SecurityDecisionOutputContract.Citation> reasonCodes,
                         Object hypotheses, Object unresolvedFindings, Map<String, Object> telemetry, long elapsedMs,
                         String failure, List<SecondPass> secondPasses) {
    }

    /**
     * What the second pass Layer2 would ask answered with one model (판정층 7절), after a first pass replay that
     * answered ESCALATE.
     *
     * @param requestedModel the model the second pass was asked with
     * @param telemetry      the runtime telemetry of the call, with the model that answered
     * @param failure        why it gave no answer: no first prompt kept, a first pass state the replay cannot give
     *                       the second pass (its own search is not replayed), or the call's failure; null otherwise
     */
    public record SecondPass(String requestedModel, String action, String reason,
                             List<SecurityDecisionOutputContract.Citation> reasonCodes, Object hypotheses,
                             Object unresolvedFindings, Map<String, Object> telemetry, long elapsedMs, String failure) {
    }

    public Result replay(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                         BaselineVector organizationBaseline, String bundleVersion, Duration timeout) {
        return replay(sealed, personalBaseline, organizationBaseline, bundleVersion, timeout, List.of());
    }

    /**
     * The replay, and when it answers ESCALATE the second pass Layer2 would ask, once per given model in that order
     * (판정층 7절: the same second pass on different models).
     */
    public Result replay(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                         BaselineVector organizationBaseline, String bundleVersion, Duration timeout,
                         List<String> secondPassModels) {
        if (SecurityDecisionPromptBundles.find(bundleVersion).isEmpty()) {
            throw new IllegalArgumentException("Bundle " + bundleVersion + " is not a bundle this build runs");
        }
        String replayId = SealedDecisionReplayInputs.REPLAY_ID_PREFIX + UUID.randomUUID();
        long started = System.nanoTime();
        try {
            SealedDecisionReplayInputs inputs = SealedDecisionReplayInputs.of(sealed, replayId, objectMapper, serializer);
            SealedDecisionReplayStrategy strategy = strategy(SealedDecisionReplayStrategy.FIRST_LAYER,
                    personalBaseline, organizationBaseline);
            SecurityDecisionResponse response = strategy.replay(inputs, bundleVersion, timeout);
            Map<String, Object> metadata = response != null ? response.getAllMetadata() : Map.of();
            List<SecondPass> secondPasses = secondPasses(sealed, inputs, response, personalBaseline,
                    organizationBaseline, bundleVersion, timeout, replayId, secondPassModels);
            return new Result(sealed.getCorrelationId(), replayId, sealed.getPackageId(), bundleVersion,
                    response != null ? response.getAction() : null, response != null ? response.getReasoning() : null,
                    response != null && response.getReasonCodes() != null ? response.getReasonCodes() : List.of(),
                    metadata.get(SecurityDecisionV21OutputInspector.HYPOTHESES),
                    metadata.get(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS), telemetry(metadata),
                    elapsedMillis(started), response == null ? "NO_RESPONSE" : null, secondPasses);
        }
        catch (RuntimeException exception) {
            log.error("Replay of sealed package {} with bundle {} failed", sealed.getPackageId(), bundleVersion, exception);
            return new Result(sealed.getCorrelationId(), replayId, sealed.getPackageId(), bundleVersion, null, null,
                    List.of(), null, null, Map.of(), elapsedMillis(started),
                    exception.getClass().getSimpleName() + ": " + exception.getMessage(), List.of());
        }
    }

    private SealedDecisionReplayStrategy strategy(String layer, BaselineVector personalBaseline,
                                                  BaselineVector organizationBaseline) {
        SealedDecisionReplayStrategy strategy = new SealedDecisionReplayStrategy(promptTemplate, pipelineOrchestrator,
                baselineLearningService.readingFrom(
                        new SealedDecisionReplayInputs.SealedBaselines(personalBaseline, organizationBaseline)),
                tieredStrategyProperties, structuredOutputCapabilityRegistry, layer);
        strategy.setModelSelectionStrategy(modelSelectionStrategy);
        strategy.setMinimumActionSettings(minimumActionSettings, minimumActionMode);
        return strategy;
    }

    /**
     * The second passes after a first pass that answered ESCALATE: the first prompt the composer kept on the event and
     * the first pass's sealed past record state. A first pass that could not retrieve its records needs the second
     * pass's own search, which a replay does not run, so that second pass is not asked.
     */
    private List<SecondPass> secondPasses(SealedEvidencePackage sealed, SealedDecisionReplayInputs first,
                                          SecurityDecisionResponse answer, BaselineVector personalBaseline,
                                          BaselineVector organizationBaseline, String bundleVersion, Duration timeout,
                                          String replayId, List<String> models) {
        if (models == null || models.isEmpty() || answer == null || answer.getAction() == null
                || !"ESCALATE".equalsIgnoreCase(answer.getAction().trim())) {
            return List.of();
        }
        Map<String, Object> firstMetadata = first.event().getMetadata();
        Object firstPrompt = firstMetadata != null ? firstMetadata.get(PromptRuntimeTelemetrySupport.FIRST_PASS_USER_PROMPT)
                : null;
        Object stateValue = firstMetadata != null ? firstMetadata.get("ragRetrievalState") : null;
        String state = stateValue != null ? String.valueOf(stateValue).trim() : null;
        List<SecondPass> passes = new ArrayList<>();
        for (int index = 0; index < models.size(); index++) {
            String model = models.get(index);
            long started = System.nanoTime();
            if (!(firstPrompt instanceof String prompt) || prompt.isBlank()) {
                passes.add(failed(model, "NO_FIRST_PROMPT", started));
                continue;
            }
            if (state == null || state.isEmpty()
                    || PastRecordLineValues.NOT_RETRIEVED_STATES.contains(state.toUpperCase(Locale.ROOT))) {
                passes.add(failed(model, "SECOND_PASS_SEARCH_NOT_REPLAYED", started));
                continue;
            }
            try {
                SealedDecisionReplayInputs inputs = SealedDecisionReplayInputs.of(sealed,
                        replayId + "-second-" + (index + 1), objectMapper, serializer);
                SecurityDecisionResponse response = strategy(SealedDecisionReplayStrategy.SECOND_LAYER,
                        personalBaseline, organizationBaseline)
                        .replaySecondPass(inputs, bundleVersion, prompt, state, model, timeout);
                Map<String, Object> metadata = response != null ? response.getAllMetadata() : Map.of();
                passes.add(new SecondPass(model, response != null ? response.getAction() : null,
                        response != null ? response.getReasoning() : null,
                        response != null && response.getReasonCodes() != null ? response.getReasonCodes() : List.of(),
                        metadata.get(SecurityDecisionV21OutputInspector.HYPOTHESES),
                        metadata.get(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS), telemetry(metadata),
                        elapsedMillis(started), response == null ? "NO_RESPONSE" : null));
            }
            catch (RuntimeException exception) {
                log.error("Second pass replay of sealed package {} with model {} failed", sealed.getPackageId(), model,
                        exception);
                passes.add(failed(model, exception.getClass().getSimpleName() + ": " + exception.getMessage(), started));
            }
        }
        return List.copyOf(passes);
    }

    private static SecondPass failed(String model, String failure, long startedNanos) {
        return new SecondPass(model, null, null, List.of(), null, null, Map.of(), elapsedMillis(startedNanos), failure);
    }

    /** The runtime telemetry of a call with the model's output texts and retries. */
    private static Map<String, Object> telemetry(Map<String, Object> metadata) {
        Map<String, Object> telemetry = new LinkedHashMap<>(PromptRuntimeTelemetrySupport.extractRuntimeTelemetry(metadata));
        for (String key : PromptRuntimeTelemetrySupport.modelOutputTextKeys()) {
            if (metadata.get(key) != null) {
                telemetry.put(key, metadata.get(key));
            }
        }
        if (metadata.get(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES) != null) {
            telemetry.put(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES,
                    metadata.get(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES));
        }
        return telemetry;
    }

    private static long elapsedMillis(long startedNanos) {
        return Duration.ofNanos(System.nanoTime() - startedNanos).toMillis();
    }
}
