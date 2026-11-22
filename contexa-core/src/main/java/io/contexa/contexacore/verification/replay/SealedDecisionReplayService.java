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
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.tiered.prompt.PastRecordLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.SealedReplayContextMissingException;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionCitationCheck;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.strategy.SealedDecisionReplayStrategy;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.gate.ModelServerSignals;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * A sealed decision drawn again with a chosen bundle and asked once (V-2.2 of the v21 plan), to measure a bundle on the
 * inputs real decisions were made on without running the applications again. The prompt is drawn from the sealed
 * inputs and the baselines the caller gives (those the decision was drawn against), through the engine's prompt
 * template, pipeline and first-layer request options; the answer is returned and nothing else follows from it. The
 * sealed inputs may be those of a package of the store or ones built in memory in that form (a labelled case of the
 * quality plan, 3.2): the replay reads the inputs, not the seal.
 */
@Slf4j
public class SealedDecisionReplayService {

    /**
     * Why a call gave no decision although the model answered, as the engine names it: an answer cut at the output
     * limit or ended at the context window, a refusal, an empty answer, an answer that broke the response contract.
     * Any other reason is one of the model server or of time (busy, unreachable, a time limit).
     */
    private static final Set<String> MODEL_ANSWERED = Set.of("OUTPUT_TRUNCATED", "MODEL_CONTEXT_WINDOW_EXCEEDED",
            "PROVIDER_REFUSAL", "EMPTY_RESPONSE", "VALIDATION_FAILED");

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
     * What to replay (quality plan 3.3).
     *
     * @param sealed               the sealed inputs: a package of the store, or one built in memory in its form
     * @param personalBaseline     the person's baseline the decision was drawn against; null when it had none
     * @param organizationBaseline the organization's, likewise
     * @param bundleVersion        the version the prompt is drawn with
     * @param timeout              the longest one pass waits
     * @param secondPassModels     the models the second pass is asked with by name, after an ESCALATE of the first
     * @param configuredSecondPass whether the second pass is also asked with the second layer's own model, the one the
     *                             server is set to, before the named ones
     * @param contextFormatVersion the version of the context format the sealed inputs are written in, compared with
     *                             {@link SealedDecisionReplayInputs#CONTEXT_FORMAT_VERSION}; null when the inputs do not
     *                             say, as a package this server sealed, which is read as it is
     * @param scope                quality plan 3.2: the registry scope the version is read in (a labelled case's is its
     *                             measurement's); null for the store's own, as a decision sealed here names its version
     * @param timeZone             quality plan 3.2: the time zone the prompt's times are drawn in (a labelled case
     *                             fixes its own, so that it is the same input on every server); null for the time zone
     *                             of the events of this server
     */
    public record Request(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                          BaselineVector organizationBaseline, String bundleVersion, Duration timeout,
                          List<String> secondPassModels, boolean configuredSecondPass, String contextFormatVersion,
                          String scope, ZoneId timeZone) {

        /** A replay of the version of the store's own scope, drawn in the time zone of the events of this server. */
        public Request(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                       BaselineVector organizationBaseline, String bundleVersion, Duration timeout,
                       List<String> secondPassModels, boolean configuredSecondPass, String contextFormatVersion) {
            this(sealed, personalBaseline, organizationBaseline, bundleVersion, timeout, secondPassModels,
                    configuredSecondPass, contextFormatVersion, null, null);
        }
    }

    /**
     * What a replay came to (quality plan 3.3): a failure of the measurement is no answer of the prompt, so the two are
     * told apart. Only {@link #ANSWERED} and {@link #MODEL_ANSWER_UNUSABLE} say something about the prompt.
     */
    public enum Outcome {
        /** The model's answer gave the action. */
        ANSWERED,
        /**
         * The model answered, but its answer could not be used and the engine set the action: no usable form, a
         * response contract still broken after the retry, an answer cut or refused.
         */
        MODEL_ANSWER_UNUSABLE,
        /**
         * The model gave no answer: its server was busy or could not be reached, a time limit ended the call, or the
         * engine's pipeline is not there. The replay may be asked again; an action the engine set meanwhile is no
         * answer of the prompt.
         */
        INFRASTRUCTURE_FAILURE,
        /**
         * The sealed context was not there when the prompt was drawn. The prompt is not drawn with the context of now
         * instead, so the replay ends; it may be asked again.
         */
        CONTEXT_MISSING,
        /** The inputs are written in a context format this build does not read; they need to be migrated. */
        CONTEXT_FORMAT_MISMATCH,
        /** The sealed inputs could not be read: no canonical context, or a section that is no JSON. */
        INPUT_UNREADABLE,
        /** The replay failed for another reason, inside the engine. */
        REPLAY_ERROR
    }

    /**
     * One model call of a replay, in the order the calls were made (the first answer, its corrective retry).
     *
     * @param callMs     how long the provider call took; null when it was not measured
     * @param gateWaitMs how long the call waited at the model server's gate; null when it did not go through one
     * @param timeoutMs  the call's time limit; null when it had none
     * @param failed     whether the call ended without an answer
     */
    public record ModelCall(Long callMs, Long gateWaitMs, Long timeoutMs, boolean failed) {
    }

    /**
     * What one replay answered.
     *
     * @param replayedRequestId the request the sealed package belongs to
     * @param replayId          the replay's own request id, under which the engine recorded the model call
     * @param packageId         the sealed package
     * @param bundleVersion     the bundle the prompt was drawn with
     * @param action            the action the pipeline's response gave, null without a response; after a failure of the
     *                          model call it is the action the engine set, which {@code outcome} tells
     * @param reason            the reason the answer gave
     * @param reasonCodes       the reason codes with the fact IDs they cite
     * @param hypotheses        the explanations a v21 answer weighed
     * @param unresolvedFindings what a v21 answer still said wrongly after its retry, or null
     * @param telemetry         the runtime telemetry of the call (tokens, retries, model, timings)
     * @param elapsedMs         the wall time of the replay
     * @param failure           why the replay gave no answer, or null
     * @param outcome           what the replay came to
     * @param modelAction       the action the model's own answer gave before any rule of the engine replaced it: the
     *                          response's action when the model's answer stood, the retry's answer when the response
     *                          contract replaced it, null when no action could be read from the model
     * @param systemPrompt      the system prompt drawn for the model call, null when none was drawn
     * @param userPrompt        the user prompt drawn for the model call, likewise
     * @param citationCheck     what the response check found of each reason code of the answer that was kept
     * @param modelCalls        the model calls in their order, each with its times
     */
    public record Result(String replayedRequestId, String replayId, String packageId, String bundleVersion,
                         String action, String reason, List<SecurityDecisionOutputContract.Citation> reasonCodes,
                         Object hypotheses, Object unresolvedFindings, Map<String, Object> telemetry, long elapsedMs,
                         String failure, List<SecondPass> secondPasses, Outcome outcome, String modelAction,
                         String systemPrompt, String userPrompt, SecurityDecisionCitationCheck citationCheck,
                         List<ModelCall> modelCalls) {

        /** An answer without what quality plan 3.3 adds: answered when it names no failure. */
        public Result(String replayedRequestId, String replayId, String packageId, String bundleVersion,
                      String action, String reason, List<SecurityDecisionOutputContract.Citation> reasonCodes,
                      Object hypotheses, Object unresolvedFindings, Map<String, Object> telemetry, long elapsedMs,
                      String failure, List<SecondPass> secondPasses) {
            this(replayedRequestId, replayId, packageId, bundleVersion, action, reason, reasonCodes, hypotheses,
                    unresolvedFindings, telemetry, elapsedMs, failure, secondPasses,
                    failure == null ? Outcome.ANSWERED : Outcome.REPLAY_ERROR, failure == null ? action : null, null,
                    null, null, List.of());
        }
    }

    /**
     * What the second pass Layer2 would ask answered with one model (decision layer design, section 7), after a first pass replay that
     * answered ESCALATE.
     *
     * @param requestedModel the model the second pass was asked with; null for the second layer's own model, the one
     *                       the server is set to
     * @param telemetry      the runtime telemetry of the call, with the model that answered
     * @param failure        why it gave no answer: no first prompt kept, a first pass state the replay cannot give
     *                       the second pass (its own search is not replayed), or the call's failure; null otherwise
     * @param outcome        what the second pass came to, as a replay's
     * @param modelAction    the action the model's own answer gave, as a replay's
     * @param systemPrompt   the system prompt drawn for the second pass
     * @param userPrompt     the user prompt drawn for the second pass, the first prompt with its SECOND PASS block
     * @param citationCheck  what the response check found of each reason code of the answer that was kept
     * @param modelCalls     the model calls in their order, each with its times
     */
    public record SecondPass(String requestedModel, String action, String reason,
                             List<SecurityDecisionOutputContract.Citation> reasonCodes, Object hypotheses,
                             Object unresolvedFindings, Map<String, Object> telemetry, long elapsedMs, String failure,
                             Outcome outcome, String modelAction, String systemPrompt, String userPrompt,
                             SecurityDecisionCitationCheck citationCheck, List<ModelCall> modelCalls) {
    }

    /**
     * The prompts a sealed decision draws with a version, the model not asked (plan 3.10 (2): the finished prompt of
     * the version screen).
     *
     * @param packageId    the sealed package the prompts were drawn from
     * @param version      the version they were drawn with ({@code v2.0}, or a bundle this build runs)
     * @param contentHash  the content hash of that version
     * @param systemPrompt the system prompt as the replay's model call gets it, with the output format when the call
     *                     does not carry the schema itself
     * @param userPrompt   the user prompt of the first pass with the sealed decision's values, with the blocks the
     *                     version adds at their places
     */
    public record Drawing(String packageId, String version, String contentHash, String systemPrompt,
                          String userPrompt) {
    }

    /**
     * Plan 3.10 (2): the first pass prompts the sealed inputs draw with the version, on the baselines the caller gives,
     * as a replay draws them for its model call (the same sealed inputs, first-layer request options, template and
     * version fixed on the event), but without the call: nothing is asked, applied, learned or sealed.
     *
     * @throws IllegalArgumentException when the version is none this server can draw
     */
    public Drawing draw(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                        BaselineVector organizationBaseline, String version) {
        String name = version != null ? version.trim() : null;
        if (!replayable(name)) {
            throw new IllegalArgumentException(PromptBundleCatalog.isVersionName(name)
                    ? "Version " + name + " is not a version this server can draw"
                    : "Bundle " + name + " is not a bundle this build runs");
        }
        SealedDecisionReplayInputs inputs = SealedDecisionReplayInputs.of(sealed,
                SealedDecisionReplayInputs.REPLAY_ID_PREFIX + UUID.randomUUID(), objectMapper, serializer);
        SecurityDecisionRequest request = strategy(SealedDecisionReplayStrategy.FIRST_LAYER, personalBaseline,
                organizationBaseline).request(inputs, name);
        String systemPrompt = promptTemplate.generateSystemPrompt(request, null);
        String userPrompt = promptTemplate.generateUserPrompt(request, null);
        Object contentHash = inputs.event().getMetadata() != null
                ? inputs.event().getMetadata().get(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH) : null;
        return new Drawing(sealed.getPackageId(), name, contentHash != null ? String.valueOf(contentHash) : null,
                systemPrompt, userPrompt);
    }

    public Result replay(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                         BaselineVector organizationBaseline, String bundleVersion, Duration timeout) {
        return replay(sealed, personalBaseline, organizationBaseline, bundleVersion, timeout, List.of());
    }

    /**
     * The replay, and when it answers ESCALATE the second pass Layer2 would ask, once per given model in that order
     * (decision layer design, section 7: the same second pass on different models).
     */
    public Result replay(SealedEvidencePackage sealed, BaselineVector personalBaseline,
                         BaselineVector organizationBaseline, String bundleVersion, Duration timeout,
                         List<String> secondPassModels) {
        return replay(new Request(sealed, personalBaseline, organizationBaseline, bundleVersion, timeout,
                secondPassModels, false, null));
    }

    /**
     * The replay of the request (quality plan 3.3): the first pass, and when it answers ESCALATE the second pass, with
     * the second layer's own model when the request asks for it and then once per named model. The answer says what
     * the replay came to, and carries the prompts drawn, the citation check and the model calls' times.
     *
     * @throws IllegalArgumentException when the version is none this server can draw
     */
    public Result replay(Request request) {
        SealedEvidencePackage sealed = request.sealed();
        String bundleVersion = request.bundleVersion();
        if (!replayable(request.scope(), bundleVersion)) {
            throw new IllegalArgumentException(PromptBundleCatalog.isVersionName(bundleVersion)
                    ? "Version " + bundleVersion + " is not a version this server can draw"
                    : "Bundle " + bundleVersion + " is not a bundle this build runs");
        }
        String replayId = SealedDecisionReplayInputs.REPLAY_ID_PREFIX + UUID.randomUUID();
        long started = System.nanoTime();
        String format = request.contextFormatVersion() != null ? request.contextFormatVersion().trim() : null;
        if (format != null && !SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION.equals(format)) {
            // Quality plan 9: inputs of another context format are not read as if they were of this one.
            log.warn("Replay of {} with bundle {} refused: its inputs are of context format {}, this build reads {}",
                    sealed.getPackageId(), bundleVersion, format, SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION);
            return failed(sealed, replayId, bundleVersion, Outcome.CONTEXT_FORMAT_MISMATCH,
                    Outcome.CONTEXT_FORMAT_MISMATCH + ": the inputs are of context format " + format
                            + ", this build reads " + SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION, started);
        }
        if (pipelineOrchestrator == null) {
            log.warn("Replay of {} with bundle {} not run: the decision pipeline is not available",
                    sealed.getPackageId(), bundleVersion);
            return failed(sealed, replayId, bundleVersion, Outcome.INFRASTRUCTURE_FAILURE, "PIPELINE_UNAVAILABLE",
                    started);
        }
        SealedDecisionReplayInputs inputs;
        try {
            inputs = SealedDecisionReplayInputs.of(sealed, replayId, objectMapper, serializer);
            fixScopeAndClock(inputs, request);
        }
        catch (RuntimeException exception) {
            log.error("Replay of {} with bundle {} failed: its sealed inputs could not be read",
                    sealed.getPackageId(), bundleVersion, exception);
            return failed(sealed, replayId, bundleVersion, Outcome.INPUT_UNREADABLE,
                    exception.getClass().getSimpleName() + ": " + exception.getMessage(), started);
        }
        try {
            SealedDecisionReplayStrategy strategy = strategy(SealedDecisionReplayStrategy.FIRST_LAYER,
                    request.personalBaseline(), request.organizationBaseline());
            SecurityDecisionResponse response = strategy.replay(inputs, bundleVersion, request.timeout());
            Map<String, Object> metadata = response != null ? response.getAllMetadata() : Map.of();
            List<SecondPass> secondPasses = secondPasses(request, inputs, response, replayId);
            Outcome outcome = response == null ? Outcome.INFRASTRUCTURE_FAILURE : outcomeOf(metadata);
            return new Result(sealed.getCorrelationId(), replayId, sealed.getPackageId(), bundleVersion,
                    response != null ? response.getAction() : null, response != null ? response.getReasoning() : null,
                    response != null && response.getReasonCodes() != null ? response.getReasonCodes() : List.of(),
                    metadata.get(SecurityDecisionV21OutputInspector.HYPOTHESES),
                    metadata.get(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS), telemetry(metadata),
                    elapsedMillis(started), response == null ? "NO_RESPONSE" : null, secondPasses, outcome,
                    modelAction(outcome, response, metadata),
                    drawn(metadata.get(PromptRuntimeTelemetrySupport.DRAWN_SYSTEM_PROMPT)),
                    drawn(metadata.get(PromptRuntimeTelemetrySupport.DRAWN_USER_PROMPT)),
                    SecurityDecisionCitationCheck.of(metadata.get(SecurityDecisionCitationCheck.METADATA_KEY)),
                    modelCalls(metadata));
        }
        catch (RuntimeException exception) {
            Outcome outcome = outcomeOf(exception);
            if (outcome == Outcome.REPLAY_ERROR) {
                log.error("Replay of sealed package {} with bundle {} failed", sealed.getPackageId(), bundleVersion,
                        exception);
            }
            else {
                // A time limit, a busy or unreachable model server, a sealed context no longer kept: the replay may be
                // asked again, and the failure is told to the caller.
                log.warn("Replay of sealed package {} with bundle {} gave no answer ({}): {}", sealed.getPackageId(),
                        bundleVersion, outcome, exception.toString());
            }
            return failed(sealed, replayId, bundleVersion, outcome,
                    exception.getClass().getSimpleName() + ": " + exception.getMessage(), started);
        }
    }

    /**
     * Plan 3.9: whether the replay can draw the release: a version of the database the store of the template reads
     * ({@code v2.0}), or a bundle this build runs. A version the store does not have would be drawn as the product
     * version under its name, so it is refused.
     */
    public boolean replayable(String release) {
        return replayable(null, release);
    }

    /**
     * Quality plan 3.2: whether the replay can draw the release with the version of that name in the registry scope;
     * the store's own scope when none is given.
     */
    public boolean replayable(String scope, String release) {
        if (release == null || release.isBlank()) {
            return false;
        }
        if (PromptBundleCatalog.isVersionName(release)) {
            return promptTemplate.findPromptVersion(scope, release.trim()).isPresent();
        }
        return SecurityDecisionPromptBundles.find(release).isPresent();
    }

    /**
     * Quality plan 3.2: the registry scope the version is read in and the time zone the times are drawn in, fixed on
     * the replay's event as the request names them; nothing the sealed inputs carry under those names counts.
     */
    private static void fixScopeAndClock(SealedDecisionReplayInputs inputs, Request request) {
        SecurityEvent event = inputs.event();
        if (event.getMetadata() != null) {
            event.getMetadata().remove(SecurityDecisionPromptSections.EVENT_BUNDLE_SCOPE);
            event.getMetadata().remove(EventTimeZone.EVENT_METADATA_KEY);
        }
        if (request.scope() != null && !request.scope().isBlank()) {
            event.addMetadata(SecurityDecisionPromptSections.EVENT_BUNDLE_SCOPE, request.scope().trim());
        }
        if (request.timeZone() != null) {
            event.addMetadata(EventTimeZone.EVENT_METADATA_KEY, request.timeZone());
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
     * pass's own search, which a replay does not run, so that second pass is not asked. Quality plan 3.3: the second
     * layer's own model, the one the server is set to, is asked first when the request says so, under no name.
     */
    private List<SecondPass> secondPasses(Request request, SealedDecisionReplayInputs first,
                                          SecurityDecisionResponse answer, String replayId) {
        List<String> models = new ArrayList<>();
        if (request.configuredSecondPass()) {
            models.add(null);
        }
        if (request.secondPassModels() != null) {
            models.addAll(request.secondPassModels());
        }
        if (models.isEmpty() || answer == null || answer.getAction() == null
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
                passes.add(failed(model, Outcome.REPLAY_ERROR, "NO_FIRST_PROMPT", started));
                continue;
            }
            if (state == null || state.isEmpty()
                    || PastRecordLineValues.NOT_RETRIEVED_STATES.contains(state.toUpperCase(Locale.ROOT))) {
                passes.add(failed(model, Outcome.REPLAY_ERROR, "SECOND_PASS_SEARCH_NOT_REPLAYED", started));
                continue;
            }
            try {
                SealedDecisionReplayInputs inputs = SealedDecisionReplayInputs.of(request.sealed(),
                        replayId + "-second-" + (index + 1), objectMapper, serializer);
                fixScopeAndClock(inputs, request);
                SecurityDecisionResponse response = strategy(SealedDecisionReplayStrategy.SECOND_LAYER,
                        request.personalBaseline(), request.organizationBaseline())
                        .replaySecondPass(inputs, request.bundleVersion(), prompt, state, model, request.timeout());
                Map<String, Object> metadata = response != null ? response.getAllMetadata() : Map.of();
                Outcome outcome = response == null ? Outcome.INFRASTRUCTURE_FAILURE : outcomeOf(metadata);
                passes.add(new SecondPass(model, response != null ? response.getAction() : null,
                        response != null ? response.getReasoning() : null,
                        response != null && response.getReasonCodes() != null ? response.getReasonCodes() : List.of(),
                        metadata.get(SecurityDecisionV21OutputInspector.HYPOTHESES),
                        metadata.get(SecurityDecisionV21OutputInspector.UNRESOLVED_FINDINGS), telemetry(metadata),
                        elapsedMillis(started), response == null ? "NO_RESPONSE" : null, outcome,
                        modelAction(outcome, response, metadata),
                        drawn(metadata.get(PromptRuntimeTelemetrySupport.DRAWN_SYSTEM_PROMPT)),
                        drawn(metadata.get(PromptRuntimeTelemetrySupport.DRAWN_USER_PROMPT)),
                        SecurityDecisionCitationCheck.of(metadata.get(SecurityDecisionCitationCheck.METADATA_KEY)),
                        modelCalls(metadata)));
            }
            catch (RuntimeException exception) {
                Outcome outcome = outcomeOf(exception);
                if (outcome == Outcome.REPLAY_ERROR) {
                    log.error("Second pass replay of sealed package {} with model {} failed",
                            request.sealed().getPackageId(), model, exception);
                }
                else {
                    log.warn("Second pass replay of sealed package {} with model {} gave no answer ({}): {}",
                            request.sealed().getPackageId(), model, outcome, exception.toString());
                }
                passes.add(failed(model, outcome, exception.getClass().getSimpleName() + ": " + exception.getMessage(),
                        started));
            }
        }
        return List.copyOf(passes);
    }

    private static SecondPass failed(String model, Outcome outcome, String failure, long startedNanos) {
        return new SecondPass(model, null, null, List.of(), null, null, Map.of(), elapsedMillis(startedNanos), failure,
                outcome, null, null, null, null, List.of());
    }

    private static Result failed(SealedEvidencePackage sealed, String replayId, String bundleVersion, Outcome outcome,
                                 String failure, long startedNanos) {
        return new Result(sealed.getCorrelationId(), replayId, sealed.getPackageId(), bundleVersion, null, null,
                List.of(), null, null, Map.of(), elapsedMillis(startedNanos), failure, List.of(), outcome, null, null,
                null, null, List.of());
    }

    /**
     * Quality plan 3.3: what a pipeline response came to, read from the marks the engine leaves on it. A model call
     * that failed leaves the engine's safe-side action on the response, so the action alone does not tell.
     */
    static Outcome outcomeOf(Map<String, Object> metadata) {
        if (Boolean.FALSE.equals(bool(metadata.get("rawExecutionSucceeded")))) {
            String category = text(metadata.get("structuredOutputFailureCategory"));
            if (category == null) {
                category = text(metadata.get("securityDecisionParseFailureCategory"));
            }
            return category != null && MODEL_ANSWERED.contains(category.toUpperCase(Locale.ROOT))
                    ? Outcome.MODEL_ANSWER_UNUSABLE : Outcome.INFRASTRUCTURE_FAILURE;
        }
        if (Boolean.TRUE.equals(bool(metadata.get("securityDecisionParsingFallbackApplied")))
                || Boolean.TRUE.equals(bool(metadata.get("securityDecisionFallbackApplied")))
                || Boolean.FALSE.equals(bool(metadata.get("llmDecisionPresent")))
                || text(metadata.get("securityDecisionContractFallbackAction")) != null) {
            return Outcome.MODEL_ANSWER_UNUSABLE;
        }
        return Outcome.ANSWERED;
    }

    /**
     * Quality plan 3.3: what a replay that ended in a failure came to: the sealed context no longer kept, a time limit
     * or a busy or unreachable model server, or a failure of the engine itself.
     */
    static Outcome outcomeOf(Throwable failure) {
        for (Throwable current = failure; current != null;
             current = current.getCause() != current ? current.getCause() : null) {
            if (current instanceof SealedReplayContextMissingException) {
                return Outcome.CONTEXT_MISSING;
            }
        }
        return ModelServerSignals.isTimeLimit(failure) || ModelServerSignals.isUnreachable(failure)
                || ModelServerSignals.isOverload(failure) ? Outcome.INFRASTRUCTURE_FAILURE : Outcome.REPLAY_ERROR;
    }

    /**
     * The action the model's own answer gave, within what the engine's marks say: the response's action while the
     * model's answer stands; the retry's answer when the response contract replaced it; none when the model gave no
     * usable action.
     */
    private static String modelAction(Outcome outcome, SecurityDecisionResponse response, Map<String, Object> metadata) {
        if (outcome == Outcome.ANSWERED) {
            return response != null ? response.getAction() : null;
        }
        if (outcome == Outcome.MODEL_ANSWER_UNUSABLE
                && text(metadata.get("securityDecisionContractFallbackAction")) != null) {
            return text(metadata.get("securityDecisionRetryAction"));
        }
        return null;
    }

    /** The model calls of a run in their order, as the pipeline step kept them. */
    private static List<ModelCall> modelCalls(Map<String, Object> metadata) {
        if (!(metadata.get(PromptRuntimeTelemetrySupport.MODEL_CALLS) instanceof List<?> kept)) {
            return List.of();
        }
        List<ModelCall> calls = new ArrayList<>();
        for (Object entry : kept) {
            if (entry instanceof Map<?, ?> call) {
                calls.add(new ModelCall(number(call.get("callMs")), number(call.get("gateWaitMs")),
                        number(call.get("timeoutMs")), Boolean.TRUE.equals(call.get("failed"))));
            }
        }
        return List.copyOf(calls);
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

    private static Boolean bool(Object value) {
        if (value instanceof Boolean flag) {
            return flag;
        }
        return value == null ? null : Boolean.valueOf(String.valueOf(value).trim());
    }

    private static Long number(Object value) {
        return value instanceof Number number ? Long.valueOf(number.longValue()) : null;
    }

    /** A prompt as it was drawn, every character of it: the citation check reads its lines, so nothing is trimmed. */
    private static String drawn(Object value) {
        return value instanceof String prompt && !prompt.isEmpty() ? prompt : null;
    }

    private static String text(Object value) {
        return value != null && !String.valueOf(value).isBlank() ? String.valueOf(value).trim() : null;
    }

    private static long elapsedMillis(long startedNanos) {
        return Duration.ofNanos(System.nanoTime() - startedNanos).toMillis();
    }
}
