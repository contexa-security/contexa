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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.ThreatAssessment;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.List;

/**
 * One sealed decision drawn again with a chosen bundle and asked once (V-2.2 of the v21 plan): the request options of
 * the first layer (its model, effort, output limit, call limit and structured output), the prompt template and the
 * pipeline the engine runs, the baselines the decision was drawn against and its sealed canonical context. Nothing the
 * answer says is applied, learned or sealed; the caller only reads it.
 */
public class SealedDecisionReplayStrategy extends AbstractTieredStrategy {

    /** The layer whose request options a replay takes by default: the first layer's. */
    public static final String FIRST_LAYER = "Layer1";
    /** The layer of a second pass replay: its tier selects the second layer's model and its options apply. */
    public static final String SECOND_LAYER = "Layer2";
    private final PipelineOrchestrator pipelineOrchestrator;
    private final String layer;

    public SealedDecisionReplayStrategy(SecurityDecisionStandardPromptTemplate promptTemplate,
                                        PipelineOrchestrator pipelineOrchestrator,
                                        BaselineLearningService sealedBaselines,
                                        TieredStrategyProperties tieredStrategyProperties,
                                        StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry) {
        this(promptTemplate, pipelineOrchestrator, sealedBaselines, tieredStrategyProperties,
                structuredOutputCapabilityRegistry, FIRST_LAYER);
    }

    /** A replay with the request options, tier and model of the given layer ({@link #FIRST_LAYER}, {@link #SECOND_LAYER}). */
    public SealedDecisionReplayStrategy(SecurityDecisionStandardPromptTemplate promptTemplate,
                                        PipelineOrchestrator pipelineOrchestrator,
                                        BaselineLearningService sealedBaselines,
                                        TieredStrategyProperties tieredStrategyProperties,
                                        StructuredOutputCapabilityRegistry structuredOutputCapabilityRegistry,
                                        String layer) {
        super(null, promptTemplate, null, null, sealedBaselines, null, null, tieredStrategyProperties,
                structuredOutputCapabilityRegistry);
        this.pipelineOrchestrator = pipelineOrchestrator;
        this.layer = layer;
    }

    /** The answer of the pipeline to the sealed inputs drawn with the bundle of that version. */
    public SecurityDecisionResponse replay(SealedDecisionReplayInputs inputs, String bundleVersion, Duration timeout) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis = prepare(inputs, bundleVersion);
        return executeSecurityDecisionPipeline(pipelineOrchestrator, inputs.event(), inputs.session(), analysis,
                inputs.documents())
                .subscribeOn(Schedulers.boundedElastic())
                .block(timeout);
    }

    /**
     * The second pass Layer2 asks after a first pass that answered ESCALATE (판정층 7절): the first prompt as it was sent
     * with the SECOND PASS block, the first pass's past record state, on this strategy's layer, and the model named, or
     * the layer's own when none is.
     */
    public SecurityDecisionResponse replaySecondPass(SealedDecisionReplayInputs inputs, String bundleVersion,
                                                     String firstUserPrompt, String firstPastRecordsState, String model,
                                                     Duration timeout) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis = prepare(inputs, bundleVersion);
        SecurityEvent event = inputs.event();
        if (model != null && !model.isBlank()) {
            // The request names the model, as a runtime selection option the model selection follows.
            event.addMetadata("requestedModelId", model.trim());
        }
        SecurityDecisionRequest request = buildSecurityDecisionRequest(event, inputs.session(), analysis,
                inputs.documents());
        request.withParameter("layer2FirstPassUserPrompt", firstUserPrompt);
        request.withParameter("layer2FirstPassVerdict", ZeroTrustAction.ESCALATE.name());
        request.withParameter("layer2FirstPassPastRecordsState", firstPastRecordsState);
        return pipelineOrchestrator.execute(request, SECURITY_DECISION_PIPELINE_CONFIGURATION,
                        SecurityDecisionResponse.class)
                .subscribeOn(Schedulers.boundedElastic())
                .block(timeout);
    }

    /** Restores the sealed inputs on the event with the bundle fixed and returns the behaviour analysis drawn. */
    private SecurityDecisionStandardPromptTemplate.BehaviorAnalysis prepare(SealedDecisionReplayInputs inputs,
                                                                            String bundleVersion) {
        SecurityEvent event = inputs.event();
        // The bundle is fixed on the event as the first prompt of an event fixes it (W3-16).
        event.addMetadata("promptBundleSelection.version", bundleVersion);
        event.addMetadata("promptBundleSelection.source", PromptBundleSelectionSource.REPLAY.name());
        promptTemplate.useCanonicalContext(event, inputs.canonicalContext());
        BaseBehaviorAnalysis base = analyzeBehaviorPatternsBase(event, baselineLearningService, List.of());
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        analysis.setBaselineEstablished(base.isBaselineEstablished());
        enrichBehaviorAnalysisWithRuntimeLearningSupport(analysis, event, null, null, null, null);
        clearPromptRuntimeTelemetry(event);
        return analysis;
    }

    @Override
    protected String getLayerName() {
        return layer;
    }

    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        throw new UnsupportedOperationException("A replay only draws a sealed decision again");
    }
}
