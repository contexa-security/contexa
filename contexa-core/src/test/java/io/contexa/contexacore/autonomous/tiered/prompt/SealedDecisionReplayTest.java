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
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.llm.gate.ModelServerBusyException;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.ZoneId;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TimeZone;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The replay of a sealed decision (V-2.2 of the v21 plan) draws the prompt the golden render draws from the same
 * sealed inputs: the replay strategy restores the event, the session, the past records, the behaviour analysis on the
 * given baselines and the sealed canonical context, and fixes the chosen bundle. The pipeline is a stand-in that draws
 * the prompt through the template and answers.
 */
class SealedDecisionReplayTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .findAndRegisterModules();

    @Test
    void aReplayDrawsTheGoldenPromptOfTheSealedInputsWithTheChosenBundle() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties v21 = new TieredStrategyProperties();
        for (String caseKey : List.of("A3", "A3T", "S12")) {
            JsonNode goldenCase = golden.cases().stream()
                    .filter(item -> item.path("caseKey").asText().equals(caseKey)).findFirst().orElseThrow();
            String expected = golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, v21).userText();

            Drawing drawing = replay(goldenCase);
            write(caseKey + "-golden.txt", expected);
            write(caseKey + "-replayed.txt", drawing.userPrompts.isEmpty() ? "" : drawing.userPrompts.get(0));

            assertThat(drawing.userPrompts).as(caseKey).hasSize(1);
            assertThat(drawing.userPrompts.get(0)).as(caseKey).isEqualTo(expected);
            assertThat(drawing.result.action()).isEqualTo("ESCALATE");
            assertThat(drawing.result.replayId()).startsWith(SealedDecisionReplayInputs.REPLAY_ID_PREFIX);
            assertThat(drawing.result.replayedRequestId()).isEqualTo(goldenCase.path("requestFacts").path("requestId").asText());
            assertThat(drawing.result.failure()).isNull();
        }
    }

    /**
     * 판정층 7절: a first pass replay that answers ESCALATE is followed by the second pass Layer2 would ask, once per
     * given model: the first prompt with the SECOND PASS block, on the second layer's tier and options, with the model
     * named; after a first pass that retrieved its past records the block knows none as new.
     */
    @Test
    void anEscalateIsFollowedByTheSecondPassOncePerGivenModel() {
        JsonNode goldenCase = goldenCase("A3");

        Drawing drawing = replay(goldenCase, List.of("model-two", "model-one"), "ESCALATE");

        assertThat(drawing.userPrompts).hasSize(3);
        assertThat(drawing.tiers).containsExactly(1, 2, 2);
        assertThat(drawing.models).containsExactly(null, "model-two", "model-one");
        for (String secondPrompt : drawing.userPrompts.subList(1, 3)) {
            assertThat(secondPrompt).startsWith(drawing.userPrompts.get(0).stripTrailing())
                    .contains("=== SECOND PASS")
                    .contains("FirstPassVerdict: ESCALATE")
                    .contains("PastRecord{i}: none new (first pass: retrieved, AVAILABLE)");
        }
        assertThat(drawing.result.secondPasses()).extracting(SealedDecisionReplayService.SecondPass::requestedModel)
                .containsExactly("model-two", "model-one");
        assertThat(drawing.result.secondPasses()).extracting(SealedDecisionReplayService.SecondPass::action)
                .containsExactly("BLOCK", "CHALLENGE");
        assertThat(drawing.result.secondPasses()).allSatisfy(pass -> assertThat(pass.failure()).isNull());
    }

    /** A first pass that does not hand the request over is not followed by a second pass, whatever models are given. */
    @Test
    void aFirstPassThatDoesNotEscalateIsNotFollowedByASecondPass() {
        Drawing drawing = replay(goldenCase("A3T"), List.of("model-two"), "ALLOW");

        assertThat(drawing.userPrompts).hasSize(1);
        assertThat(drawing.result.action()).isEqualTo("ALLOW");
        assertThat(drawing.result.secondPasses()).isEmpty();
    }

    /**
     * Plan 3.8 (10), 3.9: a replay that names a version of the database (v2.0) draws the sealed decision with that
     * version's parts, fixed on the event as a decision's version is, with its content hash; a version the store does
     * not have is refused instead of drawn as the product version under its name.
     */
    @Test
    void aReplayOfAVersionOfTheDatabaseDrawsItsParts() {
        AssembledPrompt version = new PromptAssembler().apply(SecurityDecisionPromptDocument.product(),
                new PromptVersionDocumentReader().read("""
                        prompt: cortex.security-decision
                        basedOn: v1.0
                        title: Finance
                        system:
                          - key: org-context
                            add-after: evidence-reading
                            title: Our organization
                            text: |
                              Finance staff close the books on the last two days of a month.
                        """));
        PromptVersionStore store = (prompt, name) -> "v2.0".equals(name) ? Optional.of(version)
                : SecurityDecisionPromptDocument.productStore().find(prompt, name);

        Drawing drawing = replay(goldenCase("A3"), List.of(), "ALLOW", "v2.0", store);

        assertThat(drawing.result.failure()).isNull();
        assertThat(drawing.result.bundleVersion()).isEqualTo("v2.0");
        assertThat(drawing.pinned).containsExactly("v2.0 REPLAY " + version.contentHash());
        assertThat(drawing.systemPrompts).singleElement().asString()
                .contains("Finance staff close the books on the last two days of a month.");
        Drawing product = replay(goldenCase("A3"), List.of(), "ALLOW");
        assertThat(product.systemPrompts).singleElement().asString()
                .doesNotContain("Finance staff close the books on the last two days of a month.");
        assertThat(product.pinned).containsExactly(SecurityDecisionPromptBundles.V1.version() + " REPLAY "
                + SecurityDecisionPromptDocument.product().contentHash());
        assertThatThrownBy(() -> replay(goldenCase("A3"), List.of(), "ALLOW", "v9.0", store))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("v9.0");
    }

    /**
     * K57 and plan 3.10 (2): a replay of a version that adds a block to the user prompt draws the block at its place,
     * and the drawing of a sealed decision gives the prompts the replay asks with, without asking the model; with the
     * product version it gives the prompt the decision was drawn with (the golden prompt).
     */
    @Test
    void aDrawingIsThePromptAReplayAsksWithTheBlocksItsVersionAdds() {
        AssembledPrompt version = new PromptAssembler().apply(SecurityDecisionPromptDocument.product(),
                new PromptVersionDocumentReader().read("""
                        prompt: cortex.security-decision
                        basedOn: v1.0
                        title: Finance
                        user:
                          - key: org-closing
                            add-after: REQUEST
                            title: Finance closing
                            text: |
                              Finance staff export the ledger on the last two business days of a month.
                        """));
        String block = "=== Finance closing (reference written by your organization) ===\n"
                + "Finance staff export the ledger on the last two business days of a month.\n";
        PromptVersionStore store = (prompt, name) -> "v2.0".equals(name) ? Optional.of(version)
                : SecurityDecisionPromptDocument.productStore().find(prompt, name);
        JsonNode goldenCase = goldenCase("A3");
        String golden = SecurityDecisionGoldenRender.load()
                .render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, new TieredStrategyProperties())
                .userText();

        Drawing replayed = replay(goldenCase, List.of(), "ALLOW", "v2.0", store);
        write("A3-organization-replayed.txt", replayed.userPrompts.isEmpty() ? "" : replayed.userPrompts.get(0));
        assertThat(replayed.userPrompts).singleElement()
                .isEqualTo(SecurityDecisionOrganizationBlocksTest.insertedAfter(golden, "REQUEST", block));

        SealedDecisionReplayService.Drawing drawn = draw(goldenCase, " v2.0 ", store);
        assertThat(drawn.userPrompt()).isEqualTo(replayed.userPrompts.get(0));
        assertThat(drawn.systemPrompt()).isEqualTo(replayed.systemPrompts.get(0));
        assertThat(drawn.version()).isEqualTo("v2.0");
        assertThat(drawn.contentHash()).isEqualTo(version.contentHash());
        assertThat(drawn.packageId()).isEqualTo(goldenCase.path("source").path("packageId").asText());

        SealedDecisionReplayService.Drawing product = draw(goldenCase, SecurityDecisionPromptBundles.V1.version(), null);
        assertThat(product.userPrompt()).isEqualTo(golden);
        assertThat(product.systemPrompt()).isEqualTo(replay(goldenCase).systemPrompts.get(0));
        assertThat(product.contentHash()).isEqualTo(SecurityDecisionPromptDocument.product().contentHash());
        assertThatThrownBy(() -> draw(goldenCase, "v9.0", store))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("v9.0");
    }

    /**
     * Quality plan 3.2 (P24): a replay that fixes a time zone draws the prompt's times in it, whatever the time zone of
     * the server; one that fixes none draws them in the server's, as a decision sealed here was drawn.
     */
    @Test
    void aReplayDrawsInTheTimeZoneItFixesWhateverTheServers() {
        JsonNode goldenCase = goldenCase("A3");
        String golden = SecurityDecisionGoldenRender.load()
                .render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, new TieredStrategyProperties())
                .userText();
        String bundle = SecurityDecisionPromptBundles.V1.version();
        BaselineVector personal = vector(goldenCase.path("learningEvidence").path("personalBaseline"));
        BaselineVector organization = vector(goldenCase.path("learningEvidence").path("organizationBaseline"));

        // The server runs fourteen hours ahead of the time zone the golden prompt was drawn in.
        Drawing fixed = replay(goldenCase, "ALLOW", bundle, null, sealed -> {
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati"));
            return new SealedDecisionReplayService.Request(sealed, personal, organization, bundle,
                    Duration.ofSeconds(30), List.of(), false, null, null, ZoneId.of("UTC"));
        }, null);
        Drawing onTheServersClock = replay(goldenCase, "ALLOW", bundle, null, sealed -> {
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati"));
            return new SealedDecisionReplayService.Request(sealed, personal, organization, bundle,
                    Duration.ofSeconds(30), List.of(), false, null);
        }, null);

        assertThat(fixed.userPrompts).singleElement().isEqualTo(golden);
        assertThat(onTheServersClock.userPrompts).singleElement().isNotEqualTo(golden);
    }

    /** The drawing through the replay service, with a pipeline that fails the test when it is asked. */
    private static SealedDecisionReplayService.Drawing draw(JsonNode goldenCase, String release,
                                                           PromptVersionStore store) {
        TimeZone original = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                    new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties,
                            event -> Optional.empty(), new PromptContextComposer(), null, null, null));
            template.setPromptVersionStore(store);
            List<String> asked = new ArrayList<>();
            PipelineOrchestrator pipeline = new PipelineOrchestrator(List.of()) {
                @Override
                public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
                        AIRequest<T> request, PipelineConfiguration config, Class<R> responseType) {
                    asked.add(String.valueOf(request.getPromptTemplate()));
                    return Mono.error(new IllegalStateException("A drawing asks no model"));
                }
            };
            SealedDecisionReplayService service = new SealedDecisionReplayService(template, pipeline,
                    new BaselineLearningService(null, new SecurityZeroTrustProperties()), properties,
                    StructuredOutputCapabilityRegistry.defaultRegistry(), () -> null,
                    null, "OBSERVE", new CanonicalSecurityContextSerializer(MAPPER), MAPPER);
            SealedDecisionReplayService.Drawing drawn = service.draw(sealed(goldenCase),
                    vector(goldenCase.path("learningEvidence").path("personalBaseline")),
                    vector(goldenCase.path("learningEvidence").path("organizationBaseline")), release);
            assertThat(asked).as("the model is not asked").isEmpty();
            return drawn;
        }
        finally {
            TimeZone.setDefault(original);
        }
    }

    private static JsonNode goldenCase(String caseKey) {
        return SecurityDecisionGoldenRender.load().cases().stream()
                .filter(item -> item.path("caseKey").asText().equals(caseKey)).findFirst().orElseThrow();
    }

    private static void write(String name, String text) {
        try {
            Path directory = Path.of("build/reports/prompt-bundle/replay");
            Files.createDirectories(directory);
            Files.writeString(directory.resolve(name), text);
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    /**
     * Quality plan 3.3: the second pass is asked with the second layer's own model, the one the server is set to, when
     * the request says so: under no name, on the second layer's tier, before the named models.
     */
    @Test
    void theSecondPassIsAskedWithTheSecondLayersOwnModelWhenTheRequestSaysSo() {
        Drawing drawing = replay(goldenCase("A3"), "ESCALATE", SecurityDecisionPromptBundles.V1.version(), null,
                sealed -> new SealedDecisionReplayService.Request(sealed, null, null,
                        SecurityDecisionPromptBundles.V1.version(), Duration.ofSeconds(30), List.of("model-two"), true,
                        null), null);
        Drawing ownModelOnly = replay(goldenCase("A3"), "ESCALATE", SecurityDecisionPromptBundles.V1.version(), null,
                sealed -> new SealedDecisionReplayService.Request(sealed, null, null,
                        SecurityDecisionPromptBundles.V1.version(), Duration.ofSeconds(30), null, true, null), null);

        assertThat(drawing.tiers).containsExactly(1, 2, 2);
        assertThat(drawing.models).as("no model is named for the server's own").containsExactly(null, null, "model-two");
        assertThat(drawing.result.secondPasses()).extracting(SealedDecisionReplayService.SecondPass::requestedModel)
                .containsExactly(null, "model-two");
        assertThat(drawing.result.secondPasses()).extracting(SealedDecisionReplayService.SecondPass::action)
                .containsExactly("CHALLENGE", "BLOCK");
        assertThat(drawing.result.secondPasses()).allSatisfy(pass -> assertThat(pass.failure()).isNull());
        assertThat(ownModelOnly.tiers).containsExactly(1, 2);
        assertThat(ownModelOnly.result.secondPasses()).singleElement()
                .satisfies(pass -> assertThat(pass.requestedModel()).isNull());
    }

    /**
     * Quality plan 3.3: the answer of a replay carries what the pipeline returns for it: the prompts drawn for the
     * model call (the replay's request asks the pipeline for them), what the response check found of each reason code,
     * and the model calls with their times; so does each second pass.
     */
    @Test
    void theAnswerCarriesThePromptsDrawnTheCitationCheckAndTheModelCalls() {
        SecurityDecisionCitationCheck check = SecurityDecisionCitationCheck.skipped(List.of());
        Drawing drawing = replay(goldenCase("A3"), "ESCALATE", SecurityDecisionPromptBundles.V1.version(), null,
                sealed -> new SealedDecisionReplayService.Request(sealed, null, null,
                        SecurityDecisionPromptBundles.V1.version(), Duration.ofSeconds(30), List.of("model-two"), false,
                        null),
                (response, userPrompt) -> {
                    response.withMetadata(PromptRuntimeTelemetrySupport.DRAWN_SYSTEM_PROMPT, "SYSTEM AS DRAWN");
                    response.withMetadata(PromptRuntimeTelemetrySupport.DRAWN_USER_PROMPT, userPrompt);
                    response.withMetadata(SecurityDecisionCitationCheck.METADATA_KEY, check);
                    response.withMetadata(PromptRuntimeTelemetrySupport.MODEL_CALLS,
                            PromptRuntimeTelemetrySupport.withModelCall(PromptRuntimeTelemetrySupport.withModelCall(
                                    null, 7_000, 120L, 90_000, false), 6_500L, null, null, true));
                });

        assertThat(drawing.keptPrompts).as("every request of a replay asks for the drawn prompts")
                .containsExactly(true, true);
        SealedDecisionReplayService.Result result = drawing.result;
        assertThat(result.systemPrompt()).isEqualTo("SYSTEM AS DRAWN");
        assertThat(result.userPrompt()).isEqualTo(drawing.userPrompts.get(0));
        assertThat(result.citationCheck()).isSameAs(check);
        assertThat(result.modelCalls()).containsExactly(
                new SealedDecisionReplayService.ModelCall(7_000L, 120L, 90_000L, false),
                new SealedDecisionReplayService.ModelCall(6_500L, null, null, true));
        assertThat(result.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.ANSWERED);
        assertThat(result.modelAction()).isEqualTo("ESCALATE");
        SealedDecisionReplayService.SecondPass second = result.secondPasses().get(0);
        assertThat(second.userPrompt()).isEqualTo(drawing.userPrompts.get(1)).contains("=== SECOND PASS");
        assertThat(second.citationCheck()).isSameAs(check);
        assertThat(second.modelCalls()).hasSize(2);
        assertThat(second.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.ANSWERED);
        assertThat(second.modelAction()).isEqualTo("BLOCK");
    }

    /**
     * Quality plan 3.3: a failure of the measurement is told apart from an answer that could not be used. When the
     * model call fails the engine sets a safe-side action on the response, so the action alone does not tell: a busy
     * or unreachable model server and a time limit are a failure of the infrastructure, to be asked again; an answer
     * that broke the response contract or had no usable form is the model's, with the action the model gave when one
     * could be read.
     */
    @Test
    void aFailureOfTheMeasurementIsToldApartFromAnAnswerThatCouldNotBeUsed() {
        SealedDecisionReplayService.Result busy = answered(Map.of("rawExecutionSucceeded", false,
                "structuredOutputFailureCategory", "MODEL_SERVER_BUSY", "securityDecisionParsingFallbackApplied", true));
        SealedDecisionReplayService.Result timedOut = answered(Map.of("rawExecutionSucceeded", false,
                "securityDecisionParseFailureCategory", "TIMEOUT"));
        SealedDecisionReplayService.Result unavailable = answered(Map.of("rawExecutionSucceeded", false,
                "structuredOutputFailureCategory", "MODEL_UNAVAILABLE"));
        SealedDecisionReplayService.Result contractBroken = answered(Map.of("rawExecutionSucceeded", false,
                "structuredOutputFailureCategory", "VALIDATION_FAILED", "securityDecisionContractFallbackAction",
                "ESCALATE", "securityDecisionRetryAction", "ALLOW"));
        SealedDecisionReplayService.Result cut = answered(Map.of("rawExecutionSucceeded", false,
                "structuredOutputFailureCategory", "OUTPUT_TRUNCATED"));
        SealedDecisionReplayService.Result unreadable = answered(Map.of("rawExecutionSucceeded", true,
                "securityDecisionParsingFallbackApplied", true, "llmDecisionPresent", false));
        SealedDecisionReplayService.Result sound = answered(Map.of("rawExecutionSucceeded", true,
                "securityDecisionParsingFallbackApplied", false, "llmDecisionPresent", true));

        for (SealedDecisionReplayService.Result infrastructure : List.of(busy, timedOut, unavailable)) {
            assertThat(infrastructure.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE);
            assertThat(infrastructure.action()).as("the action the engine set, no answer of the prompt")
                    .isEqualTo("CHALLENGE");
            assertThat(infrastructure.modelAction()).isNull();
        }
        assertThat(contractBroken.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE);
        assertThat(contractBroken.modelAction()).as("the answer the contract replaced").isEqualTo("ALLOW");
        assertThat(cut.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE);
        assertThat(cut.modelAction()).isNull();
        assertThat(unreadable.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE);
        assertThat(unreadable.modelAction()).isNull();
        assertThat(sound.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.ANSWERED);
        assertThat(sound.modelAction()).isEqualTo("CHALLENGE");

        assertThat(failing(new ModelServerBusyException("ollama", "No free slot")).outcome())
                .isEqualTo(SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE);
        assertThat(failing(new IllegalStateException("wrapped", new TimeoutException("the layer's limit"))).outcome())
                .isEqualTo(SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE);
        assertThat(failing(new IllegalStateException("wrapped", new ConnectException("refused"))).outcome())
                .isEqualTo(SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE);
        SealedDecisionReplayService.Result contextGone = failing(new SealedReplayContextMissingException("replay-x"));
        assertThat(contextGone.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.CONTEXT_MISSING);
        assertThat(contextGone.action()).isNull();
        assertThat(contextGone.failure()).contains("SealedReplayContextMissingException");
        assertThat(failing(new IllegalArgumentException("a defect of the engine")).outcome())
                .isEqualTo(SealedDecisionReplayService.Outcome.REPLAY_ERROR);

        TieredStrategyProperties properties = new TieredStrategyProperties();
        SealedDecisionReplayService withoutPipeline = new SealedDecisionReplayService(
                new SecurityDecisionStandardPromptTemplate(new SecurityDecisionPromptSections(new SecurityEventEnricher(),
                        properties, event -> Optional.empty(), new PromptContextComposer(), null, null, null)),
                null, new BaselineLearningService(null, new SecurityZeroTrustProperties()), properties,
                StructuredOutputCapabilityRegistry.defaultRegistry(), () -> null, null, "OBSERVE",
                new CanonicalSecurityContextSerializer(MAPPER), MAPPER);
        SealedDecisionReplayService.Result notRun = withoutPipeline.replay(sealed(goldenCase("A3")), null, null,
                SecurityDecisionPromptBundles.V1.version(), Duration.ofSeconds(30));
        assertThat(notRun.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE);
        assertThat(notRun.failure()).isEqualTo("PIPELINE_UNAVAILABLE");
    }

    /**
     * Quality plan 9: a replay that is told the context format of its inputs does not read inputs of another format
     * as if they were of this build's, and says so without asking the model; inputs that name none (a package this
     * server sealed) are read as before. Sealed inputs that cannot be read at all are told apart too.
     */
    @Test
    void inputsOfAnotherContextFormatAreNotReadAndUnreadableInputsAreToldApart() {
        JsonNode goldenCase = goldenCase("A3T");
        String bundle = SecurityDecisionPromptBundles.V1.version();
        Drawing other = replay(goldenCase, "ALLOW", bundle, null, sealed -> new SealedDecisionReplayService.Request(
                sealed, null, null, bundle, Duration.ofSeconds(30), List.of(), false, "2"), null);
        Drawing same = replay(goldenCase, "ALLOW", bundle, null, sealed -> new SealedDecisionReplayService.Request(
                sealed, null, null, bundle, Duration.ofSeconds(30), List.of(), false,
                " " + SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION + " "), null);
        Drawing unnamed = replay(goldenCase, "ALLOW", bundle, null, sealed -> new SealedDecisionReplayService.Request(
                sealed, null, null, bundle, Duration.ofSeconds(30), List.of(), false, null), null);
        Drawing unreadable = replay(goldenCase, "ALLOW", bundle, null, sealed -> {
            sealed.setCanonicalContextJson(null);
            return new SealedDecisionReplayService.Request(sealed, null, null, bundle, Duration.ofSeconds(30),
                    List.of(), false, SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION);
        }, null);

        assertThat(other.result.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.CONTEXT_FORMAT_MISMATCH);
        assertThat(other.result.failure()).startsWith("CONTEXT_FORMAT_MISMATCH").contains("format 2");
        assertThat(other.result.action()).isNull();
        assertThat(other.userPrompts).as("the model is not asked").isEmpty();
        assertThat(same.result.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.ANSWERED);
        assertThat(same.userPrompts).hasSize(1);
        assertThat(unnamed.result.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.ANSWERED);
        assertThat(unreadable.result.outcome()).isEqualTo(SealedDecisionReplayService.Outcome.INPUT_UNREADABLE);
        assertThat(unreadable.userPrompts).isEmpty();
    }

    /**
     * Quality plan 9 (K161): the prompt of a replay is drawn with the canonical context the replay fixed for its event,
     * or not at all: once that context is no longer kept, the context the provider resolves now is not taken in its
     * place. An event that is no replay resolves its context as before.
     */
    @Test
    void aReplayIsNotDrawnWithTheContextOfNowWhenItsSealedContextIsNoLongerKept() {
        CanonicalSecurityContext live = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("NORMAL").build()).build();
        CanonicalSecurityContext sealedContext = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("SENSITIVE").build()).build();
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(new SecurityEventEnricher(),
                new TieredStrategyProperties(), event -> Optional.of(live), new PromptContextComposer(), null, null, null);
        SecurityEvent fixed = replayEvent("replay-fixed");
        SecurityEvent forgotten = replayEvent("replay-forgotten");
        SecurityEvent decision = SecurityEvent.builder().eventId("event-live").userId("alice")
                .metadata(new LinkedHashMap<>()).build();
        sections.useCanonicalContext(fixed, sealedContext);

        assertThat(sections.resolveCanonicalSecurityContext(fixed).orElseThrow().getResource().getResourceClass())
                .isEqualTo("SENSITIVE");
        assertThatThrownBy(() -> sections.resolveCanonicalSecurityContext(forgotten))
                .isInstanceOf(SealedReplayContextMissingException.class).hasMessageContaining("replay-forgotten");
        assertThat(sections.resolveCanonicalSecurityContext(decision).orElseThrow().getResource().getResourceClass())
                .as("a decision's own path is as it was").isEqualTo("NORMAL");
    }

    private static SecurityEvent replayEvent(String id) {
        SecurityEvent event = SecurityEvent.builder().eventId(id).userId("alice").metadata(new LinkedHashMap<>()).build();
        event.addMetadata(SecurityDecisionPromptSections.EVENT_BUNDLE_SOURCE, PromptBundleSelectionSource.REPLAY.name());
        return event;
    }

    /** A replay of A3T whose pipeline answers CHALLENGE with the given marks of the engine on its response. */
    private static SealedDecisionReplayService.Result answered(Map<String, Object> marks) {
        return replay(goldenCase("A3T"), "CHALLENGE", SecurityDecisionPromptBundles.V1.version(), null,
                sealed -> new SealedDecisionReplayService.Request(sealed, null, null,
                        SecurityDecisionPromptBundles.V1.version(), Duration.ofSeconds(30), List.of(), false, null),
                (response, userPrompt) -> marks.forEach(response::withMetadata)).result;
    }

    /** A replay of A3T whose pipeline ends in the given failure. */
    private static SealedDecisionReplayService.Result failing(RuntimeException failure) {
        return replay(goldenCase("A3T"), "CHALLENGE", SecurityDecisionPromptBundles.V1.version(), null,
                sealed -> new SealedDecisionReplayService.Request(sealed, null, null,
                        SecurityDecisionPromptBundles.V1.version(), Duration.ofSeconds(30), List.of(), false, null),
                (response, userPrompt) -> {
                    throw failure;
                }).result;
    }

    private record Drawing(SealedDecisionReplayService.Result result, List<String> userPrompts, List<Integer> tiers,
                           List<String> models, List<String> pinned, List<String> systemPrompts,
                           List<Boolean> keptPrompts) {
    }

    private static Drawing replay(JsonNode goldenCase) {
        return replay(goldenCase, List.of(), "ESCALATE");
    }

    private static Drawing replay(JsonNode goldenCase, List<String> secondPassModels, String firstAction) {
        return replay(goldenCase, secondPassModels, firstAction, SecurityDecisionPromptBundles.V1.version(), null);
    }

    /**
     * The replay through a stand-in pipeline that draws the prompt through the template, keeps the first prompt on the
     * event as the prompt composer does, and answers the first layer with the given action and the second layer by
     * the model it names (model-two BLOCK, any other CHALLENGE).
     */
    private static Drawing replay(JsonNode goldenCase, List<String> secondPassModels, String firstAction,
                                  String release, PromptVersionStore store) {
        return replay(goldenCase, firstAction, release, store, sealed -> new SealedDecisionReplayService.Request(sealed,
                vector(goldenCase.path("learningEvidence").path("personalBaseline")),
                vector(goldenCase.path("learningEvidence").path("organizationBaseline")),
                release, Duration.ofSeconds(30), secondPassModels, false, null), null);
    }

    /**
     * The replay of the request the sealed package is made into, through the stand-in pipeline; {@code marking} may
     * add to each response what the engine's pipeline leaves on it, or fail as the pipeline would.
     */
    private static Drawing replay(JsonNode goldenCase, String firstAction, String release, PromptVersionStore store,
                                  Function<SealedEvidencePackage, SealedDecisionReplayService.Request> asking,
                                  BiConsumer<SecurityDecisionResponse, String> marking) {
        TimeZone original = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        try {
            TieredStrategyProperties properties = new TieredStrategyProperties();
            SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                    new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties,
                            event -> Optional.empty(), new PromptContextComposer(), null, null, null));
            template.setPromptVersionStore(store);
            List<String> userPrompts = new ArrayList<>();
            List<Integer> tiers = new ArrayList<>();
            List<String> models = new ArrayList<>();
            List<String> pinned = new ArrayList<>();
            List<String> systemPrompts = new ArrayList<>();
            List<Boolean> keptPrompts = new ArrayList<>();
            PipelineOrchestrator pipeline = new PipelineOrchestrator(List.of()) {
                @Override
                @SuppressWarnings("unchecked")
                public <T extends DomainContext, R extends AIResponse> Mono<R> execute(
                        AIRequest<T> request, PipelineConfiguration config, Class<R> responseType) {
                    String userPrompt = template.generateUserPrompt(request, null);
                    userPrompts.add(userPrompt);
                    systemPrompts.add(template.generateSystemPrompt(request, null));
                    Integer tier = request.getParameter("platformAnalysisTier", Integer.class);
                    String model = request.getParameter("requestedModelId", String.class);
                    tiers.add(tier);
                    models.add(model);
                    keptPrompts.add(Boolean.TRUE.equals(
                            request.getParameter(PromptRuntimeTelemetrySupport.KEEP_DRAWN_PROMPTS, Boolean.class)));
                    if (request.getContext() instanceof SecurityDecisionContext decision) {
                        decision.getSecurityEvent().getMetadata()
                                .putIfAbsent(PromptRuntimeTelemetrySupport.FIRST_PASS_USER_PROMPT, userPrompt);
                        Map<String, Object> metadata = decision.getSecurityEvent().getMetadata();
                        pinned.add(metadata.get(SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION) + " "
                                + metadata.get(SecurityDecisionPromptSections.EVENT_BUNDLE_SOURCE) + " "
                                + metadata.get(SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH));
                    }
                    SecurityDecisionResponse response = new SecurityDecisionResponse();
                    response.setAction(tier != null && tier == 2 ? ("model-two".equals(model) ? "BLOCK" : "CHALLENGE")
                            : firstAction);
                    response.setReasoning("stand-in");
                    if (marking != null) {
                        marking.accept(response, userPrompt);
                    }
                    return Mono.just((R) response);
                }
            };
            SealedDecisionReplayService service = new SealedDecisionReplayService(template, pipeline,
                    new BaselineLearningService(null, new SecurityZeroTrustProperties()), properties,
                    StructuredOutputCapabilityRegistry.defaultRegistry(), () -> null,
                    null, "OBSERVE", new CanonicalSecurityContextSerializer(MAPPER), MAPPER);
            SealedDecisionReplayService.Result result = service.replay(asking.apply(sealed(goldenCase)));
            return new Drawing(result, userPrompts, tiers, models, pinned, systemPrompts, keptPrompts);
        }
        finally {
            TimeZone.setDefault(original);
        }
    }

    /** The golden case as the sealed package it was taken from. */
    private static SealedEvidencePackage sealed(JsonNode goldenCase) {
        SealedEvidencePackage sealed = new SealedEvidencePackage();
        sealed.setPackageId(goldenCase.path("source").path("packageId").asText());
        sealed.setCorrelationId(goldenCase.path("requestFacts").path("requestId").asText());
        sealed.setCanonicalContextJson(goldenCase.path("canonicalContext").toString());
        sealed.setRequestFactsJson(goldenCase.path("requestFacts").toString());
        sealed.setAuthStateJson(goldenCase.path("authState").toString());
        sealed.setBaselineSnapshotJson(goldenCase.path("baselineSnapshot").toString());
        sealed.setRagResultsJson(goldenCase.path("ragResults").toString());
        return sealed;
    }

    private static BaselineVector vector(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : MAPPER.convertValue(node, BaselineVector.class);
    }
}
