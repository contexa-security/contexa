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
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TimeZone;

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
        // N3: the bundle's name is also the name of the earlier product release, which the replay draws.
        assertThat(product.pinned).containsExactly(SecurityDecisionPromptBundles.V1.version() + " REPLAY "
                + release(SecurityDecisionPromptBundles.V1.version()).contentHash());
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
        assertThat(product.contentHash()).isEqualTo(release(SecurityDecisionPromptBundles.V1.version()).contentHash());
        assertThatThrownBy(() -> draw(goldenCase, "v9.0", store))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("v9.0");
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

    private record Drawing(SealedDecisionReplayService.Result result, List<String> userPrompts, List<Integer> tiers,
                           List<String> models, List<String> pinned, List<String> systemPrompts) {
    }

    private static AssembledPrompt release(String name) {
        return SecurityDecisionPromptDocument.productStore().find(SecurityDecisionPromptDocument.PROMPT, name)
                .orElseThrow();
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
                    return Mono.just((R) response);
                }
            };
            SealedDecisionReplayService service = new SealedDecisionReplayService(template, pipeline,
                    new BaselineLearningService(null, new SecurityZeroTrustProperties()), properties,
                    StructuredOutputCapabilityRegistry.defaultRegistry(), () -> null,
                    null, "OBSERVE", new CanonicalSecurityContextSerializer(MAPPER), MAPPER);
            SealedDecisionReplayService.Result result = service.replay(sealed(goldenCase),
                    vector(goldenCase.path("learningEvidence").path("personalBaseline")),
                    vector(goldenCase.path("learningEvidence").path("organizationBaseline")),
                    release, Duration.ofSeconds(30), secondPassModels);
            return new Drawing(result, userPrompts, tiers, models, pinned, systemPrompts);
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
