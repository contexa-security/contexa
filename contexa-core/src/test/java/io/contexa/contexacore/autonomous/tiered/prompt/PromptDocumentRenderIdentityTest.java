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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-1 (Q1): the prompts of the v1.0 bundles are the ones the code drew before their sentences moved to the product
 * prompt document. Every golden case is rendered by v1.0, its four measured variants and v21 (whose sentences the
 * document holds as well) for the first pass of both profiles and for the second pass, and an agent's request, a
 * timed-out past record search and a provider with structured output are rendered as well; the sha-256 of each system
 * and user prompt must be the one recorded from the code before the move
 * ({@code v1-texts-before-prompt-document.txt}).
 *
 * <p>Record the digests again only when a prompt changes on purpose: run this test with the environment variable
 * {@code CONTEXA_PIN_CAPTURE_V1_DOCUMENT} set to the path of the resource file; it then writes the file instead of
 * comparing. With {@code CONTEXA_PIN_DUMP_V1_DOCUMENT} set to a directory it also writes every rendered text there.</p>
 */
class PromptDocumentRenderIdentityTest {

    static final String PINNED = "prompt-bundles/golden/cortex.security-decision/v1-texts-before-prompt-document.txt";

    private static final List<SecurityDecisionPromptBundles.Bundle> BUNDLES = List.of(
            SecurityDecisionPromptBundles.V1,
            SecurityDecisionPromptBundles.V1_RECORD_SIMILAR,
            SecurityDecisionPromptBundles.V1_RECORD_EXACT,
            SecurityDecisionPromptBundles.V1_FALLBACK_SIMILAR,
            SecurityDecisionPromptBundles.V1_FALLBACK_EXACT,
            SecurityDecisionPromptBundles.V21);

    @Test
    void everyV1PromptIsTheOneTheCodeDrewBeforeTheProductDocument() throws IOException {
        Map<String, String> texts = renderedTexts();
        Map<String, String> now = new LinkedHashMap<>();
        texts.forEach((key, text) -> now.put(key, V21UserPromptByteIdentityTest.sha256(text)));
        String dump = System.getenv("CONTEXA_PIN_DUMP_V1_DOCUMENT");
        if (dump != null && !dump.isBlank()) {
            Path directory = Files.createDirectories(Path.of(dump));
            for (Map.Entry<String, String> entry : texts.entrySet()) {
                Files.writeString(directory.resolve(entry.getKey().replace('/', '_') + ".txt"), entry.getValue(),
                        StandardCharsets.UTF_8);
            }
        }
        String capture = System.getenv("CONTEXA_PIN_CAPTURE_V1_DOCUMENT");
        if (capture != null && !capture.isBlank()) {
            StringBuilder file = new StringBuilder();
            now.forEach((key, digest) -> file.append(key).append('=').append(digest).append('\n'));
            Files.writeString(Path.of(capture), file.toString(), StandardCharsets.UTF_8);
            return;
        }
        Map<String, String> pinned = V21UserPromptByteIdentityTest.pinned(PINNED);
        assertThat(pinned).as("the recorded digests").isNotEmpty();
        assertThat(now.keySet()).as("the rendered prompts").containsExactlyElementsOf(pinned.keySet());
        Map<String, String> changed = new LinkedHashMap<>();
        now.forEach((key, digest) -> {
            if (!digest.equals(pinned.get(key))) {
                changed.put(key, digest);
            }
        });
        assertThat(changed).as("prompts that differ from the ones the code drew before the product document").isEmpty();
    }

    /** Every prompt the test pins, by key. */
    static Map<String, String> renderedTexts() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        Map<String, String> texts = new LinkedHashMap<>();
        for (SecurityDecisionPromptBundles.Bundle bundle : BUNDLES) {
            String name = bundle.version();
            TieredStrategyProperties properties = new TieredStrategyProperties();
            properties.getPromptBundle().setActive(bundle.version());
            for (JsonNode goldenCase : golden.cases()) {
                String caseKey = goldenCase.path("caseKey").asText();
                for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                    put(texts, name + "/" + caseKey + "/" + profile.name(), golden.render(goldenCase, profile, properties));
                }
                if (goldenCase.path("ragResults").path("relatedDocuments").isEmpty()) {
                    continue;
                }
                String first = golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties)
                        .userText();
                put(texts, name + "/" + caseKey + "/second-pass", golden.render(goldenCase,
                        PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT, properties, null,
                        Map.of("layer2FirstPassUserPrompt", first,
                                "layer2FirstPassVerdict", "ESCALATE",
                                "layer2FirstPassPastRecordsState", "TIMEOUT")));
            }
            JsonNode first = golden.cases().get(0);
            put(texts, name + "/agent", golden.render(changed(first, PromptDocumentRenderIdentityTest::agent),
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties));
            put(texts, name + "/timed-out-search", golden.render(timedOutSearch(first),
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties));
            put(texts, name + "/native-structured-output", golden.render(first,
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties, null,
                    Map.of("structuredOutputMode", StructuredOutputMode.NATIVE_STRUCTURED.name())));
        }
        return texts;
    }

    private static void put(Map<String, String> texts, String key, SecurityDecisionGoldenRender.RenderedCase rendered) {
        texts.put(key + "/system", rendered.systemText());
        texts.put(key + "/user", rendered.userText());
    }

    /** The request as an agent sends it, as the v1.0 bundle test draws one. */
    private static void agent(CanonicalSecurityContext context) {
        context.getAttributes().put("executionSubjectKind", "AUTONOMOUS_AGENT");
        context.getAttributes().put("agentId", "report-agent");
        context.setDelegation(CanonicalSecurityContext.Delegation.builder().delegated(false)
                .agentId("report-agent").build());
    }

    private static JsonNode changed(JsonNode goldenCase, Consumer<CanonicalSecurityContext> change) {
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER
                .deserialize(goldenCase.path("canonicalContext").toString());
        change.accept(context);
        ObjectNode changed = goldenCase.deepCopy();
        try {
            changed.set("canonicalContext", InspectionGolden.JSON.readTree(InspectionGolden.SERIALIZER.serialize(context)));
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
        return changed;
    }

    /** The case when its past record search timed out, as the inspection golden draws one. */
    private static JsonNode timedOutSearch(JsonNode goldenCase) {
        ObjectNode changed = goldenCase.deepCopy();
        ObjectNode rag = (ObjectNode) changed.path("ragResults");
        rag.put("ragRetrievalState", "TIMEOUT").put("ragAbsenceReason", "TIMEOUT").put("ragTimedOut", true)
                .put("ragUnavailable", true).put("ragZeroResults", false).put("ragSearchExecuted", true)
                .put("ragTimeoutMs", 500).put("ragAuthorizedDocumentCount", 0).put("ragCandidateDocumentCount", 0)
                .put("ragDeniedDocumentCount", 0).put("relatedDocumentCount", 0)
                .put("ragRelevance", "NO_DOCUMENTS").put("ragProjectionState", "UNAVAILABLE_DECLARED");
        rag.putNull("ragProjectedToFinalPrompt");
        rag.remove("ragEarlierRetrievalState");
        rag.putArray("relatedDocuments");
        return changed;
    }
}
