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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElementState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleGoldenInputs;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import jakarta.persistence.Column;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Build verification of the security decision prompt bundles (W1-18, W3-16): for every bundle the build runs, the
 * element hashes of the code are recomputed and must equal the manifest of the bundle's version. A changed element
 * under the same version name fails the build; the computed manifest is written to build/prompt-bundles so a new
 * version can be frozen from it.
 */
class SecurityDecisionPromptBundleTest {

    private static final String INSPECTOR_SOURCE =
            "src/main/java/io/contexa/contexacore/std/pipeline/processor/SecurityDecisionRawOutputContractInspector.java";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private static SecurityDecisionGoldenRender golden;
    private static Map<String, List<SecurityDecisionGoldenRender.RenderedCase>> renderedByBundle;

    @BeforeAll
    static void render() {
        golden = SecurityDecisionGoldenRender.load();
        renderedByBundle = new LinkedHashMap<>();
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            renderedByBundle.put(bundle.descriptor().promptVersion(), renderAll(bundle));
        }
    }

    @Test
    void goldenRenderIsDeterministic() {
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            assertThat(SecurityDecisionGoldenRender.digest(renderAll(bundle)))
                    .as(bundle.descriptor().promptVersion())
                    .isEqualTo(SecurityDecisionGoldenRender.digest(rendered(bundle)));
        }
    }

    @Test
    void systemTextIsTheSameForEveryCaseOfAProfile() {
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                Set<String> systemTexts = new LinkedHashSet<>();
                rendered(bundle).stream().filter(item -> item.profile() == profile)
                        .forEach(item -> systemTexts.add(item.systemText()));
                assertThat(systemTexts).as("system text of " + profile + " in " + bundle.descriptor().promptVersion())
                        .hasSize(1);
            }
        }
    }

    /**
     * Every bundle's change summary fits the registry and change ledger columns the bundle is registered into at start
     * (the first v20.6 summary did not, and the host failed to start; TO-1 real server).
     */
    @Test
    void everyBundlesChangeSummaryFitsTheRegistryColumns() throws NoSuchFieldException {
        for (Class<?> record : List.of(PromptGovernanceRegistryRecord.class, PromptGovernanceChangeRecord.class)) {
            int length = record.getDeclaredField("changeSummary").getAnnotation(Column.class).length();
            for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
                assertThat(bundle.descriptor().changeSummary().length())
                        .as(bundle.descriptor().promptVersion() + " " + record.getSimpleName())
                        .isLessThanOrEqualTo(length);
            }
        }
    }

    /** R4-B9 (Q-78 request 2): the verifier contracts of the former quality assurance are no element of a bundle. */
    @Test
    void theVerifierContractsAreNoElementOfTheBundlesTheBuildRuns() {
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            PromptGovernanceDescriptor descriptor = bundle.descriptor();
            PromptBundleElement verifierContracts = PromptBundleCatalog.shared()
                    .find(descriptor.promptKey(), descriptor.promptVersion()).orElseThrow().elements().stream()
                    .filter(element -> "B9".equals(element.id())).findFirst().orElseThrow();
            assertThat(verifierContracts.state()).as(descriptor.promptVersion()).isEqualTo(PromptBundleElementState.ABSENT);
        }
    }

    @Test
    void codeMatchesTheManifestOfEveryBundleTheBuildRuns() throws IOException {
        for (SecurityDecisionPromptBundles.Bundle bundle : SecurityDecisionPromptBundles.ALL) {
            codeMatchesTheManifestOf(bundle);
        }
    }

    private void codeMatchesTheManifestOf(SecurityDecisionPromptBundles.Bundle bundle) throws IOException {
        PromptGovernanceDescriptor descriptor = bundle.descriptor();
        PromptBundleManifest computed = computedManifest(bundle);
        Path written = Path.of("build/prompt-bundles/manifests", computed.promptKey(), computed.bundleVersion() + ".json");
        Files.createDirectories(written.getParent());
        Files.writeString(written, OBJECT_MAPPER.writeValueAsString(computed).replace("\r\n", "\n") + "\n");

        PromptBundleManifest shipped = PromptBundleCatalog.shared()
                .find(descriptor.promptKey(), descriptor.promptVersion())
                .orElse(null);
        assertThat(shipped)
                .as("no manifest ships for " + descriptor.promptKey() + "@" + descriptor.promptVersion()
                        + "; freeze it from " + written.toAbsolutePath())
                .isNotNull();
        List<String> changed = new ArrayList<>();
        for (PromptBundleElement element : computed.elements()) {
            PromptBundleElement declared = shipped.elements().stream()
                    .filter(item -> item.id().equals(element.id()))
                    .findFirst()
                    .orElseThrow();
            if (!declared.hash().equals(element.hash()) || declared.state() != element.state()) {
                changed.add(element.id() + " (" + element.detail() + ")");
            }
        }
        assertThat(changed)
                .as("bundle " + descriptor.promptVersion() + " changed; give the changed content a new bundle version"
                        + " (computed manifest: " + written.toAbsolutePath() + ")")
                .isEmpty();
        assertThat(shipped.bundleHash()).isEqualTo(computed.bundleHash());
        assertThat(shipped.goldenInputs().sha256()).isEqualTo(golden.contentSha256());
        assertThat(descriptor.artifactHashSha256()).isEqualTo(shipped.bundleHash());
    }

    @Test
    void goldenRenderFidelityAgainstTheSealedPromptsIsReported() throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        int sections = 0;
        int identical = 0;
        for (JsonNode goldenCase : golden.cases()) {
            PromptBudgetProfile profile = PromptBudgetProfile.fromKey(goldenCase.path("budgetProfile").asText(),
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
            SecurityDecisionGoldenRender.RenderedCase item = rendered(SecurityDecisionPromptBundles.DEFAULT).stream()
                    .filter(candidate -> candidate.caseKey().equals(goldenCase.path("caseKey").asText())
                            && candidate.profile() == profile)
                    .findFirst()
                    .orElseThrow();
            Map<String, String> sealed = sections(goldenCase.path("rawUserPrompt").asText(""));
            Map<String, String> renderedSections = sections(item.userText());
            List<String> differing = new ArrayList<>();
            for (Map.Entry<String, String> entry : sealed.entrySet()) {
                sections++;
                if (entry.getValue().equals(renderedSections.get(entry.getKey()))) {
                    identical++;
                }
                else {
                    differing.add(entry.getKey());
                }
            }
            Map<String, Object> caseReport = new LinkedHashMap<>();
            caseReport.put("profile", profile.name());
            caseReport.put("sealedSections", sealed.size());
            caseReport.put("differingSections", differing);
            caseReport.put("systemTextIdentical", item.systemText().equals(goldenCase.path("rawSystemPrompt").asText("")));
            report.put(item.caseKey(), caseReport);
            Path renderedDirectory = Path.of("build/reports/prompt-bundle/rendered");
            Files.createDirectories(renderedDirectory);
            Files.writeString(renderedDirectory.resolve(item.caseKey() + "-system.txt"), item.systemText());
            Files.writeString(renderedDirectory.resolve(item.caseKey() + "-user.txt"), item.userText());
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("sections", sections);
        summary.put("identicalSections", identical);
        summary.put("cases", report);
        Path path = Path.of("build/reports/prompt-bundle/security-decision-golden-fidelity.json");
        Files.createDirectories(path.getParent());
        Files.writeString(path, OBJECT_MAPPER.writeValueAsString(summary));
        assertThat(sections).isPositive();
    }

    /**
     * The golden renders of a bundle: every case with the L1 and L2 budget profiles, and for a v20 bundle the second
     * analysis as well: the second-pass layout over a case's first prompt, for each case with past records the first
     * pass could not retrieve (W3-9).
     */
    private static List<SecurityDecisionGoldenRender.RenderedCase> renderAll(SecurityDecisionPromptBundles.Bundle bundle) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(bundle.descriptor().promptVersion());
        List<SecurityDecisionGoldenRender.RenderedCase> rendered = new ArrayList<>();
        for (JsonNode goldenCase : golden.cases()) {
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                rendered.add(golden.render(goldenCase, profile, properties));
            }
        }
        if (bundle.layout() == SecurityDecisionPromptBundles.UserPromptLayout.V20_BLOCKS) {
            for (JsonNode goldenCase : golden.cases()) {
                if (goldenCase.path("ragResults").path("relatedDocuments").isEmpty()) {
                    continue;
                }
                String first = golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties)
                        .userText();
                rendered.add(golden.render(goldenCase, PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT, properties, null,
                        Map.of("layer2FirstPassUserPrompt", first,
                                "layer2FirstPassVerdict", "ESCALATE",
                                "layer2FirstPassPastRecordsState", "TIMEOUT")));
            }
        }
        return rendered;
    }

    private static List<SecurityDecisionGoldenRender.RenderedCase> rendered(SecurityDecisionPromptBundles.Bundle bundle) {
        return renderedByBundle.get(bundle.descriptor().promptVersion());
    }

    private PromptBundleManifest computedManifest(SecurityDecisionPromptBundles.Bundle bundle) throws IOException {
        PromptGovernanceDescriptor descriptor = bundle.descriptor();
        List<SecurityDecisionGoldenRender.RenderedCase> rendered = rendered(bundle);
        boolean v20 = bundle.layout() == SecurityDecisionPromptBundles.UserPromptLayout.V20_BLOCKS;
        long secondPasses = rendered.size() - (long) golden.cases().size() * SecurityDecisionGoldenRender.PROFILES.size();
        List<PromptBundleElement> elements = new ArrayList<>();
        elements.add(PromptBundleHashes.present("B1", systemTexts(rendered),
                "rendered system text of the L1 and L2 budget profiles"));
        elements.add(v20
                ? PromptBundleHashes.present("B2", SecurityDecisionPromptDictionary.contentText(), "prompt dictionary "
                        + SecurityDecisionPromptDictionary.VERSION + ": every entry with all its fields and the block header labels (W3-1)")
                : PromptBundleHashes.marker("B2", PromptBundleElementState.ABSENT, "no prompt dictionary in v19 (v20, W3-1)"));
        elements.add(PromptBundleHashes.presentHash("B3", SecurityDecisionGoldenRender.digest(rendered),
                "golden render digest: " + golden.cases().size() + " cases x L1/L2"
                        + (v20 ? " and " + secondPasses + " second passes" : "") + ", inputs " + golden.contentSha256()));
        elements.add(PromptBundleHashes.present("B4", outputContract(), "format instructions and the response fields"));
        elements.add(PromptBundleHashes.marker("B5", PromptBundleElementState.ABSENT,
                v20 ? "no minimum response rules yet (W4-4)" : "no minimum response rules in v19 (W4-4)"));
        elements.add(PromptBundleHashes.present("B6", Files.readString(Path.of(INSPECTOR_SOURCE), StandardCharsets.UTF_8),
                v20 ? "response inspector definition source (no declarative rule list yet, W4-4)"
                        : "response inspector definition source (no declarative rule list in v19)"));
        elements.add(PromptBundleHashes.present("B7", retrievalSettings(), "retrieval counts, thresholds, waits and document truncation defaults"));
        elements.add(PromptBundleHashes.present("B8", budgetProfiles(), "all prompt budget profiles"));
        elements.add(PromptBundleHashes.marker("B9", PromptBundleElementState.ABSENT,
                "no verifier contracts: the former quality assurance contracts are not part of the prompt (R4-B9, Q-78)"));
        elements.add(PromptBundleHashes.marker("B10", PromptBundleElementState.UNVERSIONED,
                v20 ? "no vocabulary version yet (W5-7)"
                        : "no vocabulary version in v19; classification happens before the canonical context (W2-1, W2-2, W5-7)"));
        elements.add(PromptBundleHashes.marker("B11", PromptBundleElementState.INCLUDED,
                v20 ? "the second analysis renders inside B3: the L2 budget profile and the second-pass layout (W3-9)"
                        : "the second analysis renders with the L2 budget profile inside B3"));
        Map<String, String> excluded = golden.excludedCases();
        return new PromptBundleManifest(
                descriptor.promptKey(),
                descriptor.promptVersion(),
                PromptBundleHashes.bundleHash(elements),
                elements,
                new PromptBundleGoldenInputs(SecurityDecisionGoldenRender.RESOURCE, golden.contentSha256(),
                        golden.cases().size(), excluded,
                        SecurityDecisionGoldenRender.PROFILES.stream().map(Enum::name).toList()),
                null,
                descriptor.changeSummary(),
                List.of(),
                descriptor.owner(),
                "2026-10-10",
                null,
                List.of(),
                List.of(),
                descriptor.supportedModelProfiles());
    }

    private static String systemTexts(List<SecurityDecisionGoldenRender.RenderedCase> rendered) {
        StringBuilder text = new StringBuilder();
        for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
            String systemText = rendered.stream()
                    .filter(item -> item.profile() == profile)
                    .map(SecurityDecisionGoldenRender.RenderedCase::systemText)
                    .findFirst()
                    .orElseThrow();
            text.append(profile.name()).append(":\n").append(systemText).append('\n');
        }
        return text.toString();
    }

    /** R1b-7: the dictionary's digest in main code is the hash of the bundle's dictionary element. */
    @Test
    void theDictionaryDigestIsTheHashOfTheBundlesDictionaryElement() {
        PromptBundleManifest shipped = PromptBundleCatalog.shared()
                .find("cortex.security-decision", SecurityDecisionPromptBundles.V20.descriptor().promptVersion())
                .orElseThrow();
        PromptBundleElement dictionary = shipped.elements().stream().filter(element -> "B2".equals(element.id()))
                .findFirst().orElseThrow();

        assertThat(SecurityDecisionPromptDictionary.contentDigest()).isEqualTo(dictionary.hash());
    }

    private static String outputContract() {
        StringBuilder text = new StringBuilder(SecurityDecisionContractSectionBuilder.formatInstructions()).append('\n');
        Arrays.stream(SecurityDecisionResponseLite.class.getDeclaredFields())
                .filter(field -> !field.isSynthetic() && !Modifier.isStatic(field.getModifiers()))
                .sorted(Comparator.comparing(Field::getName))
                .forEach(field -> text.append(field.getName()).append(':').append(field.getGenericType().getTypeName()).append('\n'));
        return text.toString();
    }

    private static String retrievalSettings() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        Map<String, Object> values = new TreeMap<>();
        values.put("layer1.vectorSearchLimit", properties.getLayer1().getVectorSearchLimit());
        values.put("layer1.prompt.maxSimilarEvents", properties.getLayer1().getPrompt().getMaxSimilarEvents());
        values.put("layer1.prompt.maxRagDocuments", properties.getLayer1().getPrompt().getMaxRagDocuments());
        values.put("layer1.rag.similarityThreshold", properties.getLayer1().getRag().getSimilarityThreshold());
        values.put("layer1.rag.multiQuerySearchEnabled", properties.getLayer1().getRag().isMultiQuerySearchEnabled());
        values.put("layer1.rag.supportingSearchEnabled", properties.getLayer1().getRag().isSupportingSearchEnabled());
        values.put("layer1.timeout.ragMs", properties.getLayer1().getTimeout().getRagMs());
        values.put("layer1.timeout.interactiveRagWaitMs", properties.getLayer1().getTimeout().getInteractiveRagWaitMs());
        values.put("layer2.ragTopK", properties.getLayer2().getRagTopK());
        values.put("layer2.rag.similarityThreshold", properties.getLayer2().getRag().getSimilarityThreshold());
        values.put("truncation.layer1.ragDocument", properties.getTruncation().getLayer1().getRagDocument());
        values.put("truncation.layer2.ragDocument", properties.getTruncation().getLayer2().getRagDocument());
        StringBuilder text = new StringBuilder();
        values.forEach((key, value) -> text.append(key).append('=').append(value).append('\n'));
        return text.toString();
    }

    private static String budgetProfiles() {
        StringBuilder text = new StringBuilder();
        for (PromptBudgetProfile profile : PromptBudgetProfile.values()) {
            text.append(profile.name()).append('=').append(new TreeMap<>(profile.toMetadataMap())).append('\n');
        }
        return text.toString();
    }

    private static Map<String, String> sections(String prompt) {
        Map<String, String> sections = new LinkedHashMap<>();
        String current = "(preamble)";
        StringBuilder body = new StringBuilder();
        for (String line : PromptBundleHashes.normalizeText(prompt).split("\n", -1)) {
            if (line.startsWith("=== ") && line.endsWith(" ===")) {
                sections.merge(current, body.toString(), (left, right) -> left + right);
                current = line;
                body = new StringBuilder();
            }
            else {
                body.append(line).append('\n');
            }
        }
        sections.merge(current, body.toString(), (left, right) -> left + right);
        return sections;
    }
}
