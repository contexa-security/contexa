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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.adjudication.SealedEvidencePromptScorecard;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePromptEvidenceBackfill;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import io.contexa.contexacore.verification.prompt.VerificationPromptReplayBuilder;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.replay.DeterministicReplayService;
import io.contexa.contexacore.verification.inspection.DecisionFactMatchCheck;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.InspectionCheckRunner;
import io.contexa.contexacore.verification.inspection.PastRecordNotationCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * v1.0 (plan 2.3 A20 to A27, D3): a v1.0 package is inspected as a dictionary prompt with its variant's dictionary; the
 * lines v1.0 adds, the conclusion lines of a variant with the decision rules and the similar case lines are compared with
 * the sealed sources the render drew them from.
 */
class SecurityDecisionV1InspectionTest {

    private static final String OTHER_TARGET_PATH = "/api/documents/ZZ-SIMILAR-9/download";

    @Test
    void everyCoreCheckFindsAFallbackRenderWithSimilarCasesSound() {
        Sealed sealed = seal(MeasuredVariant.FALLBACK_SIMILAR, 3);

        for (PromptInspectionCheck check : PromptInspector.coreChecks()) {
            PromptInspectionCheckResult result = run(check, SecurityDecisionPromptDictionary.V1_RULES_ENTRIES, sealed);
            assertThat(result.mismatched()).as(check.code() + " " + mismatches(result)).isZero();
        }
    }

    @Test
    void everyCoreCheckFindsARecordRenderSound() {
        Sealed sealed = seal(MeasuredVariant.RECORD_EXACT, 0);

        for (PromptInspectionCheck check : PromptInspector.coreChecks()) {
            PromptInspectionCheckResult result = run(check, SecurityDecisionPromptDictionary.V1_ENTRIES, sealed);
            assertThat(result.mismatched()).as(check.code() + " " + mismatches(result)).isZero();
        }
    }

    @Test
    void theSimilarCaseLinesAndTargetsAreTheSealedSimilarCases() {
        Sealed sealed = seal(MeasuredVariant.RECORD_SIMILAR, 3);
        List<Integer> similarLines = linesStarting(sealed.pkg().getUserPromptText(), "SimilarCase");
        String tampered = sealed.pkg().getUserPromptText().replaceFirst("(?m)^((\\[P\\d+\\] )?SimilarCase2: \\S+)", "$1 9");

        PromptInspectionCheckResult notation = run(new PastRecordNotationCheck(),
                SecurityDecisionPromptDictionary.V1_ENTRIES, sealed);
        PromptInspectionCheckResult target = run(new FactAccuracyCheck(), SecurityDecisionPromptDictionary.V1_ENTRIES,
                sealed);
        PromptInspectionCheckResult broken = run(new PastRecordNotationCheck(),
                SecurityDecisionPromptDictionary.V1_ENTRIES, sealed.withUserPrompt(tampered));

        assertThat(similarLines).hasSize(3);
        assertThat(notation.matchedLines()).containsAll(similarLines);
        assertThat(sealed.pkg().getUserPromptText()).contains(UntrustedTextSources.SIMILAR_CASE_TARGET);
        assertThat(target.mismatched()).as(mismatches(target)).isZero();
        assertThat(target.matchedLines()).contains(linesStarting(sealed.pkg().getUserPromptText(),
                "UntrustedText").stream().filter(line -> sealed.pkg().getUserPromptText().lines().toList()
                .get(line - 1).contains(UntrustedTextSources.SIMILAR_CASE_TARGET)).findFirst().orElseThrow());
        assertThat(broken.findings()).anyMatch(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH
                && "SimilarCase2".equals(finding.entry()));
    }

    @Test
    void theConclusionLinesAreTheConclusionsTheSealedContextGives() {
        Sealed sealed = seal(MeasuredVariant.FALLBACK_EXACT, 0);
        String tampered = sealed.pkg().getUserPromptText().replaceFirst("(?m)^((\\[F\\d+\\] )?PolicySatisfied: )(.*)$",
                "$1tampered");

        PromptInspectionCheckResult result = run(new DecisionFactMatchCheck(),
                SecurityDecisionPromptDictionary.V1_RULES_ENTRIES, sealed);
        PromptInspectionCheckResult broken = run(new DecisionFactMatchCheck(),
                SecurityDecisionPromptDictionary.V1_RULES_ENTRIES, sealed.withUserPrompt(tampered));

        assertThat(sealed.pkg().getUserPromptText()).containsPattern("(?m)^(\\[F\\d+\\] )?PolicySatisfied: ");
        assertThat(result.mismatched()).as(mismatches(result)).isZero();
        assertThat(broken.findings()).anyMatch(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH
                && "PolicySatisfied".equals(finding.entry()));
    }

    @Test
    void aV1PackageIsReadAsADictionaryPromptWithItsVariantsDictionary() {
        PromptInspector inspector = new PromptInspector(PromptInspector.coreChecks(), InspectionGolden.JSON);

        PromptInspectionResult rules = inspector.inspect(seal(MeasuredVariant.FALLBACK_SIMILAR, 3).pkg());
        PromptInspectionResult records = inspector.inspect(seal(MeasuredVariant.RECORD_EXACT, 0).pkg());

        assertThat(rules.layoutVersion()).isEqualTo(PromptInspector.V1_LAYOUT);
        assertThat(rules.dictionaryVersion()).isEqualTo(PromptInspector.V1_RULES_DICTIONARY_VERSION);
        assertThat(records.dictionaryVersion()).isEqualTo(PromptInspector.V1_DICTIONARY_VERSION);
        assertThat(List.of(rules.verdict(), records.verdict())).doesNotContain(PromptInspectionVerdict.NOT_APPLICABLE,
                PromptInspectionVerdict.FAIL, PromptInspectionVerdict.ERROR);
    }

    /**
     * Plan 2.3 B10: the scorecard reads a v1.0 package in its dictionary form (the output section, the action schema,
     * the blocks and the evidence lines it draws), not by the v19 sections it does not have.
     */
    @Test
    void theScorecardReadsAV1PackageInItsDictionaryForm() {
        ScorecardResult result = new SealedEvidencePromptScorecard(InspectionGolden.JSON)
                .evaluate(seal(MeasuredVariant.FALLBACK_SIMILAR, 3).pkg());
        Map<String, Boolean> checks = new LinkedHashMap<>();
        result.checks().forEach(check -> checks.put(check.label(), check.passed()));

        assertThat(checks).containsEntry("systemPrompt contains OUTPUT section", true)
                .containsEntry("systemPrompt contains output_format", true)
                .containsEntry("systemPrompt contains action schema", true)
                .containsEntry("userPrompt contains USER BASELINE block", true)
                .containsEntry("userPrompt contains SESSION block", true)
                .containsEntry("userPrompt contains REQUEST block", true)
                .containsEntry("userPrompt contains DECISION FACTS block", true)
                .containsEntry("userPrompt contains LoginMethod evidence", true)
                .containsEntry("userPrompt contains ResourceClass evidence", true)
                .containsEntry("userPrompt contains BaselineStatus evidence", true)
                .doesNotContainKey("userPrompt contains CURRENT REQUEST AND EVENT section")
                .doesNotContainKey("systemPrompt contains DECISION section");
    }

    /**
     * Plan 2.3 B12: the deterministic replay computes a v1.0 package's lines again from its sealed sources instead of
     * looking for the v19 sections it does not have.
     */
    @Test
    void theDeterministicReplayComputesAV1PackagesLinesAgain() {
        SealedEvidencePackage pkg = seal(MeasuredVariant.FALLBACK_SIMILAR, 3).pkg();
        String packageId = pkg.getPackageId() != null ? pkg.getPackageId() : "pkg-v1-deterministic";
        pkg.setPackageId(packageId);
        SealedEvidencePackageLookupPort lookup = mock(SealedEvidencePackageLookupPort.class);
        when(lookup.findByPackageId(packageId)).thenReturn(Optional.of(pkg));
        DeterministicReplayService replay = new DeterministicReplayService(lookup, InspectionGolden.SERIALIZER,
                new PromptContextComposer(), new SealedEvidencePackageIntegrity(), new VerificationPromptReplayBuilder(),
                new PromptInspector(PromptInspector.coreChecks(), InspectionGolden.JSON));

        DeterministicReplayResult result = replay.replay(packageId);

        assertThat(result.diffSummary()).noneMatch(finding -> finding.startsWith("CONTEXT_SECTION_DRIFT")
                || finding.startsWith("CONTEXT_REASSEMBLY_EMPTY") || finding.startsWith("CONTEXT_LINE_DRIFT")
                || finding.startsWith("CONTEXT_REINSPECTION_FAILED"));
    }

    /**
     * Plan 2.3 B13: the evidence backfill reads a v1.0 package's facts on the dictionary lines their v19 labels went to,
     * and a requester's text in UNTRUSTED TEXT, so they count as reaching the prompt.
     */
    @Test
    void theEvidenceBackfillReadsAV1PackageOnItsDictionaryLines() throws Exception {
        SealedEvidencePackage pkg = seal(MeasuredVariant.FALLBACK_SIMILAR, 3).pkg();
        SealedEvidencePackage withoutLayout = seal(MeasuredVariant.FALLBACK_SIMILAR, 3).pkg();
        Map<String, Object> metadata = InspectionGolden.JSON.readValue(withoutLayout.getPromptExecutionMetadataJson(),
                new TypeReference<>() {
                });
        metadata.remove(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR);
        withoutLayout.setPromptExecutionMetadataJson(InspectionGolden.JSON.writeValueAsString(metadata));

        Map<String, String> dictionary = states(pkg);
        Map<String, String> v19Reading = states(withoutLayout);

        // The golden package seals no authentication state, so the fields read from it have no evidence here.
        assertThat(dictionary).containsEntry("clientIp", "PRESENT")
                .containsEntry("httpMethod", "PRESENT")
                .containsEntry("userId", "PRESENT")
                .containsEntry("requestPath", "PRESENT");
        assertThat(dictionary.values().stream().filter("PRESENT"::equals).count())
                .isGreaterThan(v19Reading.values().stream().filter("PRESENT"::equals).count());
    }

    /** Each evidence field's projection state the backfill gives the package. */
    private static Map<String, String> states(SealedEvidencePackage pkg) throws Exception {
        SealedEvidencePackage prepared = SealedEvidencePromptEvidenceBackfill.prepare(InspectionGolden.JSON, pkg)
                .packageForVerification();
        JsonNode manifest = InspectionGolden.JSON.readTree(prepared.getPromptEvidenceManifestJson());
        Map<String, String> states = new LinkedHashMap<>();
        manifest.path("fields").forEach(field -> states.put(field.path("fieldKey").asText(),
                field.path("projectionState").asText()));
        return states;
    }

    /** A rendered v1.0 package, its sealed execution metadata and the context the render used. */
    private record Sealed(InspectionGolden.Render render, SealedEvidencePackage pkg, Map<String, Object> metadata) {

        Sealed withUserPrompt(String userPrompt) {
            return new Sealed(render, render.sealed(userPrompt), metadata);
        }
    }

    private static PromptInspectionCheckResult run(PromptInspectionCheck check, List<PromptDictionaryEntry> dictionary,
                                                   Sealed sealed) {
        return InspectionCheckRunner.run(check.forV1(dictionary), sealed.pkg(), PromptInspector.V1_LAYOUT,
                sealed.metadata(), sealed.render().used());
    }

    /**
     * The A1 case rendered by the bundle with copies of its first records as similar cases (the first at another
     * target), sealed as the assembler seals it: the past records and, apart, the similar cases.
     */
    private static Sealed seal(MeasuredVariant variant, int similarCases) {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        JsonNode a1 = golden.cases().stream().filter(item -> "A1".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        ObjectNode input = a1.deepCopy();
        ArrayNode documents = (ArrayNode) input.path("ragResults").path("relatedDocuments");
        ObjectNode sealedRetrieval = ((ObjectNode) a1.path("ragResults")).deepCopy();
        ArrayNode sealedSimilar = sealedRetrieval.putArray(SimilarCases.SEALED_KEY);
        for (int index = 0; index < similarCases; index++) {
            ObjectNode copy = documents.get(index).deepCopy();
            copy.put("id", "similar-case-" + index);
            copy.put("eventId", "similar-event-" + index);
            if (index == 0) {
                copy.put("requestPath", OTHER_TARGET_PATH);
            }
            sealedSimilar.add(copy.deepCopy());
            copy.put(SimilarCases.MARK, true);
            documents.add(copy);
        }
        if (similarCases == 0) {
            sealedRetrieval.remove(SimilarCases.SEALED_KEY);
        }
        SecurityDecisionGoldenRender.RenderedCase rendered = golden.renderVersion(input,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, new TieredStrategyProperties(), variant.store(),
                MeasuredVariant.VERSION, Map.of());
        InspectionGolden.Render render = new InspectionGolden.Render(rendered.caseKey(),
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, rendered.systemText(), rendered.userText(),
                rendered.canonicalContext(), rendered.executionMetadata().toMetadataMap(), sealedRetrieval.toString(),
                a1.path("requestFacts").toString());
        SealedEvidencePackage pkg = render.sealed();
        try {
            Map<String, Object> metadata = InspectionGolden.JSON.readValue(pkg.getPromptExecutionMetadataJson(),
                    new TypeReference<>() {
                    });
            return new Sealed(render, pkg, metadata);
        }
        catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static List<Integer> linesStarting(String userPrompt, String label) {
        List<String> lines = userPrompt.lines().toList();
        return IntStream.range(0, lines.size())
                .filter(index -> InspectionGolden.bare(lines.get(index)).startsWith(label))
                .mapToObj(index -> index + 1).toList();
    }

    private static String mismatches(PromptInspectionCheckResult result) {
        return String.join("; ", result.findings().stream()
                .filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .map(PromptInspectionFinding::toString).toList());
    }
}
