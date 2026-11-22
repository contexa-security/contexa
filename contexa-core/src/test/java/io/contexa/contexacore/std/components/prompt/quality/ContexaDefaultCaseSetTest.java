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
package io.contexa.contexacore.std.components.prompt.quality;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.autonomous.tiered.prompt.SimilarCases;
import io.contexa.contexacore.autonomous.tiered.prompt.V1LineValues;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.2: the default case set Contexa ships is the 60 cases and the 10 control cases of the local measurement, as
 * finished cases in a product resource. The resource is the one the generator makes from the golden inputs, and every
 * case has the definition the local measurement wrote beside its answers.
 */
class ContexaDefaultCaseSetTest {

    /** The version of the shipped set. A change of any case changes it, and the change is made here on purpose. */
    private static final String SHIPPED_VERSION = "97d66c58e468f8774b5f5c76233f20a4e400a47abcc502b39172e1308dd37ebb";

    private static final Pattern HANGUL = Pattern.compile("[\\uAC00-\\uD7A3]");

    /** The explanation the local measurement expected of each kind. */
    private static final Map<QualityCaseKind, String> HYPOTHESIS = Map.of(QualityCaseKind.NORMAL_WORK, "H1",
            QualityCaseKind.OUTSIDER, "H2", QualityCaseKind.INSIDER, "H3", QualityCaseKind.AUTOMATION, "H4");

    private static QualityCaseSet shipped;

    @BeforeAll
    static void readTheShippedSet() {
        shipped = QualityCaseSetReader.contexaDefault();
    }

    @Test
    void theShippedSetIsTheOneTheGeneratorMakesFromTheGoldenInputs() throws IOException {
        QualityCaseSet made;
        try (InputStream golden = getClass().getClassLoader()
                .getResourceAsStream(ContexaDefaultCaseSetGenerator.GOLDEN_RESOURCE)) {
            made = ContexaDefaultCaseSetGenerator.build(ContexaDefaultCaseSetGenerator.readGolden(golden));
        }

        assertThat(shipped.name()).isEqualTo(QualityCaseSet.CONTEXA_DEFAULT);
        assertThat(shipped.cases()).extracting(QualityCase::key)
                .containsExactlyElementsOf(made.cases().stream().map(QualityCase::key).toList());
        // The content hash covers the whole input and the right answer, so equal hashes are equal cases.
        for (QualityCase item : made.cases()) {
            assertThat(shipped.find(item.key()).orElseThrow().contentHash()).as("content of %s", item.key())
                    .isEqualTo(item.contentHash());
        }
        assertThat(shipped.version()).isEqualTo(made.version()).isEqualTo(SHIPPED_VERSION);
    }

    @Test
    void everyCaseHasTheDefinitionTheLocalMeasurementWroteBesideItsAnswers() {
        List<QualityFixtures.LocalRow> rows = new ArrayList<>(QualityFixtures.localRows("n1-60.jsonl"));
        rows.addAll(QualityFixtures.localRows("n1-ver-base.jsonl"));

        assertThat(rows).hasSize(70);
        assertThat(shipped.cases()).extracting(QualityCase::key)
                .containsExactlyInAnyOrderElementsOf(rows.stream().map(QualityFixtures.LocalRow::caseKey).toList());
        for (QualityFixtures.LocalRow row : rows) {
            QualityCase item = shipped.find(row.caseKey()).orElseThrow();
            QualityCaseExpectation expectation = item.expectation();
            boolean control = "VERIFIED".equals(row.kind());
            // The control cases are outsiders (the account is taken over) that must be caught.
            String kind = control ? "OUTSIDER" : "NORMAL".equals(row.kind()) ? "NORMAL_WORK" : row.kind();
            assertThat(expectation.kind().name()).as("kind of %s", row.caseKey()).isEqualTo(kind);
            assertThat(expectation.classification().name()).as("class of %s", row.caseKey()).isEqualTo(row.expected());
            assertThat(expectation.allowedActions().stream().map(Enum::name).collect(Collectors.toSet()))
                    .as("allowed actions of %s", row.caseKey()).isEqualTo(Set.copyOf(row.allowed()));
            assertThat(HYPOTHESIS.get(expectation.kind())).as("explanation of %s", row.caseKey())
                    .isEqualTo(row.hypothesis());
            assertThat(item.grade()).as("grade of %s", row.caseKey())
                    .isEqualTo(control ? QualityCaseGrade.MUST_CATCH : QualityCaseGrade.ORDINARY);
        }
    }

    @Test
    void theSetHoldsFifteenCasesOfEachKindAndTheTenControlCases() {
        List<QualityCase> sixty = shipped.cases().stream()
                .filter(item -> item.grade() == QualityCaseGrade.ORDINARY).toList();
        List<QualityCase> controls = shipped.cases().stream()
                .filter(item -> item.grade() == QualityCaseGrade.MUST_CATCH).toList();

        assertThat(shipped.cases()).hasSize(70);
        assertThat(sixty).hasSize(60);
        for (QualityCaseKind kind : QualityCaseKind.values()) {
            assertThat(sixty).filteredOn(item -> item.expectation().kind() == kind).as("cases of %s", kind)
                    .hasSize(15);
        }
        assertThat(sixty).filteredOn(item -> item.expectation().classification() == QualityCaseClass.THREAT)
                .hasSize(44);
        assertThat(sixty).filteredOn(item -> item.expectation().classification() == QualityCaseClass.UNCERTAIN)
                .extracting(QualityCase::key).containsExactly("S07");
        assertThat(sixty).filteredOn(item -> item.expectation().classification() == QualityCaseClass.NORMAL)
                .hasSize(15);
        assertThat(controls).hasSize(10).allSatisfy(item -> {
            assertThat(item.key()).startsWith("VER-");
            assertThat(item.expectation().allowedActions()).containsExactly(QualityAction.BLOCK);
        });
        assertThat(shipped.cases()).noneMatch(item -> item.grade() == QualityCaseGrade.MUST_NOT_BLOCK);
    }

    @Test
    void aVariantNamesTheSealedDecisionItWasMadeFromAndCountsUnderIt() {
        List<QualityCase> originals = shipped.cases().stream().filter(item -> item.rootCaseKey() == null).toList();
        List<QualityCase> variants = shipped.cases().stream().filter(item -> item.rootCaseKey() != null).toList();
        Set<String> originalKeys = originals.stream().map(QualityCase::key).collect(Collectors.toSet());

        // 25 sealed decisions; 35 variants of the 10 normal ones and the 10 control cases.
        assertThat(originals).hasSize(25);
        assertThat(variants).hasSize(45).allSatisfy(item -> {
            assertThat(originalKeys).contains(item.rootCaseKey());
            assertThat(item.key()).endsWith("-" + item.rootCaseKey());
        });
        assertThat(variants).filteredOn(item -> item.grade() == QualityCaseGrade.ORDINARY)
                .extracting(QualityCase::rootKey).containsOnly("A1T", "A3T", "A3ST", "A5T", "A6T", "A8T", "K2", "S01",
                        "S02", "S03");
        // The 60 cases count as 25 roots, the 45 that must be stopped as 25 and the 15 to allow as 10.
        List<QualityCase> sixty = shipped.cases().stream()
                .filter(item -> item.grade() == QualityCaseGrade.ORDINARY).toList();
        assertThat(sixty.stream().map(QualityCase::rootKey).distinct()).hasSize(25);
        assertThat(sixty.stream().filter(QualityCase::shouldStop).map(QualityCase::rootKey).distinct()).hasSize(25);
        assertThat(sixty.stream().filter(item -> !item.shouldStop()).map(QualityCase::rootKey).distinct()).hasSize(10);
    }

    @Test
    void everyCaseSaysWhyInKoreanAndEnglishAndFixesItsEnvironment() {
        assertThat(shipped.cases()).allSatisfy(item -> {
            QualityCaseExpectation expectation = item.expectation();
            assertThat(expectation.rationale().korean()).as("Korean reason of %s", item.key()).isNotBlank()
                    .containsPattern(HANGUL);
            assertThat(expectation.rationale().english()).as("English reason of %s", item.key()).isNotBlank()
                    .doesNotContainPattern(HANGUL);
            // Nothing says which stopping action is the most desirable; normal work is best allowed.
            assertThat(expectation.preferredAction()).as("preferred action of %s", item.key()).isEqualTo(
                    expectation.classification() == QualityCaseClass.NORMAL ? QualityAction.ALLOW : null);
            assertThat(expectation.decidingFacts().isEmpty()).as("deciding facts of %s", item.key())
                    .isEqualTo(item.rootCaseKey() == null);
            assertThat(item.environment()).isEqualTo(new QualityCaseEnvironment("UTC", "1"));
            assertThat(item.origin()).isEqualTo(QualityCaseOrigin.CONTEXA);
            assertThat(item.addedAt()).isNull();
        });
    }

    @Test
    void theInputIsWhatTheReplayReadsAndCarriesNoPromptText() throws IOException {
        assertThat(shipped.cases()).allSatisfy(item -> {
            QualityCaseInput input = item.input();
            assertThat(input.canonicalContext().path("session").isObject()).isTrue();
            assertThat(input.requestFacts().path("userId").asText()).isNotBlank();
            assertThat(input.authState().has("authMethod")).isTrue();
            assertThat(input.baselineSnapshot().isObject()).isTrue();
            assertThat(input.ragResults().isObject()).isTrue();
            assertThat(input.personalBaseline()).isNotNull();
        });
        // A control case carries the signal under the source the product trusts.
        QualityCase control = shipped.find("VER-A1T").orElseThrow();
        assertThat(control.input().canonicalContext().path("intent").path("anomalySignalSource").asText())
                .isEqualTo(V1LineValues.TRUSTED_SIGNAL_SOURCE)
                .isEqualTo(ContexaDefaultCaseSetGenerator.TRUSTED_SIGNAL_SOURCE);
        assertThat(ContexaDefaultCaseSetGenerator.SIMILAR_CASES).isEqualTo(SimilarCases.SEALED_KEY);

        String document;
        try (InputStream resource = getClass().getClassLoader()
                .getResourceAsStream(QualityCaseSetReader.CONTEXA_DEFAULT_RESOURCE);
             GZIPInputStream json = new GZIPInputStream(resource)) {
            document = new String(json.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertThat(document).doesNotContain("rawSystemPrompt", "rawUserPrompt", "You are the Zero Trust",
                "=== USER BASELINE");
    }

    /**
     * K189: every variant states the decision facts the engine draws from its changed input when a replay draws its
     * prompt, so no fact of its root stays beside the change: an insider without the record that covered the work is
     * known to be off duty, and no removed record covers the request any more. A sealed decision keeps the facts it was
     * sealed with, as an engine before this one wrote them; a replay draws them again in any case.
     */
    @Test
    void everyVariantStatesTheDecisionFactsTheEngineDrawsFromItsInput() {
        List<QualityCase> variants = shipped.cases().stream().filter(item -> item.rootCaseKey() != null).toList();
        List<String> differing = variants.stream().filter(item -> !ContexaDefaultCaseSetGenerator
                .drawnDecisionFacts(item.key(), item.input())
                .equals(item.input().canonicalContext().path("decisionFacts"))).map(QualityCase::key).toList();

        assertThat(variants).hasSize(45);
        assertThat(differing).as("variants whose decision facts are not the ones drawn from their input").isEmpty();
        for (String key : List.of("INS-S02", "INS-S03", "INS-A6T")) {
            JsonNode facts = shipped.find(key).orElseThrow().input().canonicalContext().path("decisionFacts");
            assertThat(facts.path("unknown").toString()).as("unknown facts of %s", key).doesNotContain("OnCall");
            assertThat(facts.toString()).as("records of %s", key).doesNotContain("APR-", "TCK-", "ONC-");
        }
    }

    @Test
    void theVersionIsFixedByTheContentOfTheCasesAndNothingElse() {
        QualityCase threat = QualityFixtures.threat("T1");
        QualityCase normal = QualityFixtures.normal("N1");
        String version = new QualityCaseSet("one", List.of(threat, normal)).version();

        assertThat(version).matches("[0-9a-f]{64}");
        // The order of the cases and the name of the set do not count; where a case comes from and when do not either.
        assertThat(new QualityCaseSet("other", List.of(normal, threat)).version()).isEqualTo(version);
        QualityCase promoted = new QualityCase(threat.key(), threat.input(), threat.expectation(), threat.grade(),
                threat.rootCaseKey(), threat.environment(), QualityCaseOrigin.OPERATION,
                Instant.parse("2026-11-22T00:00:00Z"));
        assertThat(new QualityCaseSet("one", List.of(promoted, normal)).version()).isEqualTo(version);

        // The right answer, the grade, the root, the environment and the input each count.
        QualityCase blockOnly = QualityFixtures.of("T1", null, QualityCaseClass.THREAT, EnumSet.of(QualityAction.BLOCK),
                QualityCaseGrade.ORDINARY, QualityCaseOrigin.CONTEXA, null);
        QualityCase graded = QualityFixtures.of("T1", null, QualityCaseClass.THREAT, EnumSet.of(QualityAction.BLOCK),
                QualityCaseGrade.MUST_CATCH, QualityCaseOrigin.CONTEXA, null);
        QualityCase rooted = QualityFixtures.threat("T1", "T0");
        QualityCase elsewhere = new QualityCase(threat.key(), threat.input(), threat.expectation(), threat.grade(),
                null, new QualityCaseEnvironment("Asia/Seoul", "1"), threat.origin(), null);
        QualityCase otherInput = new QualityCase(threat.key(),
                QualityFixtures.input(QualityFixtures.JSON.createObjectNode().put("requestObservedAt", "2026-09-30")),
                threat.expectation(), threat.grade(), null, threat.environment(), threat.origin(), null);
        assertThat(List.of(blockOnly, graded, rooted, elsewhere, otherInput)).allSatisfy(changed ->
                assertThat(new QualityCaseSet("one", List.of(changed, normal)).version()).isNotEqualTo(version));
        assertThat(Set.of(threat.contentHash(), blockOnly.contentHash(), graded.contentHash(), rooted.contentHash(),
                elsewhere.contentHash(), otherInput.contentHash())).hasSize(6);
    }

    @Test
    void theHashReadsValuesNotTheirText() throws IOException {
        QualityCase written = caseOf("{\"b\": [1, 2.50, true, null], \"a\": {\"y\": \"t\", \"x\": 10}}");
        QualityCase rewritten = caseOf("{\"a\":{\"x\":10,\"y\":\"t\"},\"b\":[1,2.5,true,null]}");
        QualityCase otherNumber = caseOf("{\"a\":{\"x\":10.0,\"y\":\"t\"},\"b\":[1,2.5,true,null]}");
        QualityCase otherOrder = caseOf("{\"a\":{\"x\":10,\"y\":\"t\"},\"b\":[2.5,1,true,null]}");

        // The order of fields and the spelling of a number do not count; a whole number is not a fractional one, and
        // the order of a list counts.
        assertThat(rewritten.contentHash()).isEqualTo(written.contentHash());
        assertThat(otherNumber.contentHash()).isNotEqualTo(written.contentHash());
        assertThat(otherOrder.contentHash()).isNotEqualTo(written.contentHash());
    }

    private static QualityCase caseOf(String canonicalContext) throws IOException {
        QualityCase threat = QualityFixtures.threat("T1");
        return new QualityCase(threat.key(), QualityFixtures.input(QualityFixtures.JSON.readTree(canonicalContext)),
                threat.expectation(), threat.grade(), null, threat.environment(), threat.origin(), null);
    }
}
