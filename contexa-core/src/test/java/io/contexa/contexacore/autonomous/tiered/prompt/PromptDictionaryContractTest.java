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
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionarySlotPlanProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptMissingNotation;
import io.contexa.contexacore.autonomous.context.prompt.PromptListOrder;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlot;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotPlan;
import io.contexa.contexacore.autonomous.context.prompt.PromptSourceGrade;
import io.contexa.contexacore.verification.inspection.DictionaryContractCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-1: the v20 prompt dictionary in code equals the dictionary document (docs/showcase/프롬프트-v20-사전.md, read
 * into prompt-dictionary/v20-dictionary-doc.json) and keeps a place for every fact the v19 prompt and the canonical
 * context carry (prompt-dictionary/v19-inventory-places.json from the inventory and the removal list).
 */
class PromptDictionaryContractTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> PRIORITIES = Set.of(PromptDictionaryEntry.PRIORITY_REQUIRED,
            PromptDictionaryEntry.PRIORITY_HIGH_VALUE, PromptDictionaryEntry.PRIORITY_SUPPORTING);
    /**
     * The places that are not an entry. {@code REMOVED:Q-n}: the user removed the fact under principle 14 (W3-5, the
     * prompt-quality verification mark, Q-73 T1).
     */
    private static final Pattern PLACE_KIND = Pattern.compile(
            "(BLOCK_HEADER|BLOCK_LINES):[A-Z_]+|BLOCK_HEADERS|SOURCE_GRADE|SYSTEM_TEXT|NO_FACT|REMOVED:Q-\\d+");

    private static JsonNode document;
    private static JsonNode inventory;
    private static Map<String, PromptDictionaryEntry> entries;

    @BeforeAll
    static void load() throws IOException {
        document = read("/prompt-dictionary/v20-dictionary-doc.json");
        inventory = read("/prompt-dictionary/v19-inventory-places.json");
        entries = new LinkedHashMap<>();
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            entries.put(key(entry), entry);
        }
    }

    /** The seven user blocks, and the SECOND PASS block a Layer2 second pass adds after them (W3-9). */
    @Test
    void theBlocksAreTheUserBlocksInRenderingOrder() {
        assertThat(Arrays.stream(PromptBlock.values()).map(PromptBlock::title)).containsExactly(
                "USER BASELINE", "SESSION", "REQUEST", "DECISION FACTS", "PAST RECORDS", "UNKNOWN", "UNTRUSTED TEXT",
                "SECOND PASS");
        assertThat(Arrays.stream(PromptBlock.values()).map(PromptBlock::factPrefix)).containsExactly(
                "B", "S", "R", "F", "P", null, null, null);
        assertThat(PromptBlock.fromSectionKey("=== USER BASELINE (learned; time zone Asia/Seoul) ===")).contains(
                PromptBlock.USER_BASELINE);
        assertThat(PromptBlock.fromSectionKey("DECISION FACTS")).contains(PromptBlock.DECISION_FACTS);
        assertThat(PromptBlock.fromSectionKey("SESSION NARRATIVE CONTEXT")).isEmpty();
        assertThat(PromptBlock.fromSectionKey("CURRENT REQUEST AND EVENT")).isEmpty();
    }

    /** P3-EXTRA-18: the DeviationsFromBaseline examples use the form the resolver writes ('seen 0 of n'). */
    @Test
    void theDeviationExamplesUseTheFormTheResolverWrites() {
        PromptDictionaryEntry deviations = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(entry -> "DeviationsFromBaseline".equals(entry.name())).findFirst().orElseThrow();

        assertThat(deviations.formatExamples()).noneMatch(example -> example.contains(" never ("));
        assertThat(deviations.formatExamples().get(0))
                .contains("target projectKey seen 0 of 25 (unexplained); class CRITICAL seen 0 of 25 (unexplained)");
    }

    @Test
    void theEntriesAreTheDictionaryRowsInBlockOrder() {
        List<String> documented = new ArrayList<>();
        document.path("entries").forEach(row -> documented.add(row.path("block").asText() + "." + row.path("name").asText()));
        assertThat(entries.keySet()).containsExactlyElementsOf(documented);
        Map<PromptBlock, Long> perBlock = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .collect(Collectors.groupingBy(PromptDictionaryEntry::block, LinkedHashMap::new, Collectors.counting()));
        assertThat(perBlock).containsExactly(
                Map.entry(PromptBlock.USER_BASELINE, 18L), Map.entry(PromptBlock.SESSION, 12L),
                Map.entry(PromptBlock.REQUEST, 10L), Map.entry(PromptBlock.DECISION_FACTS, 24L),
                Map.entry(PromptBlock.PAST_RECORDS, 6L), Map.entry(PromptBlock.UNKNOWN, 2L),
                Map.entry(PromptBlock.UNTRUSTED_TEXT, 1L), Map.entry(PromptBlock.SECOND_PASS, 3L));
    }

    @Test
    void everyNameIsUsedOnce() {
        List<String> names = SecurityDecisionPromptDictionary.ENTRIES.stream().map(PromptDictionaryEntry::name).toList();
        assertThat(new HashSet<>(names)).hasSameSizeAs(names);
    }

    @Test
    void everyEntryCarriesItsColumns() {
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            String where = key(entry);
            assertThat(entry.meaning()).as(where + " meaning").isNotBlank();
            assertThat(entry.sourcePath()).as(where + " source").isNotBlank();
            assertThat(entry.formatPattern()).as(where + " format").isNotBlank();
            assertThat(Pattern.compile(entry.formatPattern())).as(where + " pattern").isNotNull();
            assertThat(entry.formatExamples()).as(where + " examples").isNotEmpty();
            assertThat(entry.missing()).as(where + " missing").isNotNull();
            assertThat(entry.decisionUse()).as(where + " use").isNotBlank();
            assertThat(entry.priority()).as(where + " priority").isIn(PRIORITIES);
            assertThat(entry.missingText() != null).as(where + " missing text")
                    .isEqualTo(entry.missing() == PromptMissingNotation.RENDERED_VALUE);
        }
    }

    @Test
    void gradesConditionsAndMissingNotationsFollowTheDictionary() {
        for (JsonNode row : document.path("entries")) {
            PromptDictionaryEntry entry = entries.get(row.path("block").asText() + "." + row.path("name").asText());
            String where = key(entry);
            Set<String> grades = new TreeSet<>();
            row.path("grades").forEach(grade -> grades.add(grade.asText()));
            Set<String> declared = entry.grades().stream().map(Enum::name).collect(Collectors.toCollection(TreeSet::new));
            assertThat(declared).as(where + " grades").isEqualTo(grades);
            assertThat(entry.conditional()).as(where + " conditional").isEqualTo(row.path("conditional").asBoolean());
            assertThat(entry.missing().name()).as(where + " missing").isEqualTo(row.path("missing").asText());
            assertThat(entry.missingText()).as(where + " missing text")
                    .isEqualTo(row.path("missingText").isNull() ? null : row.path("missingText").asText());
        }
    }

    @Test
    void onlyUntrustedTextMayBeCut() {
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            assertThat(entry.truncationAllowed()).as(key(entry))
                    .isEqualTo(entry.block() == PromptBlock.UNTRUSTED_TEXT);
            if (entry.block() == PromptBlock.UNTRUSTED_TEXT) {
                assertThat(entry.grades()).containsExactly(PromptSourceGrade.UNTRUSTED);
            }
        }
    }

    @Test
    void listCapsAreTheOnesTheDictionaryStates() {
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            Integer expected = "PastRecord{i}".equals(entry.name()) || "NewPastRecord{i}".equals(entry.name()) ? 5 : null;
            assertThat(entry.listCap()).as(key(entry)).isEqualTo(expected);
        }
    }

    /** Dictionary 1.5 (list orders), 2.2 (requests in time order) and 7 (past records); other entries are not lists. */
    @Test
    void listsAreOrderedByTheDictionaryRules() {
        Map<String, PromptListOrder> expected = Map.ofEntries(
                Map.entry("DeviationsFromBaseline", PromptListOrder.DIMENSION_ORDER),
                Map.entry("SameAsBaseline", PromptListOrder.DIMENSION_ORDER),
                Map.entry("UsualHours", PromptListOrder.ASCENDING),
                Map.entry("UsualActions", PromptListOrder.FREQUENCY_DESCENDING),
                Map.entry("UsualNetworks", PromptListOrder.NAME_ASCENDING),
                Map.entry("UsualDevices", PromptListOrder.NAME_ASCENDING),
                Map.entry("UsualTargets", PromptListOrder.NAME_ASCENDING),
                Map.entry("UsualLoginMethods", PromptListOrder.NAME_ASCENDING),
                Map.entry("UsualResourceClass", PromptListOrder.NAME_ASCENDING),
                Map.entry("Roles", PromptListOrder.NAME_ASCENDING),
                Map.entry("Permissions", PromptListOrder.NAME_ASCENDING),
                Map.entry("Unknown", PromptListOrder.NAME_ASCENDING),
                Map.entry("UsualDays", PromptListOrder.WEEKDAY),
                Map.entry("RequestsInSession", PromptListOrder.TIME),
                Map.entry("PastRecord{i}", PromptListOrder.PAST_RECORD),
                Map.entry("NewPastRecord{i}", PromptListOrder.PAST_RECORD));
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            assertThat(entry.listOrder()).as(key(entry))
                    .isEqualTo(expected.getOrDefault(entry.name(), PromptListOrder.NONE));
        }
        assertThat(PromptListOrder.DIMENSIONS).containsExactly(
                "time", "day", "network", "device", "login method", "target", "action", "class", "size", "rate");
    }

    @Test
    void priorityFollowsWhatTheDecisionUsesTheFactFor() {
        for (JsonNode row : document.path("entries")) {
            PromptDictionaryEntry entry = entries.get(row.path("block").asText() + "." + row.path("name").asText());
            List<String> cited = new ArrayList<>();
            row.path("citedByDecision").forEach(code -> cited.add(code.asText()));
            String expected = !cited.isEmpty() ? PromptDictionaryEntry.PRIORITY_REQUIRED
                    : row.path("referenceOnly").asBoolean() ? PromptDictionaryEntry.PRIORITY_SUPPORTING
                    : PromptDictionaryEntry.PRIORITY_HIGH_VALUE;
            assertThat(entry.priority()).as(key(entry)).isEqualTo(expected);
            for (String code : cited) {
                assertThat(entry.decisionUse()).as(key(entry) + " cites " + code).contains(code);
            }
        }
    }

    /**
     * W5-10 D6: the usual login methods take every recorded method name and a login of two methods joined by '+', as
     * the normalizer records them.
     */
    @Test
    void theUsualLoginMethodsTakeTheRecordedNamesAndALoginOfTwoMethods() {
        PromptDictionaryEntry entry = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(candidate -> candidate.block() == PromptBlock.USER_BASELINE
                        && "UsualLoginMethods".equals(candidate.name()))
                .findFirst().orElseThrow();

        assertThat(entry.acceptsValue("PASSWORD+ONE_TIME_CODE")).isTrue();
        assertThat(entry.acceptsValue("PASSWORD, PASSWORD+ONE_TIME_CODE")).isTrue();
        assertThat(entry.acceptsValue("MFA_ONLY")).isTrue();
        assertThat(entry.acceptsValue("PASSWORD; source host")).isFalse();
    }

    /** Examples with angle-bracket placeholders or an ellipsis stand for values the measured run did not have. */
    @Test
    void everyMeasuredExampleHasTheEntryForm() {
        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.ENTRIES) {
            for (String example : entry.formatExamples()) {
                assertThat(example).as(key(entry) + " example").doesNotContain("\r", "\n");
                if (!example.contains("〈") && !example.contains("…")) {
                    assertThat(entry.acceptsValue(example)).as(key(entry) + " accepts " + example).isTrue();
                }
            }
            if (entry.missingText() != null) {
                assertThat(entry.missingText()).as(key(entry)).doesNotContain("\r", "\n");
            }
        }
    }

    /**
     * W3-12 (one form per fact, P3 change 3): the values real v20 prompts wrote in the single vocabulary of their source
     * (the W2-4 device and band, the view's class, enum names, the resolver's wording) have their entry's form, as does an
     * entry's own missing text.
     */
    @Test
    void theRealValuesOfTheSourceVocabularyHaveTheEntryForm() throws IOException {
        JsonNode real = read("/prompt-dictionary/v20-real-values.json").path("values");
        assertThat(real.size()).isPositive();
        real.fieldNames().forEachRemaining(key -> {
            PromptDictionaryEntry entry = entries.get(key);
            assertThat(entry).as(key).isNotNull();
            for (JsonNode value : real.path(key)) {
                assertThat(entry.acceptsValue(value.asText()) || value.asText().equals(entry.missingText()))
                        .as(key + " accepts " + value.asText()).isTrue();
            }
        });
    }

    @Test
    void theDictionaryKeepsEveryLabelItPreserves() {
        for (JsonNode row : document.path("entries")) {
            PromptDictionaryEntry entry = entries.get(row.path("block").asText() + "." + row.path("name").asText());
            row.path("preservedLabels").forEach(label ->
                    assertThat(entry.preservedLabels()).as(key(entry)).contains(label.asText()));
        }
        document.path("blockHeaders").fields().forEachRemaining(header -> header.getValue().forEach(label ->
                assertThat(SecurityDecisionPromptDictionary.BLOCK_HEADER_PRESERVED_LABELS
                        .get(PromptBlock.valueOf(header.getKey()))).as(header.getKey()).contains(label.asText())));
    }

    @Test
    void everyFactOfThePreservationTableKeepsAPlace() {
        assertThat(document.path("preservedFacts")).hasSize(52);
        document.path("preservedFacts").forEach(fact -> assertPlaces(fact.path("label").asText(), fact.path("places")));
    }

    @Test
    void everyPendingStandardContextLabelKeepsAPlace() {
        assertThat(document.path("pendingFacts")).hasSize(50);
        document.path("pendingFacts").forEach(fact -> assertPlaces(fact.path("label").asText(), fact.path("places")));
    }

    /**
     * Inventory sections 1 (labels of the recorded prompts), 2 (lines without a label), 7 and 8 (labels only the
     * canonical context assembler or a supporting section can write); sections 3 to 6 belong to the system prompt,
     * past record fields, response fields and event metadata (W4-1, W3-3, W4-2).
     */
    @Test
    void everyLabelOfTheInventoryHasAPlace() {
        assertThat(inventory.path("labels")).hasSize(398);
        Map<String, Long> perPart = new LinkedHashMap<>();
        inventory.path("labels").forEach(label -> perPart.merge(label.path("part").asText(), 1L, Long::sum));
        assertThat(perPart).containsExactly(Map.entry("1", 191L), Map.entry("2", 50L), Map.entry("7", 98L),
                Map.entry("8", 59L));
        inventory.path("labels").forEach(label -> assertPlaces(label.path("label").asText(), label.path("places")));
    }

    @Test
    void theProviderGivesAV20LineItsEntryAndLeavesV19LinesAsBefore() {
        PromptDictionarySlotPlanProvider provider = SecurityDecisionPromptDictionary.slotPlanProvider();

        PromptSlotPlan policy = provider.planFor("=== DECISION FACTS ===", "PolicySatisfied");
        assertThat(policy.dictionaryEntry()).isSameAs(entries.get("DECISION_FACTS.PolicySatisfied"));
        assertThat(policy.slotKey()).isEqualTo("DECISION FACTS.PolicySatisfied");
        assertThat(policy.priority()).isEqualTo(PromptDictionaryEntry.PRIORITY_REQUIRED);
        assertThat(policy.truncationPolicy()).isEqualTo("FORBID_TRUNCATION");

        PromptSlotPlan record = provider.planFor("=== PAST RECORDS (learned; source personal retrieved subset) ===",
                "PastRecord3");
        assertThat(record.dictionaryEntry()).isSameAs(entries.get("PAST_RECORDS.PastRecord{i}"));
        assertThat(record.labelKey()).isEqualTo("PastRecord3");

        PromptSlotPlan text = provider.planFor("UNTRUSTED TEXT", "UntrustedText1");
        assertThat(text.truncationPolicy()).isEqualTo("STANDARD");

        PromptSlotPlan v19 = provider.planFor("SESSION NARRATIVE CONTEXT", "SessionAgeMinutes");
        assertThat(v19).isEqualTo(PromptSlotPlan.unscoped("SESSION NARRATIVE CONTEXT", "SessionAgeMinutes"));
        assertThat(v19.dictionaryEntry()).isNull();
        assertThat(provider.planFor("DECISION FACTS", "NotAnEntry").dictionaryEntry()).isNull();

        PromptSlot slot = policy.bind("no", "no - no approval for GB-500", null);
        assertThat(slot.dictionaryEntry()).isSameAs(policy.dictionaryEntry());
    }

    /**
     * W3-14: a runtime governance rule names its slot by the slot key, and a v20 rule's slot key is the dictionary
     * slot key ({@code DECISION FACTS.PolicySatisfied}). A v19 slot key (lower case, no dot) names no entry.
     */
    @Test
    void theProviderFindsTheEntryOfADictionarySlotKey() {
        PromptDictionarySlotPlanProvider provider = SecurityDecisionPromptDictionary.slotPlanProvider();

        List<PromptSlotPlan> policy = provider.plansForSlotKey("SECURITY_DECISION", "DECISION FACTS.PolicySatisfied");
        assertThat(policy).singleElement().satisfies(plan -> {
            assertThat(plan.dictionaryEntry()).isSameAs(entries.get("DECISION_FACTS.PolicySatisfied"));
            assertThat(plan.slotKey()).isEqualTo("DECISION FACTS.PolicySatisfied");
            assertThat(plan.sectionKey()).isEqualTo("DECISION FACTS");
            assertThat(plan.labelKey()).isEqualTo("PolicySatisfied");
        });
        assertThat(provider.plansForSlotKey(null, "PAST RECORDS.PastRecord{i}")).singleElement()
                .satisfies(plan -> assertThat(plan.labelKey()).isEqualTo("PastRecord{i}"));
        assertThat(provider.plansForSlotKey("SECURITY_DECISION",
                "user_currentrequest_label_requestpath_3f2a9c1d0b7e")).isEmpty();
        assertThat(provider.plansForSlotKey("SECURITY_DECISION", "REQUEST.NotAnEntry")).isEmpty();
        assertThat(provider.plansForSlotKey("SECURITY_DECISION", "DECISION_FACTS.PolicySatisfied")).isEmpty();
        assertThat(provider.plansForSlotKey("SECURITY_DECISION", null)).isEmpty();
    }

    /**
     * Carried from W3-1 (P3-CHANGE-2): every line a v20 render draws is an entry of its block, once, with line feeds. The
     * prompt inspector's dictionary contract check is the one reading of this contract (redesign R1).
     */
    @Test
    void everyLineOfTheV20PromptIsAnEntryOfItsBlock() {
        PromptInspector inspector = new PromptInspector(List.of(new DictionaryContractCheck()), InspectionGolden.JSON);
        int drawn = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = inspector.inspect(render.sealed()).checks().get(0);
            assertThat(check.findings()).as(render.caseKey() + " " + render.profile()).isEmpty();
            drawn += check.matched();
        }
        assertThat(drawn).isPositive();
    }

    private static void assertPlaces(String label, JsonNode places) {
        assertThat(places.size()).as(label + " has a place").isPositive();
        places.forEach(place -> {
            String value = place.asText();
            if (PLACE_KIND.matcher(value).matches()) {
                if (value.startsWith("BLOCK_") && value.contains(":")) {
                    assertThat(PromptBlock.valueOf(value.substring(value.indexOf(':') + 1))).as(label).isNotNull();
                }
                return;
            }
            assertThat(entries).as(label + " -> " + value).containsKey(value);
        });
    }

    /**
     * P3 extra 37: the Unknown form takes the words the renderer writes (PromptUnknownKind) and not not-applicable, which
     * dictionary 1.4 says is not written.
     */
    @Test
    void theUnknownFormTakesOnlyTheWordsTheRendererWrites() {
        Pattern form = Pattern.compile(entries.get("UNKNOWN.Unknown").formatPattern());
        assertThat(form.matcher("not-integrated: [U1] ClientSignals, [U2] PeerCohort; unavailable-now: [U3] PastRecord "
                + "(not retrieved, TIMEOUT)").matches()).isTrue();
        // N-UID-1: a name without its ID is not the form.
        assertThat(form.matcher("not-integrated: ClientSignals, PeerCohort; unavailable-now: PastRecord (not retrieved, "
                + "TIMEOUT)").matches()).isFalse();
        assertThat(form.matcher("not-integrated: [U1] ClientSignals, PeerCohort").matches()).isFalse();
        assertThat(form.matcher("not-applicable: Delegation").matches()).isFalse();
    }

    private static String key(PromptDictionaryEntry entry) {
        return entry.block().name() + "." + entry.name();
    }

    private static JsonNode read(String resource) throws IOException {
        try (InputStream input = PromptDictionaryContractTest.class.getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            return JSON.readTree(input);
        }
    }
}
