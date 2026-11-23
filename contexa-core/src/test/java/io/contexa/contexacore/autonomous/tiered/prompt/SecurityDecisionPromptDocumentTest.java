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

import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 6-1: the product prompt document holds the sentences of the v1.0 prompt and the engine fails to start when the
 * document is not the engine's (its reason codes, its user lines, its block titles); K32 (decision D10): with the
 * floors enforced the v1.0 system text states them and the response sentence says a later check raises a weaker
 * response; K16 (decision D9): no request line's use names a code that may not cite it.
 */
class SecurityDecisionPromptDocumentTest {

    private static final String RESPONSE_SENTENCE = "No later system changes an ALLOW, a CHALLENGE or a BLOCK; do not"
            + " pre-compensate for one.";

    /**
     * K66, N1 and K187: the build ships the three product releases, the latest last as the product version. 2026.11.18
     * differs from 2026.11.16 in the part organization-blocks, drawn under the condition of the precedence sentence,
     * and in the reason code VERIFIED_SIGNAL with the use of the VerifiedSignal line that names it; v1.1.0 is 2026.11.18
     * without the precedence sentence and organization-blocks, which no version draws; nothing else. Without the version tables the product version is found by its
     * release and by the name of the bundle it runs on (the earliest release's name), and an earlier release by
     * neither; the start registers each release in the version tables, which find it by its release
     * (PromptVersionServicePostgresTest). The engine still answers to the earliest release's reason codes, and to no
     * other list.
     */
    @Test
    void theBuildShipsEveryProductReleaseAndFindsEachByItsName() {
        assertThat(SecurityDecisionPromptDocument.productReleases())
                .extracting(release -> release.release())
                .containsExactly("2026.11.16-v1.0", "2026.11.18-v1.0", "v1.1.0");
        AssembledPrompt product = SecurityDecisionPromptDocument.product();
        assertThat(product.release()).isEqualTo("v1.1.0");
        AssembledPrompt earlier = shipped(0);
        AssembledPrompt previous = shipped(1);
        assertThat(earlier.release()).isEqualTo("2026.11.16-v1.0");
        assertThat(previous.release()).isEqualTo("2026.11.18-v1.0");
        assertThat(SecurityDecisionPromptDocument.productStore()
                .find(SecurityDecisionPromptDocument.PROMPT, "v1.1.0")).containsSame(product);
        assertThat(SecurityDecisionPromptDocument.productStore().find(SecurityDecisionPromptDocument.PROMPT,
                SecurityDecisionPromptBundles.DEFAULT.version())).containsSame(product);
        assertThat(SecurityDecisionPromptDocument.productStore()
                .find(SecurityDecisionPromptDocument.PROMPT, "2026.11.18-v1.0")).isEmpty();
        assertThat(SecurityDecisionPromptDocument.productStore()
                .find(SecurityDecisionPromptDocument.PROMPT, "v2.0")).isEmpty();
        assertThat(SecurityDecisionPromptDocument.productStore().find("PolicyGeneration", "v1.1.0")).isEmpty();

        // 2026.11.18 against 2026.11.16 (K66, N1).
        List<PromptVersionDocument.Part> added = previous.system().stream()
                .filter(part -> earlier.systemPart(part.key()).isEmpty()).toList();
        assertThat(added).extracting(PromptVersionDocument.Part::key).containsExactly("organization-blocks");
        List<String> changed = new ArrayList<>();
        previous.system().stream().filter(part -> !added.contains(part))
                .filter(part -> !part.equals(earlier.systemPart(part.key()).orElseThrow()))
                .forEach(part -> changed.add(part.key()));
        assertThat(changed).containsExactly(SecurityDecisionPromptDocument.REASON_CODES_PART);
        List<String> earlierCodes = new ArrayList<>(SecurityDecisionPromptDocument.reasonCodes(earlier));
        earlierCodes.add(earlierCodes.indexOf("THREAT_MATCH") + 1, "VERIFIED_SIGNAL");
        assertThat(SecurityDecisionPromptDocument.reasonCodes(previous)).isEqualTo(earlierCodes)
                .isEqualTo(SecurityDecisionOutputContractV4.codes());
        List<String> changedLines = new ArrayList<>();
        for (PromptVersionDocument.Part block : previous.user()) {
            PromptVersionDocument.Part before = earlier.userBlock(block.key()).orElseThrow();
            assertThat(block.items()).as(block.key()).hasSameSizeAs(before.items());
            for (int index = 0; index < block.items().size(); index++) {
                PromptVersionDocument.Item item = block.items().get(index);
                PromptVersionDocument.Item was = before.items().get(index);
                assertThat(item.key()).isEqualTo(was.key());
                assertThat(item.text()).as(item.key()).isEqualTo(was.text());
                if (!item.equals(was)) {
                    changedLines.add(block.key() + "." + item.key() + " " + item.use());
                }
            }
        }
        assertThat(changedLines).containsExactly(
                "DECISION_FACTS.VerifiedSignal VERIFIED_SIGNAL; under the verified signal boundary a BLOCK");
        assertThat(earlier.corrections()).isEqualTo(previous.corrections());
        PromptVersionDocument.Part part = added.get(0);
        assertThat(part.isLocked()).isTrue();
        assertThat(part.when()).isEqualTo(AssembledPrompt.ORGANIZATION_PARTS);
        assertThat(previous.system()).extracting(PromptVersionDocument.Part::key)
                .containsSubsequence("evidence-reading", "organization-blocks", "more-reading");
        assertThat(previous.drawnParts(AssembledPrompt.JUDGMENT, Set.of())).extracting(PromptVersionDocument.Part::key)
                .doesNotContain("precedence", "organization-blocks");
        assertThat(earlier.contentHash()).isNotEqualTo(previous.contentHash());

        // v1.1.0 against 2026.11.18 (K187): the same parts in the same order without the two parts about the text of
        // an organization, which no version draws, so a version on it draws only what its base draws.
        List<String> taken = previous.system().stream().map(PromptVersionDocument.Part::key)
                .filter(key -> product.systemPart(key).isEmpty()).toList();
        assertThat(taken).containsExactly("precedence", "organization-blocks");
        assertThat(product.system()).isEqualTo(previous.system().stream()
                .filter(kept -> !taken.contains(kept.key())).toList());
        for (String key : taken) {
            assertThat(previous.systemPart(key).orElseThrow().when()).as(key)
                    .isEqualTo(AssembledPrompt.ORGANIZATION_PARTS);
        }
        assertThat(product.system()).extracting(PromptVersionDocument.Part::when)
                .doesNotContain(AssembledPrompt.ORGANIZATION_PARTS);
        assertThat(product.user()).isEqualTo(previous.user());
        assertThat(product.corrections()).isEqualTo(previous.corrections());
        assertThat(SecurityDecisionPromptDocument.reasonCodes(product))
                .isEqualTo(SecurityDecisionPromptDocument.reasonCodes(previous));
        assertThat(product.drawnParts(AssembledPrompt.JUDGMENT, Set.of()))
                .isEqualTo(previous.drawnParts(AssembledPrompt.JUDGMENT, Set.of()));
        assertThat(product.drawnParts(AssembledPrompt.JUDGMENT, Set.of(AssembledPrompt.ORGANIZATION_PARTS)))
                .extracting(PromptVersionDocument.Part::key).doesNotContain("precedence", "organization-blocks");
        assertThat(previous.contentHash()).isNotEqualTo(product.contentHash());

        assertThat(SecurityDecisionPromptDocument.keepsInjectionGuard(earlier)).isTrue();
        assertThat(SecurityDecisionPromptDocument.keepsInjectionGuard(previous)).isTrue();
        assertThat(SecurityDecisionPromptDocument.keepsInjectionGuard(product)).isTrue();
        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(earlier)).isTrue();
        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(previous)).isTrue();
        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(product)).isTrue();
        AssembledPrompt fewer = withSystemPart(SecurityDecisionPromptDocument.REASON_CODES_PART, reasonCodes -> {
            List<PromptVersionDocument.Item> items = new ArrayList<>(reasonCodes.items());
            items.remove(0);
            return items;
        });
        assertThat(SecurityDecisionPromptDocument.reasonCodesOfEngine(fewer)).isFalse();
    }

    /** The product release of the build at the place of the list, as the assembler makes its product version. */
    private static AssembledPrompt shipped(int index) {
        return new PromptAssembler().product(SecurityDecisionPromptDocument.productDocument(
                SecurityDecisionPromptDocument.RELEASES.get(index)));
    }

    @Test
    void theDocumentNamesTheEngineReasonCodesInItsOrderWithAMeaningEach() {
        AssembledPrompt product = SecurityDecisionPromptDocument.product();

        assertThat(SecurityDecisionPromptDocument.reasonMeanings(product).keySet())
                .containsExactlyElementsOf(SecurityDecisionOutputContractV4.codes());
        assertThat(SecurityDecisionOutputContractV4.REASON_CODES)
                .allSatisfy(code -> assertThat(code.meaning()).isNotBlank());
        assertThat(SecurityDecisionOutputContractV4.find("RECORD_COVERS_WORK").orElseThrow().meaning())
                .isEqualTo(SecurityDecisionPromptDocument.reasonMeanings(product).get("RECORD_COVERS_WORK"));
    }

    @Test
    void theStartFailsWhenTheDocumentNamesOtherReasonCodes() {
        AssembledPrompt fewer = withSystemPart(SecurityDecisionPromptDocument.REASON_CODES_PART, part -> {
            List<PromptVersionDocument.Item> items = new ArrayList<>(part.items());
            items.remove(items.size() - 1);
            return items;
        });
        AssembledPrompt more = withSystemPart(SecurityDecisionPromptDocument.REASON_CODES_PART, part -> {
            List<PromptVersionDocument.Item> items = new ArrayList<>(part.items());
            items.add(new PromptVersionDocument.Item("NEW_CODE", "a new code", null));
            return items;
        });
        AssembledPrompt reordered = withSystemPart(SecurityDecisionPromptDocument.REASON_CODES_PART, part -> {
            List<PromptVersionDocument.Item> items = new ArrayList<>(part.items());
            items.add(items.remove(0));
            return items;
        });
        List<String> engine = SecurityDecisionOutputContractV4.codes();

        assertThatThrownBy(() -> SecurityDecisionPromptDocument.verifyReasonCodes(fewer, engine))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("missing [MATERIAL_MISSING_EVIDENCE]");
        assertThatThrownBy(() -> SecurityDecisionPromptDocument.verifyReasonCodes(more, engine))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("not known [NEW_CODE]");
        assertThatThrownBy(() -> SecurityDecisionPromptDocument.verifyReasonCodes(reordered, engine))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("in another order");
    }

    @Test
    void theStartFailsWhenTheDocumentHasOtherUserLinesOrABlockTitleTheInspectorDoesNotRead() {
        AssembledPrompt product = SecurityDecisionPromptDocument.product();
        List<PromptDictionaryEntry> engine = SecurityDecisionPromptDictionary.V1_ENTRIES;
        AssembledPrompt lineless = withUserBlock("REQUEST", block -> new PromptVersionDocument.Part(block.key(),
                block.title(), block.locked(), block.join(), block.heading(), block.group(), block.when(),
                block.prepared(), block.text(), block.whenText(), block.items().subList(1, block.items().size()),
                block.effects(), block.action(), block.addAfter()));
        AssembledPrompt retitled = withUserBlock("DECISION_FACTS", block -> new PromptVersionDocument.Part(block.key(),
                "FACTS", block.locked(), block.join(), block.heading(), block.group(), block.when(), block.prepared(),
                block.text(), block.whenText(), block.items(), block.effects(), block.action(), block.addAfter()));

        assertThat(SecurityDecisionPromptDocument.withDocumentLines(product, engine)).isEqualTo(engine);
        assertThatThrownBy(() -> SecurityDecisionPromptDocument.withDocumentLines(lineless, engine))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("missing [REQUEST.Subject]");
        assertThatThrownBy(() -> SecurityDecisionPromptDocument.blockTitles(retitled))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("is titled FACTS");
        assertThat(SecurityDecisionPromptDocument.blockTitles(product))
                .containsEntry(PromptBlock.DECISION_FACTS, "RECORDS AND COMPARISONS")
                .containsEntry(PromptBlock.USER_BASELINE, "USER BASELINE");
    }

    @Test
    void k16NoRequestOrSessionLineSaysItIsCitedByACodeThatCitesTheComparisonLine() {
        List<String> comparisonCodes = SecurityDecisionOutputContractV4.REASON_CODES.stream()
                .filter(code -> code.citedFacts().equals(List.of("DECISION_FACTS.DeviationsFromBaseline")))
                .map(SecurityDecisionOutputContractV4.ReasonCode::code).toList();
        assertThat(comparisonCodes).contains("DEVIATION_NETWORK", "DEVIATION_DEVICE", "DEVIATION_TIME");

        for (PromptDictionaryEntry entry : SecurityDecisionPromptDictionary.V1_ENTRIES) {
            if (entry.block() != PromptBlock.REQUEST && entry.block() != PromptBlock.SESSION) {
                continue;
            }
            for (String code : comparisonCodes) {
                String use = entry.decisionUse() != null ? entry.decisionUse() : "";
                if (use.contains(code)) {
                    assertThat(use).as(entry.block() + "." + entry.name())
                            .containsPattern(code + "( and DEVIATION_[A-Z_]+)? cites? DeviationsFromBaseline, not this line");
                }
            }
        }
        assertThat(entryUse(PromptBlock.REQUEST, "Network")).contains("DEVIATION_NETWORK cites DeviationsFromBaseline");
        assertThat(entryUse(PromptBlock.REQUEST, "Device")).contains("DEVIATION_DEVICE cites DeviationsFromBaseline");
    }

    @Test
    void k32WithTheFloorsEnforcedTheV1TextStatesThemAndThatALaterCheckRaisesAWeakerResponse() {
        String observe = sections(MinimumActionRules.Settings.DEFAULTS, "OBSERVE")
                .buildSystemInstructionV1(null);
        String enforce = sections(MinimumActionRules.Settings.DEFAULTS, "ENFORCE")
                .buildSystemInstructionV1(null);

        assertThat(observe).contains(RESPONSE_SENTENCE).doesNotContain("Minimum action rules");
        assertThat(enforce).doesNotContain(RESPONSE_SENTENCE)
                .contains("No later system changes an ALLOW, a CHALLENGE or a BLOCK, except that a response weaker than"
                        + " the floor of a minimum action rule below that applies is raised to that floor;")
                .contains("\n\nMinimum action rules: the host sets the weakest response allowed for some facts. First"
                        + " judge the request as the parts above say; then check these rules.")
                .contains("when several apply, the strongest of their floors. A floor is the weakest response allowed,"
                        + " not the response to choose, and it does not change which explanation you judge most likely.")
                .contains("\nP1: ResourceClass is SENSITIVE or CRITICAL, BaselineStatus is ESTABLISHED, and"
                        + " DeviationsFromBaseline states a difference in at least 2 of time, day, network and device"
                        + " that no record explains (you cite at least 2 of DEVIATION_TIME, DEVIATION_DAY,"
                        + " DEVIATION_NETWORK and DEVIATION_DEVICE). Floor: CHALLENGE.\n")
                .contains("\nP2: the request exports data, ResourceClass is SENSITIVE or CRITICAL,")
                .contains("\nP3: the company policy (Policy) asks for a record for this work and no record stated for"
                        + " this request covers it (you cite NO_COVERING_RECORD, RECORD_OTHER_TARGET,")
                .contains("P3 applies together with P1 or P2. Floor: ESCALATE (a verified user does not supply the"
                        + " missing record).\n")
                .contains("\nA later check raises a response weaker than the floor of a rule that applies to that"
                        + " floor.\n\nHonesty:\n")
                .doesNotContain("MIN_P1", "PolicySatisfied", "DeviationsExplained");
        // Everything else is the text of the default settings.
        String floors = enforce.substring(enforce.indexOf("\nMinimum action rules"), enforce.indexOf("\nHonesty:\n"));
        assertThat(enforce.replace(floors, "").replace(", except that a response weaker than the floor of a minimum"
                + " action rule below that applies is raised to that floor;", ";")).isEqualTo(observe);
    }

    @Test
    void k32TheFloorsTheHostTurnedOnAreTheOnesStatedAndNoneStatesNothing() {
        String identityOnly = sections(new MinimumActionRules.Settings(true, 3, "CRITICAL", false, false, "CHALLENGE"),
                "ENFORCE").buildSystemInstructionV1(null);
        String policyOnly = sections(new MinimumActionRules.Settings(false, 2, "SENSITIVE", false, true, "CHALLENGE"),
                "ENFORCE").buildSystemInstructionV1(null);
        String none = sections(new MinimumActionRules.Settings(false, 2, "SENSITIVE", false, false, "ESCALATE"),
                "ENFORCE").buildSystemInstructionV1(null);

        assertThat(identityOnly).contains("P1: ResourceClass is CRITICAL, BaselineStatus is ESTABLISHED, and"
                        + " DeviationsFromBaseline states a difference in at least 3 of")
                .contains("A difference explained by a record").doesNotContain("P2: ", "P3: ");
        assertThat(policyOnly).contains("Floor: CHALLENGE.\n").doesNotContain("P1: ", "P2: ")
                .doesNotContain("A difference explained by a record");
        assertThat(none).doesNotContain("Minimum action rules").contains(RESPONSE_SENTENCE);
    }

    private static SecurityDecisionPromptSections sections(MinimumActionRules.Settings settings, String mode) {
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(new SecurityEventEnricher(),
                new TieredStrategyProperties(), event -> Optional.empty(), new PromptContextComposer());
        sections.setMinimumActionSettings(settings, mode);
        return sections;
    }

    private static String entryUse(PromptBlock block, String name) {
        return SecurityDecisionPromptDictionary.V1_ENTRIES.stream()
                .filter(entry -> entry.block() == block && entry.name().equals(name)).findFirst().orElseThrow()
                .decisionUse();
    }

    private interface ItemsChange {
        List<PromptVersionDocument.Item> items(PromptVersionDocument.Part part);
    }

    private interface BlockChange {
        PromptVersionDocument.Part block(PromptVersionDocument.Part block);
    }

    /** The product document with the items of one system part changed, as a build with another document would ship. */
    private static AssembledPrompt withSystemPart(String key, ItemsChange change) {
        PromptVersionDocument product = SecurityDecisionPromptDocument.productDocument(
                SecurityDecisionPromptDocument.RELEASES.get(SecurityDecisionPromptDocument.RELEASES.size() - 1));
        List<PromptVersionDocument.Part> system = product.system().stream().map(part -> !part.key().equals(key) ? part
                : new PromptVersionDocument.Part(part.key(), part.title(), part.locked(), part.join(), part.heading(),
                part.group(), part.when(), part.prepared(), part.text(), part.whenText(), change.items(part),
                part.effects(), part.action(), part.addAfter())).toList();
        return new PromptAssembler().product(new PromptVersionDocument(product.prompt(), product.kind(),
                product.release(), null, null, product.title(), product.description(), system, product.user(),
                product.corrections()));
    }

    private static AssembledPrompt withUserBlock(String key, BlockChange change) {
        PromptVersionDocument product = new PromptVersionDocumentReader().read(SecurityDecisionPromptDocument.resource(
                SecurityDecisionPromptDocument.RELEASES.get(SecurityDecisionPromptDocument.RELEASES.size() - 1)));
        List<PromptVersionDocument.Part> user = product.user().stream()
                .map(block -> block.key().equals(key) ? change.block(block) : block).toList();
        return new PromptAssembler().product(new PromptVersionDocument(product.prompt(), product.kind(),
                product.release(), null, null, product.title(), product.description(), product.system(), user,
                product.corrections()));
    }
}
