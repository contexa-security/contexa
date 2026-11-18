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
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptDrawing;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K131 (plan 3.5: a block an organization added can be changed or deleted by a later version): a block added in one
 * version, changed in the next and changed again or deleted in the one after is drawn with its latest title and text at
 * the place it was added, in the first prompt and the second pass alike, and counted as the organization's in the
 * length and the size; once deleted it is drawn and counted no more. A prompt other than the security decision counts
 * its added user block alike.
 */
class OrganizationBlockChangesTest {

    private static final PromptBudgetProfile L1 = PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT;
    private static final PromptBudgetProfile L2 = PromptBudgetProfile.CORTEX_L2_EXPERT_STRICT;
    private static final String SOURCE = " (reference written by your organization) ===\n";
    private static final SecurityDecisionGoldenRender GOLDEN = SecurityDecisionGoldenRender.load();
    private static final AssembledPrompt PRODUCT = SecurityDecisionPromptDocument.product();

    @Test
    void aChangedBlockIsDrawnAndCountedWithItsLatestWordsAndADeletedOneNoMore() {
        AssembledPrompt added = version(PRODUCT, "v1.0", """
                user:
                  - key: org-closing
                    add-after: REQUEST
                    title: Finance closing
                    text: The ledger is exported on the last day.
                """);
        AssembledPrompt changed = version(added, "v2.0", """
                user:
                  - key: org-closing
                    text: The ledger is exported on the last two days.
                """);
        AssembledPrompt retitled = version(changed, "v3.0", """
                user:
                  - key: org-closing
                    title: Month end
                    text: The ledger is exported on the last three days.
                """);
        AssembledPrompt deleted = version(retitled, "v4.0", """
                user:
                  - key: org-closing
                    delete: true
                """);
        String product = GOLDEN.render(goldenCase("A3"), L1).userText();

        List<AssembledPrompt> chain = List.of(added, changed, retitled);
        List<String> blocks = List.of(block("Finance closing", "The ledger is exported on the last day."),
                block("Finance closing", "The ledger is exported on the last two days."),
                block("Month end", "The ledger is exported on the last three days."));
        for (int step = 0; step < chain.size(); step++) {
            AssembledPrompt version = chain.get(step);
            String block = blocks.get(step);
            assertThat(version.userBlock("org-closing").orElseThrow().action()).as("step " + step)
                    .isEqualTo(PromptVersionDocument.Action.ADD);
            assertThat(SecurityDecisionPromptDocument.organizationBlocks(version)).as("step " + step)
                    .isEqualTo(Map.of(PromptBlock.REQUEST, List.of(block)));
            assertThat(SecurityDecisionPromptDocument.organizationBlockTokens(version)).as("step " + step)
                    .isEqualTo(PromptAssembler.tokensOf(1 + block.length()));
            assertThat(render("A3", L1, version, Map.of()).userText()).as("step " + step)
                    .isEqualTo(SecurityDecisionOrganizationBlocksTest.insertedAfter(product, "REQUEST", block));
        }
        // The size against the base counts the change, as the check before the save counted it.
        PromptAssembler.Check change = new PromptAssembler().check(added, document("v2.0", """
                user:
                  - key: org-closing
                    text: The ledger is exported on the last two days.
                """), null, SecurityDecisionPromptDocument::organizationBlockTokens);
        assertThat(change.baseAddedUserTokens())
                .isEqualTo(SecurityDecisionPromptDocument.organizationBlockTokens(added));
        assertThat(change.addedUserTokens())
                .isEqualTo(SecurityDecisionPromptDocument.organizationBlockTokens(changed));

        assertThat(deleted.userBlock("org-closing")).isEmpty();
        assertThat(SecurityDecisionPromptDocument.organizationBlocks(deleted)).isEmpty();
        assertThat(SecurityDecisionPromptDocument.organizationBlockTokens(deleted)).isZero();
        assertThat(render("A3", L1, deleted, Map.of()).userText()).isEqualTo(product);
        // The content hash names what is drawn: the changed words make another version.
        assertThat(changed.contentHash()).isNotEqualTo(added.contentHash());
    }

    @Test
    void aChangedBlockAfterTheSecondPassFollowsItInTheSecondPass() {
        AssembledPrompt added = version(PRODUCT, "v1.0", """
                user:
                  - key: org-escalation
                    add-after: SECOND_PASS
                    title: Escalation desk
                    text: The security desk answers escalations within an hour.
                """);
        AssembledPrompt changed = version(added, "v2.0", """
                user:
                  - key: org-escalation
                    text: The security desk answers escalations within ten minutes.
                """);
        String escalation = block("Escalation desk", "The security desk answers escalations within ten minutes.");

        SecurityDecisionGoldenRender.RenderedCase first = render("A3", L2, changed, Map.of());
        SecurityDecisionGoldenRender.RenderedCase second = render("A3", L2, changed, secondPass(first.userText()));
        String productFirst = GOLDEN.render(goldenCase("A3"), L2).userText();
        String productSecond = render("A3", L2, PRODUCT, secondPass(productFirst)).userText();

        assertThat(first.userText()).isEqualTo(productFirst);
        String secondPassBlock = productSecond.substring(productFirst.stripTrailing().length());
        assertThat(second.userText()).isEqualTo(first.userText().stripTrailing() + secondPassBlock + "\n" + escalation);
    }

    /** Plan 3.11: a prompt other than the security decision draws and counts its changed user block alike. */
    @Test
    void anotherPromptDrawsAndCountsItsChangedUserBlock() {
        AssembledPrompt product = QueryTransformPrompt.BEHAVIOR.product();
        String place = product.user().get(product.user().size() - 1).key();
        AssembledPrompt added = new PromptAssembler().apply(product, new PromptVersionDocumentReader().read(
                "prompt: " + product.prompt() + "\nbasedOn: v1.0\ntitle: Ours\nuser:\n  - key: org-terms\n"
                        + "    add-after: " + place + "\n    title: Our terms\n    text: A book is a ledger.\n"));
        AssembledPrompt changed = new PromptAssembler().apply(added, new PromptVersionDocumentReader().read(
                "prompt: " + product.prompt() + "\nbasedOn: v2.0\ntitle: Ours\nuser:\n  - key: org-terms\n"
                        + "    text: A book is a ledger of accounts.\n"));
        AssembledPrompt deleted = new PromptAssembler().apply(changed, new PromptVersionDocumentReader().read(
                "prompt: " + product.prompt() + "\nbasedOn: v3.0\ntitle: Ours\nuser:\n  - key: org-terms\n"
                        + "    delete: true\n"));

        assertThat(PromptDrawing.user(changed, Set.of(), Map.of()))
                .contains("Our terms:\nA book is a ledger of accounts.\n");
        assertThat(PromptAssembler.addedUserTokens(changed)).isEqualTo(PromptAssembler.tokensOf(1
                + "Our terms:\n".length() + "A book is a ledger of accounts.\n".length()));
        assertThat(PromptAssembler.addedUserTokens(added)).isEqualTo(PromptAssembler.tokensOf(1
                + "Our terms:\n".length() + "A book is a ledger.\n".length()));
        assertThat(PromptDrawing.user(deleted, Set.of(), Map.of())).doesNotContain("Our terms");
        assertThat(PromptAssembler.addedUserTokens(deleted)).isZero();
    }

    private static String block(String title, String text) {
        return "=== " + title + SOURCE + text + "\n";
    }

    private static PromptVersionDocument document(String basedOn, String changes) {
        return new PromptVersionDocumentReader().read("prompt: cortex.security-decision\nbasedOn: " + basedOn
                + "\ntitle: Finance\n" + changes);
    }

    private static AssembledPrompt version(AssembledPrompt base, String basedOn, String changes) {
        return new PromptAssembler().apply(base, document(basedOn, changes));
    }

    private static Map<String, String> secondPass(String firstUserPrompt) {
        return Map.of("layer2FirstPassUserPrompt", firstUserPrompt, "layer2FirstPassVerdict", "ESCALATE",
                "layer2FirstPassPastRecordsState", "AVAILABLE");
    }

    private static SecurityDecisionGoldenRender.RenderedCase render(String caseKey, PromptBudgetProfile profile,
                                                                    AssembledPrompt version,
                                                                    Map<String, String> parameters) {
        PromptVersionStore store = (prompt, name) -> "v9.0".equals(name) ? Optional.of(version) : Optional.empty();
        return GOLDEN.renderVersion(goldenCase(caseKey), profile, new TieredStrategyProperties(), store, "v9.0",
                parameters);
    }

    private static JsonNode goldenCase(String caseKey) {
        return GOLDEN.cases().stream().filter(item -> item.path("caseKey").asText().equals(caseKey)).findFirst()
                .orElseThrow();
    }
}
