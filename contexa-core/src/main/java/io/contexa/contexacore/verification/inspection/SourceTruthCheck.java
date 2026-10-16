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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;

import java.util.List;

/**
 * W6-7 (P6-CHANGE-5, plan 2 C1): the facts the prompt states are the host's own records of them. The host's source
 * verifier reads its sources again for the sealed decision and gives, per fact, the piece the dictionary line must
 * hold; a line that holds it matches, a line that does not or no line at all is a mismatch, unless the UNKNOWN line
 * names the fact (its missing notation, N-SRC-1). Without a verifier the
 * check records that no host source is integrated; a source that cannot be read now inspects the package again later.
 */
public final class SourceTruthCheck implements PromptInspectionCheck {

    public static final String CODE = "SOURCE_TRUTH";
    private static final String NOT_INTEGRATED = "host source verifier";
    private static final String UNKNOWN = "Unknown";

    private final PromptFactSourceVerifier verifier;

    public SourceTruthCheck(PromptFactSourceVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return true;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        if (verifier == null) {
            tally.unverifiable(tally.unverifiableFinding().sourceRef(NOT_INTEGRATED)
                    .reason("no host source is integrated, so the facts are not compared with the host's records")
                    .build());
            return;
        }
        List<PromptFactSourceVerifier.SourceFact> facts = verifier.sourceFacts(tally.subject());
        for (PromptFactSourceVerifier.SourceFact fact : facts == null ? List.<PromptFactSourceVerifier.SourceFact>of() : facts) {
            List<InspectedPrompt.Line> lines = linesOf(tally.subject().prompt(), fact.block(), fact.entry());
            if (lines.isEmpty()) {
                // N-SRC-1: a fact the UNKNOWN line names has its missing notation, which the unknown check grades.
                InspectedPrompt.Line declared = declaredUnknown(tally.subject().prompt(), fact.entry());
                if (declared != null) {
                    tally.matched(declared);
                    continue;
                }
                tally.mismatch(tally.mismatchFinding().block(title(fact.block())).entry(fact.entry())
                        .expected(fact.fragment()).actual("no line").sourceRef(fact.sourceRef())
                        .reason("the host's source keeps the fact but the prompt states no line of it").build());
                continue;
            }
            InspectedPrompt.Line holding = lines.stream().filter(line -> holds(line, fact)).findFirst().orElse(null);
            if (holding != null) {
                tally.matched(holding);
                continue;
            }
            InspectedPrompt.Line line = lines.get(0);
            tally.mismatch(tally.mismatchFinding().block(title(fact.block())).entry(fact.entry())
                    .factId(line.factId()).lineNumber(line.number()).expected(fact.fragment())
                    .actual(line.entryLine().value()).sourceRef(fact.sourceRef())
                    .reason("the line does not hold what the host's source keeps").build());
        }
    }

    private static boolean holds(InspectedPrompt.Line line, PromptFactSourceVerifier.SourceFact fact) {
        String value = line.entryLine().value();
        return value.contains(fact.fragment()) && (fact.excluded() == null || !value.contains(fact.excluded()));
    }

    /** The UNKNOWN line that names the entry, or null when no UNKNOWN line names it. */
    private static InspectedPrompt.Line declaredUnknown(InspectedPrompt prompt, String entry) {
        return prompt.lines().stream()
                .filter(line -> line.kind() == InspectedPrompt.Kind.ENTRY && line.entryLine() != null)
                .filter(line -> UNKNOWN.equals(line.entryLine().label()))
                .filter(line -> UnknownDeclaredCheck.declaredNames(line.entryLine().value()).contains(entry))
                .findFirst().orElse(null);
    }

    private static List<InspectedPrompt.Line> linesOf(InspectedPrompt prompt, PromptBlock block, String entry) {
        return prompt.lines().stream()
                .filter(line -> line.kind() == InspectedPrompt.Kind.ENTRY && line.entryLine() != null)
                .filter(line -> line.block() == block && line.entryLine().label().equals(entry))
                .toList();
    }

    private static String title(PromptBlock block) {
        return block != null ? block.title() : null;
    }
}
