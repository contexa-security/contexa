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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;

import java.time.ZoneId;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Whether the decision fact lines of the resolver's facts say what the sealed decision facts say: for every sealed
 * fact with a value that the dictionary draws, the DECISION FACTS block has its line, its value letter for letter and
 * the fact id sealed with it (W3-13). A fact the render took out to fit its budget is recorded as such and counts as
 * matching. The sealed facts in turn are what the resolver computes from the sealed context, but for the two that
 * read the learning evidence the package does not seal. Lines the block draws from other sources than the resolver are
 * the fact accuracy check's.
 */
public final class DecisionFactMatchCheck implements PromptInspectionCheck {

    public static final String CODE = "DECISION_FACT_MATCH";

    private static final String SOURCE = "canonicalContext.decisionFacts";
    private static final String RECOMPUTED = "canonicalContext";
    private static final String LEARNING_EVIDENCE = "learningContextEvidence";
    private static final String NO_FACT = "no fact";
    private static final PromptBlock BLOCK = PromptBlock.DECISION_FACTS;
    private static final Set<String> LEARNED_BASELINE_FACTS = Set.of(
            DecisionFactsResolver.DEVIATIONS_FROM_BASELINE, DecisionFactsResolver.SAME_AS_BASELINE);

    private final List<PromptDictionaryEntry> entries;

    public DecisionFactMatchCheck() {
        this.entries = SecurityDecisionPromptDictionary.ENTRIES;
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
        PromptInspectionSubject subject = tally.subject();
        CanonicalSecurityContext context = subject.canonicalContext();
        DecisionFacts facts = context != null ? context.getDecisionFacts() : null;
        if (facts == null) {
            tally.unverifiable(tally.unverifiableFinding().block(BLOCK.title()).sourceRef(SOURCE)
                    .reason(subject.canonicalContextSealed() && context == null
                            ? "the sealed canonical context does not read"
                            : "the decision facts are not sealed")
                    .build());
            return;
        }
        Map<String, InspectedPrompt.Line> lines = blockLines(subject.prompt());
        Set<String> omitted = Set.copyOf(subject.budgetOmittedEntries());
        for (DecisionFact fact : facts.facts()) {
            if (fact.name() == null || !drawn(fact.name()) || fact.value() == null || fact.value().isBlank()) {
                continue;
            }
            String expected = fact.value().trim();
            String source = SOURCE + "." + fact.name();
            InspectedPrompt.Line line = lines.get(fact.name());
            if (line == null) {
                if (omitted.contains(BLOCK.name() + "." + fact.name())) {
                    tally.matched();
                    continue;
                }
                tally.mismatch(tally.mismatchFinding().block(BLOCK.title()).entry(fact.name()).factId(fact.id())
                        .expected(expected).sourceRef(source)
                        .reason("the sealed decision fact is not in the prompt").build());
                continue;
            }
            String actual = line.entryLine().value();
            if (!expected.equals(actual)) {
                tally.mismatch(tally.mismatchFinding().block(BLOCK.title()).entry(fact.name()).factId(line.factId())
                        .lineNumber(line.number()).expected(expected).actual(actual).sourceRef(source)
                        .reason("the line says other than the sealed decision fact").build());
                continue;
            }
            if (!Objects.equals(fact.id(), line.factId())) {
                tally.mismatch(tally.mismatchFinding().block(BLOCK.title()).entry(fact.name()).factId(line.factId())
                        .lineNumber(line.number()).expected(fact.id()).actual(line.factId()).sourceRef(source + ".id")
                        .reason("the line carries another fact id than the sealed one").build());
                continue;
            }
            tally.matched(line);
        }
        recompute(tally, context, facts);
    }

    /**
     * The sealed facts are what the resolver gives from the sealed context: every fact whose inputs the context seals
     * has the same state when computed again (its value, codes, records and source; or unknown, and why). The facts
     * that compare the request with the learned baseline read the learning evidence, which the package does not seal.
     */
    private static void recompute(PromptInspectionTally tally, CanonicalSecurityContext context, DecisionFacts sealed) {
        ZoneId zone = tally.subject().eventZone();
        if (zone == null) {
            tally.unverifiable(tally.unverifiableFinding().block(BLOCK.title())
                    .sourceRef(PromptInspectionSubject.EVENT_TIME_ZONE_REF)
                    .reason("the decision facts cannot be computed again: the event time zone is not sealed").build());
            return;
        }
        Map<String, String> expected = states(DecisionFactsResolver.resolve(context, null, zone));
        Map<String, String> actual = states(sealed);
        Set<String> names = new LinkedHashSet<>(actual.keySet());
        names.addAll(expected.keySet());
        for (String name : names) {
            String factId = sealed.fact(name).map(DecisionFact::id).orElse(null);
            if (LEARNED_BASELINE_FACTS.contains(name)) {
                tally.unverifiable(tally.unverifiableFinding().block(BLOCK.title()).entry(name).factId(factId)
                        .sourceRef(LEARNING_EVIDENCE)
                        .reason("the fact compares the request with the learned baseline, which is not sealed").build());
                continue;
            }
            if (Objects.equals(expected.get(name), actual.get(name))) {
                tally.matched();
                continue;
            }
            tally.mismatch(tally.mismatchFinding().block(BLOCK.title()).entry(name).factId(factId)
                    .expected(expected.getOrDefault(name, NO_FACT)).actual(actual.getOrDefault(name, NO_FACT))
                    .sourceRef(RECOMPUTED)
                    .reason("the sealed decision fact is not what the sealed context gives with this inspector's "
                            + "resolver").build());
        }
    }

    /** Each fact's state by name: a known fact with what it says and rests on, or an unknown one and why. */
    private static Map<String, String> states(DecisionFacts facts) {
        Map<String, String> states = new LinkedHashMap<>();
        for (DecisionFact fact : facts.facts()) {
            if (fact.name() != null) {
                states.put(fact.name(), fact.value() + " (codes " + fact.codes() + ", records " + fact.recordIds()
                        + ", " + fact.source() + ")");
            }
        }
        for (String name : facts.unknown()) {
            String reason = facts.unavailable().get(name);
            states.putIfAbsent(name, reason != null ? "unavailable now (" + reason + ")" : "not integrated");
        }
        return states;
    }

    private boolean drawn(String name) {
        return entries.stream().anyMatch(entry -> entry.block() == BLOCK && entry.matchesLabel(name));
    }

    /** The first line of each label in the DECISION FACTS block. */
    private static Map<String, InspectedPrompt.Line> blockLines(InspectedPrompt prompt) {
        Map<String, InspectedPrompt.Line> lines = new HashMap<>();
        for (InspectedPrompt.Line line : prompt.lines()) {
            if (line.kind() == InspectedPrompt.Kind.ENTRY && line.block() == BLOCK) {
                lines.putIfAbsent(line.entryLine().label(), line);
            }
        }
        return lines;
    }
}
