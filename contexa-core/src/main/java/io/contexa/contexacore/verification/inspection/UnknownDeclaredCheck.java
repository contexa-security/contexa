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
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptMissingNotation;
import io.contexa.contexacore.autonomous.context.prompt.PromptUnknownKind;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Whether the prompt says what it does not know as the dictionary's missing rules say (dictionary 1.4):
 * <ul>
 *     <li>every decision fact the engine could not establish is named on the UNKNOWN line with its kind, and with its
 *     reason when its source could not give it now (sealed decision facts {@code unknown}, {@code unavailable});</li>
 *     <li>a fact the UNKNOWN line names is not drawn with a value anywhere else;</li>
 *     <li>an entry the dictionary always draws, names unknown or draws with its missing text has a line or an UNKNOWN
 *     name, unless the render took it out to fit its budget.</li>
 * </ul>
 */
public final class UnknownDeclaredCheck implements PromptInspectionCheck {

    public static final String CODE = "UNKNOWN_DECLARED";

    private static final String SOURCE = "canonicalContext.decisionFacts.unknown";
    private static final String UNKNOWN_ENTRY = "Unknown";
    private static final Pattern KIND = Pattern.compile("(" + PromptUnknownKind.wordsPattern() + "): ");
    /** A word in the place of a kind: at the line's start or after {@code "; "} (the reasons are short phrases). */
    private static final Pattern KIND_WORD = Pattern.compile("(?:^|; )([a-z]+(?:-[a-z]+)*): ");
    private static final Pattern NAME = Pattern.compile("([A-Za-z][A-Za-z0-9]*)(?: \\(([^()]*)\\))?");
    private static final Set<PromptMissingNotation> DRAWN_OR_NAMED = EnumSet.of(
            PromptMissingNotation.ALWAYS_PRESENT, PromptMissingNotation.UNKNOWN_BLOCK, PromptMissingNotation.RENDERED_VALUE);

    private final List<PromptDictionaryEntry> entries;

    public UnknownDeclaredCheck() {
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

    /** A name of the UNKNOWN line with its kind word and its reason. */
    private record Declared(String kind, String reason) {
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        PromptInspectionSubject subject = tally.subject();
        InspectedPrompt prompt = subject.prompt();
        Map<String, Declared> declared = new LinkedHashMap<>();
        InspectedPrompt.Line unknownLine = null;
        Map<String, InspectedPrompt.Line> drawn = new LinkedHashMap<>();
        for (InspectedPrompt.Line line : prompt.lines()) {
            if (line.kind() != InspectedPrompt.Kind.ENTRY || line.block() == null) {
                continue;
            }
            if (line.block() == PromptBlock.UNKNOWN && UNKNOWN_ENTRY.equals(line.entryLine().label())) {
                unknownLine = line;
                Matcher word = KIND_WORD.matcher(line.entryLine().value());
                while (word.find()) {
                    if (!PromptUnknownKind.isWord(word.group(1))) {
                        tally.mismatch(tally.mismatchFinding().block(PromptBlock.UNKNOWN.title()).entry(UNKNOWN_ENTRY)
                                .lineNumber(line.number()).expected(PromptUnknownKind.wordsPattern())
                                .actual(word.group(1))
                                .reason("the UNKNOWN line names a kind the render does not write (dictionary 1.4)")
                                .build());
                    }
                }
                declared.putAll(parse(line.entryLine().value()));
                continue;
            }
            drawn.putIfAbsent(line.block().name() + "." + line.entryLine().label(), line);
        }
        Set<String> omitted = Set.copyOf(subject.budgetOmittedEntries());
        Set<String> sealedUnknown = sealedUnknowns(tally, declared, unknownLine);
        drawnButNamedUnknown(tally, declared, drawn);
        drawnOrNamed(tally, declared, drawn, omitted, sealedUnknown);
    }

    /** Rule 1: the sealed unknown decision facts are named with their kind; returns their names (empty when unsealed). */
    private Set<String> sealedUnknowns(PromptInspectionTally tally, Map<String, Declared> declared,
                                       InspectedPrompt.Line unknownLine) {
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        DecisionFacts facts = context != null ? context.getDecisionFacts() : null;
        if (facts == null) {
            tally.unverifiable(tally.unverifiableFinding().block(PromptBlock.UNKNOWN.title()).entry(UNKNOWN_ENTRY)
                    .sourceRef(SOURCE).reason("the decision facts are not sealed, so their unknown names cannot be compared")
                    .build());
            return Set.of();
        }
        Set<String> names = new HashSet<>();
        for (String name : facts.unknown()) {
            if (name == null || !isEntry(PromptBlock.DECISION_FACTS, name)) {
                continue;
            }
            names.add(name);
            String sealedReason = facts.unavailable().get(name);
            String expectedKind = PromptUnknownKind.ofReason(sealedReason).word();
            String reason = PromptUnknownKind.reasonText(sealedReason);
            Declared found = declared.get(name);
            Integer lineNumber = unknownLine != null ? unknownLine.number() : null;
            if (found == null) {
                tally.mismatch(tally.mismatchFinding().block(PromptBlock.UNKNOWN.title()).entry(name).lineNumber(lineNumber)
                        .expected(expectedKind + (reason != null ? " (" + reason + ")" : "")).sourceRef(SOURCE)
                        .reason("the sealed unknown decision fact is not named on the UNKNOWN line").build());
                continue;
            }
            if (!expectedKind.equals(found.kind()) || !Objects.equals(reason, found.reason())) {
                tally.mismatch(tally.mismatchFinding().block(PromptBlock.UNKNOWN.title()).entry(name).lineNumber(lineNumber)
                        .expected(expectedKind + (reason != null ? " (" + reason + ")" : ""))
                        .actual(found.kind() + (found.reason() != null ? " (" + found.reason() + ")" : ""))
                        .sourceRef(SOURCE).reason("the UNKNOWN line names the fact with another kind or reason").build());
                continue;
            }
            tally.matched(unknownLine);
        }
        return names;
    }

    /** Rule 2: a name of the UNKNOWN line is not drawn with a value in another block. */
    private void drawnButNamedUnknown(PromptInspectionTally tally, Map<String, Declared> declared,
                                      Map<String, InspectedPrompt.Line> drawn) {
        for (String name : declared.keySet()) {
            InspectedPrompt.Line line = drawn.values().stream()
                    .filter(candidate -> sameFact(candidate, name))
                    .findFirst().orElse(null);
            if (line == null) {
                tally.matched();
                continue;
            }
            tally.mismatch(tally.mismatchFinding().block(line.block().title()).entry(line.entryLine().label())
                    .factId(line.factId()).lineNumber(line.number()).actual(line.entryLine().value())
                    .reason("the prompt names the fact unknown and draws it with a value").build());
        }
    }

    /** Rule 3: an entry the dictionary always draws or names unknown has a line or an UNKNOWN name. */
    private void drawnOrNamed(PromptInspectionTally tally, Map<String, Declared> declared,
                              Map<String, InspectedPrompt.Line> drawn, Set<String> omitted, Set<String> sealedUnknown) {
        for (PromptDictionaryEntry entry : entries) {
            if (entry.indexed() || entry.block() == PromptBlock.UNKNOWN || !DRAWN_OR_NAMED.contains(entry.missing())) {
                continue;
            }
            String key = entry.block().name() + "." + entry.name();
            if (drawn.containsKey(key) || declared.containsKey(entry.name()) || omitted.contains(key)
                    || sealedUnknown.contains(entry.name())) {
                tally.matched();
                continue;
            }
            tally.mismatch(tally.mismatchFinding().block(entry.block().title()).entry(entry.name())
                    .expected(entry.missing() == PromptMissingNotation.RENDERED_VALUE
                            ? "a line, its missing text '" + entry.missingText() + "' or an UNKNOWN name"
                            : "a line or an UNKNOWN name")
                    .reason("the entry has neither a line nor an UNKNOWN name").build());
        }
    }

    private boolean isEntry(PromptBlock block, String name) {
        return entries.stream().anyMatch(entry -> entry.block() == block && entry.matchesLabel(name));
    }

    /** Whether a drawn line carries the fact an UNKNOWN name names (a numbered entry is named by its stem). */
    private boolean sameFact(InspectedPrompt.Line line, String name) {
        String label = line.entryLine().label();
        if (label.equals(name)) {
            return true;
        }
        return entries.stream().anyMatch(entry -> entry.block() == line.block() && entry.indexed()
                && entry.stem().equals(name) && entry.matchesLabel(label));
    }

    /** The names of an UNKNOWN line value with their kind and reason ({@code kind: A, B (reason); kind: C}). */
    static Map<String, Declared> parse(String value) {
        Map<String, Declared> names = new LinkedHashMap<>();
        if (value == null) {
            return names;
        }
        Matcher kind = KIND.matcher(value);
        int start = -1;
        String current = null;
        while (kind.find()) {
            if (current != null) {
                names(names, current, value.substring(start, kind.start()));
            }
            current = kind.group(1);
            start = kind.end();
        }
        if (current != null) {
            names(names, current, value.substring(start));
        }
        return names;
    }

    private static void names(Map<String, Declared> names, String kind, String part) {
        Matcher name = NAME.matcher(part);
        int position = 0;
        while (position < part.length() && name.find(position)) {
            names.putIfAbsent(name.group(1), new Declared(kind, name.group(2)));
            position = name.end();
            while (position < part.length() && (part.charAt(position) == ',' || part.charAt(position) == ';'
                    || part.charAt(position) == ' ')) {
                position++;
            }
        }
    }
}
