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
import io.contexa.contexacore.autonomous.tiered.prompt.PastRecordLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.autonomous.tiered.prompt.UnknownLineValues;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

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
 *     <li>an entry is drawn as its missing notation says, unless the render took it out to fit its budget (N-INS-2):
 *     an entry the dictionary always draws or names unknown has a line or an UNKNOWN name; an entry with a missing text
 *     has a line (its value or that text), or an UNKNOWN name when the render named it for want of a source the sealed
 *     context lacks as well; and an entry left out with its line or its block is not named unknown unless the render's
 *     caller named it because the seal shows the fact could not be known now (a sealed unknown decision fact, past
 *     records the sealed search did not retrieve).</li>
 * </ul>
 */
public final class UnknownDeclaredCheck implements PromptInspectionCheck {

    public static final String CODE = "UNKNOWN_DECLARED";

    private static final String SOURCE = "canonicalContext.decisionFacts.unknown";
    private static final String UNKNOWN_ENTRY = "Unknown";
    /** A word in the place of a kind: at the line's start or after {@code "; "} (the reasons are short phrases). */
    private static final Pattern KIND_WORD = Pattern.compile("(?:^|; )([a-z]+(?:-[a-z]+)*): ");
    /** A name with its reason, after the ID the line gives it (N-UID-1; a prompt sealed before has none). */
    private static final Pattern NAME = Pattern.compile("(?:\\[" + PromptUnknownKind.FACT_PREFIX
            + "[0-9]+] )?([A-Za-z][A-Za-z0-9]*)(?: \\(([^()]*)\\))?");
    /** The past record lines, which the render's caller names unknown when the search did not retrieve them. */
    private static final String PAST_RECORD_LINES = PromptBlock.PAST_RECORDS.name() + ".PastRecord{i}";
    private static final String PAST_RECORDS_STATE = PromptBlock.PAST_RECORDS.name() + ".PastRecordsState";
    private static final String PAST_RECORD_STEM = "PastRecord";
    private static final String PAST_RECORD_COUNTS = "PastRecordCounts";
    private static final String PAST_RECORD_COUNTS_LINE = PromptBlock.PAST_RECORDS.name() + "." + PAST_RECORD_COUNTS;
    private static final String RETRIEVAL_STATE = "executionMetadata." + PromptExecutionMetadata.PROMPT_RAG_STATE;

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
        drawnAsNotated(tally, declared, drawn, unknownLine, omitted, sealedUnknown);
        pastRecordReasons(tally, declared, drawn, unknownLine);
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

    /**
     * Rule 3 (N-INS-2): an entry outside the UNKNOWN block is drawn as its missing notation says. An entry the
     * dictionary always draws or names unknown has a line or an UNKNOWN name. An entry with a missing text has a line,
     * its value or that text; an UNKNOWN name in its place is its notation only when the render named it for want of a
     * source, by the render's own rule read on the sealed context (a context that does not read cannot tell). An entry
     * left out with its line or its block is not named unknown unless the render's caller named it because the seal
     * shows the fact could not be known now (a sealed unknown decision fact, past records the sealed search did not
     * retrieve). A numbered entry is named by its stem. A drawn line the UNKNOWN line names is rule 2's, a sealed
     * unknown decision fact the line leaves out is rule 1's, and an entry the budget took out is not graded.
     */
    private void drawnAsNotated(PromptInspectionTally tally, Map<String, Declared> declared,
                                Map<String, InspectedPrompt.Line> drawn, InspectedPrompt.Line unknownLine,
                                Set<String> omitted, Set<String> sealedUnknown) {
        // The search state of the render: the one it sealed, or, in a package that seals none (a Layer2 second pass
        // keeps the first prompt as it was sent), the state line the prompt draws, which the past record check grades.
        InspectedPrompt.Line stateLine = drawn.get(PAST_RECORDS_STATE);
        boolean notRetrieved = tally.subject().executionMetadata().get(PromptExecutionMetadata.PROMPT_RAG_STATE)
                instanceof Map<?, ?> state ? PastRecordLineValues.notRetrieved(state)
                : stateLine != null && PastRecordLineValues.notRetrieved(stateLine.entryLine().value());
        // The entries the render names unknown for want of a source, by its own rule on the sealed context (R1b).
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        Set<String> withoutSource = context != null ? Set.copyOf(UnknownLineValues.withoutSource(context)) : Set.of();
        Set<String> mayLackSource = Set.copyOf(UnknownLineValues.withoutSource(null));
        Integer unknownNumber = unknownLine != null ? unknownLine.number() : null;
        for (PromptDictionaryEntry entry : entries) {
            if (entry.block() == PromptBlock.UNKNOWN) {
                continue;
            }
            String key = entry.block().name() + "." + entry.name();
            if (omitted.contains(key)) {
                tally.matched();
                continue;
            }
            boolean lined = entry.indexed()
                    ? drawn.values().stream().anyMatch(line -> line.block() == entry.block()
                            && entry.matchesLabel(line.entryLine().label()))
                    : drawn.containsKey(key);
            Declared named = declared.get(entry.stem());
            if (entry.missing() == PromptMissingNotation.RENDERED_VALUE && !lined && named != null && context == null
                    && mayLackSource.contains(key)) {
                tally.unverifiable(tally.unverifiableFinding().block(entry.block().title()).entry(entry.name())
                        .lineNumber(unknownNumber).sourceRef(PromptInspectionSubject.CANONICAL_CONTEXT)
                        .reason("the context the render used is not read, so whether it named the entry unknown for "
                                + "want of a source cannot be told").build());
                continue;
            }
            // The names the render's caller writes because the seal shows the fact could not be known now.
            boolean byCaller = sealedUnknown.contains(entry.stem()) || (notRetrieved && PAST_RECORD_LINES.equals(key));
            String problem = switch (entry.missing()) {
                case ALWAYS_PRESENT, UNKNOWN_BLOCK -> lined || named != null || byCaller ? null
                        : "the entry has neither a line nor an UNKNOWN name";
                case RENDERED_VALUE -> lined || (named != null && withoutSource.contains(key)) ? null
                        : named == null ? "the entry has no line, though its missing notation draws its missing text"
                        : "the UNKNOWN line names the entry, though its missing notation draws its missing text"
                                + (mayLackSource.contains(key) ? " and the sealed context gives its source" : "");
                case LINE_OMITTED -> named == null || lined || byCaller ? null
                        : "the UNKNOWN line names the entry, though its missing notation leaves the line out";
                case BLOCK_OMITTED -> named == null || lined || byCaller ? null
                        : "the UNKNOWN line names the entry, though its missing notation leaves it out with its block";
            };
            if (problem == null) {
                tally.matched();
                continue;
            }
            tally.mismatch(tally.mismatchFinding().block(entry.block().title()).entry(entry.name())
                    .lineNumber(named != null ? unknownNumber : null)
                    .expected(drawnAs(entry)).actual(named != null ? text(named) : null).reason(problem).build());
        }
    }

    /**
     * Rule 4 (N-INS-4): with the retrieval state the render kept sealed, the past records it names unknown now for a
     * search that did not finish or did not run carry the kind and the reason it writes from that state, and so does
     * a counted facts name in place of the counts line. A package that seals no state is read by rule 3 alone.
     */
    private static void pastRecordReasons(PromptInspectionTally tally, Map<String, Declared> declared,
                                          Map<String, InspectedPrompt.Line> drawn, InspectedPrompt.Line unknownLine) {
        if (!(tally.subject().executionMetadata().get(PromptExecutionMetadata.PROMPT_RAG_STATE) instanceof Map<?, ?> state)) {
            return;
        }
        String notRetrieved = PastRecordLineValues.notRetrievedReason(state);
        if (notRetrieved != null) {
            pastRecordReason(tally, declared.get(PAST_RECORD_STEM), PAST_RECORD_LINES, notRetrieved, unknownLine);
        }
        Declared counts = declared.get(PAST_RECORD_COUNTS);
        if (counts != null && !drawn.containsKey(PAST_RECORD_COUNTS_LINE)) {
            pastRecordReason(tally, counts, PAST_RECORD_COUNTS_LINE, PastRecordLineValues.countsUnknownReason(state),
                    unknownLine);
        }
    }

    private static void pastRecordReason(PromptInspectionTally tally, Declared found, String key, String reason,
                                         InspectedPrompt.Line unknownLine) {
        String expected = PromptUnknownKind.UNAVAILABLE_NOW.word() + " (" + reason + ")";
        if (found != null && expected.equals(text(found))) {
            tally.matched(unknownLine);
            return;
        }
        tally.mismatch(tally.mismatchFinding().block(PromptBlock.PAST_RECORDS.title())
                .entry(key.substring(key.indexOf('.') + 1)).lineNumber(unknownLine != null ? unknownLine.number() : null)
                .expected(expected).actual(found != null ? text(found) : null).sourceRef(RETRIEVAL_STATE)
                .reason(found == null ? "the UNKNOWN line does not name the past records the sealed search did not retrieve"
                        : "the UNKNOWN line names the past records with another kind or reason than the sealed search "
                                + "state").build());
    }

    /** What the entry's missing notation draws when the entry has no value (N-INS-2). */
    private static String drawnAs(PromptDictionaryEntry entry) {
        return switch (entry.missing()) {
            case RENDERED_VALUE -> "a line: a value or its missing text '" + entry.missingText() + "'";
            case LINE_OMITTED, BLOCK_OMITTED -> "no UNKNOWN name: a line, or no line without a value";
            default -> "a line or an UNKNOWN name";
        };
    }

    /** A name of the UNKNOWN line as its kind and reason read ({@code unavailable-now (not retrieved, TIMEOUT)}). */
    private static String text(Declared declared) {
        return declared.kind() + (declared.reason() != null ? " (" + declared.reason() + ")" : "");
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

    /** The fact names an UNKNOWN line's value declares, of every kind (N-SRC-1). */
    static Set<String> declaredNames(String value) {
        return parse(value).keySet();
    }

    /**
     * The names of an UNKNOWN line value with their kind and reason ({@code kind: A, B (reason); kind: C}). N-INS-3:
     * every word in a kind's place starts its part, a word the render does not write included, so the names after it
     * are read under that word and not under the kind before it.
     */
    static Map<String, Declared> parse(String value) {
        Map<String, Declared> names = new LinkedHashMap<>();
        if (value == null) {
            return names;
        }
        Matcher kind = KIND_WORD.matcher(value);
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
