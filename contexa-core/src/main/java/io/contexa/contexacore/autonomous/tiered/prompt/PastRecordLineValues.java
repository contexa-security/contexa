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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryRenderer;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.support.PastDeniedDecisions;
import io.contexa.contexacore.autonomous.context.support.PastRecordPostProcessor;
import java.util.regex.Pattern;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * The PastRecord line values a v20 prompt draws from its past records: ranked, grouped, ordered and capped as the
 * render does, with each record's same-target field given. The render and the prompt inspector use the same function;
 * the inspector gives the records and the same-target fields sealed with the decision.
 */
public final class PastRecordLineValues {

    /** The separator of a past record line's fields (dictionary 7). */
    public static final String SEPARATOR = " / ";
    /** The fields of a past record line (dictionary 7, W3-18: twelve). */
    public static final int FIELDS = 12;
    /** The place of the same-target field among them, and its words. */
    public static final int SAME_TARGET_FIELD = 10;
    public static final String SAME_TARGET = "same target: ";
    /** docs/agent A3-5: the target field of a v21 past record line (PastRecordLines). */
    public static final String TARGET_APART = PastRecordLines.TARGET_APART;
    /** The time field: {@code 10-12 Sun 03:17}, a group's repeat count after it ({@code  ×3}). */
    public static final String TIME_FORMAT = "%02d-%02d %s %02d:%02d";
    public static final Pattern TIME = Pattern.compile("^(\\d{2})-(\\d{2}) \\S+ (\\d{2}):(\\d{2})");
    public static final String REPEAT = " ×";
    public static final Pattern REPEAT_COUNT = Pattern.compile(REPEAT + "(\\d+)$");
    /** The dictionary 7 form of a past record line (R1b-3: the one written form of the render, dictionary and inspector). */
    public static final String RECORD_FORMAT = ".+(" + SEPARATOR + ".+){" + (FIELDS - 1) + "}";
    /** BR-C6 (QF-14): the field of a v21 line that says how the record was learned, before its authorization. */
    public static final String LEARNED = "learned: ";
    public static final String LEARNED_MODEL_ALLOW = "by the model alone";
    public static final String LEARNED_VERIFIED = "after verification";
    public static final String LEARNED_PROMOTED = "after promotion";
    public static final String LEARNED_ADMIN_RELEASE = "by administrator release";
    /** A record stored before the source was written (never filled by a guess). */
    public static final String LEARNED_NOT_RECORDED = "source not recorded";
    /** BR-C6 (QF-13): the field of a v21 line that names the arguments of the call that came from a tool's output. */
    public static final String ARGS_FROM_TOOL_OUTPUT = "args from tool output: ";
    /** The fields of a v21 line: the twelve and the learned field, the arguments field besides when a record has one. */
    public static final int FIELDS_V21 = FIELDS + 1;
    public static final int FIELDS_V21_WITH_ARGS = FIELDS + 2;
    /**
     * The form of a v21 past record line (BR-C6): the dictionary 7 form with the learned field, and the arguments field
     * when a record has one, between the same-target field and the authorization field. Only the words of the fixed list
     * stand in the learned field.
     */
    public static final String RECORD_FORMAT_V21 = ".+(" + SEPARATOR + ".+){" + (SAME_TARGET_FIELD - 1) + "}" + SEPARATOR
            + SAME_TARGET + ".+" + SEPARATOR + LEARNED + "(" + LEARNED_MODEL_ALLOW + "|" + LEARNED_VERIFIED + "|"
            + LEARNED_PROMOTED + "|" + LEARNED_ADMIN_RELEASE + "|" + LEARNED_NOT_RECORDED + ")(" + SEPARATOR
            + ARGS_FROM_TOOL_OUTPUT + ".+)?" + SEPARATOR + "authorized as .+";
    /** The state line's words and form (W3-4, N-MISS-1 D8). */
    public static final String NONE_FOUND = "none found";
    public static final String NOT_RETRIEVED = "not retrieved";
    public static final String STATE_FORMAT = "(\\d+ records? of \\d+ candidates \\(.+\\)|" + NONE_FOUND + " \\(.+\\)|"
            + NOT_RETRIEVED + " \\(.+\\))(; second search \\(first search [A-Z_]+\\))?";
    public static final Pattern COUNTED_STATE = Pattern.compile("(\\d+) records? of \\d+ candidates.*");
    public static final Pattern EMPTY_STATE = Pattern.compile("(" + NONE_FOUND + "|" + NOT_RETRIEVED + ") .*");
    /** The retrieval states of a search the request did not finish or did not run. */
    public static final List<String> NOT_RETRIEVED_STATES = List.of("TIMEOUT", "BUDGET_EXPIRED", "UNAVAILABLE", "NOT_REQUESTED");
    /**
     * docs/agent B3-3: the validated case memory lines that hold stored free text (an earlier analysis' summary, a
     * threat signal's summary, matched threat knowledge), which the v21 render draws as untrusted texts.
     */
    public static final Set<String> VALIDATED_CASE_TEXT_LINES = Set.of("ObjectiveAwareReasoningMemory",
            "XaiLinkedFacts", "ReasoningFacts", "CrossTenantObjectiveMisuseFacts");

    private PastRecordLineValues() {
    }

    /**
     * docs/agent B3-3: the stored texts of the validated case memory lines that hold free text, each once, in the
     * memory section's order (shared with the inspector).
     */
    public static List<String> validatedCaseTexts(CanonicalSecurityContext.ReasoningMemoryProfile profile) {
        if (profile == null) {
            return List.of();
        }
        Set<String> texts = new LinkedHashSet<>();
        addText(texts, profile.getObjectiveAwareReasoningMemory());
        addTexts(texts, profile.getXaiLinkedFacts());
        addTexts(texts, profile.getReasoningFacts());
        addTexts(texts, profile.getCrossTenantObjectiveMisuseFacts());
        return List.copyOf(texts);
    }

    private static void addTexts(Set<String> texts, List<String> values) {
        if (values != null) {
            values.forEach(value -> addText(texts, value));
        }
    }

    private static void addText(Set<String> texts, String value) {
        if (value != null && !value.isBlank()) {
            texts.add(value.strip());
        }
    }

    /** The values of the PastRecord lines in drawn order, the last one {@code +n more} when the cap leaves some out. */
    public static List<String> of(List<Document> documents, Function<Document, String> sameTargetOf,
                                  LocalDateTime requestTime) {
        return of(documents, sameTargetOf, requestTime, null);
    }

    /** The values of a v20 line (no marker) or a v21 line, whose target field the marker writes (A3-5). */
    public static List<String> of(List<Document> documents, Function<Document, String> sameTargetOf,
                                  LocalDateTime requestTime, String targetMarker) {
        List<PromptListItem> items = PastRecordLines.items(ranked(documents),
                (document, record) -> sameTargetOf.apply(document), requestTime, targetMarker);
        PromptDictionaryEntry entry = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(candidate -> candidate.block() == PromptBlock.PAST_RECORDS && "PastRecord{i}".equals(candidate.name()))
                .findFirst().orElseThrow();
        List<PromptListItem> sorted = entry.listOrder().sort(items);
        int shown = PromptDictionaryRenderer.shownItems(entry, sorted.size());
        List<String> values = new ArrayList<>();
        for (int index = 0; index < shown; index++) {
            values.add(sorted.get(index).text());
        }
        if (shown < sorted.size()) {
            values.add(PromptDictionaryRenderer.overflowValue(sorted.size() - shown));
        }
        return List.copyOf(values);
    }

    /**
     * A3-5: the targets a v21 render writes apart as untrusted texts, of the past record and denied decision lines it
     * draws, each once (shared with the inspector).
     */
    public static List<String> targets(List<Document> documents, Function<Document, String> sameTargetOf,
                                       LocalDateTime requestTime, PastDeniedDecisions denied) {
        List<PromptListItem> records = documents == null || documents.isEmpty() ? List.of()
                : PastRecordLines.items(ranked(documents),
                (document, record) -> sameTargetOf.apply(document), requestTime, PastRecordLines.TARGET_APART);
        return SecurityDecisionPromptValues.pastRecordTargets(records,
                PastDeniedLines.items(denied, requestTime, true));
    }

    /** BR-S4: the records in the order the render draws them, through the same post-processing step. */
    private static List<Document> ranked(List<Document> documents) {
        return PastRecordPostProcessor.ranked().process(PastRecordPostProcessor.PAST_RECORDS, documents);
    }

    /** The PastRecordsState value the render draws from the retrieval state it kept with the prompt. */
    public static String state(Map<?, ?> retrievalState) {
        return SecurityDecisionPromptValues.pastRecordsState(SecurityDecisionPromptSections.RagState.fromMetadata(retrievalState));
    }

    /**
     * Whether the retrieval state the render kept is a search the request did not finish or did not run: the render
     * then names the past records unknown now (dictionary 1.4). N-INS-2: shared with the inspector.
     */
    public static boolean notRetrieved(Map<?, ?> retrievalState) {
        return notRetrieved(state(retrievalState));
    }

    /** Whether a PastRecordsState value says the search did not finish or did not run (N-INS-2: shared). */
    public static boolean notRetrieved(String stateValue) {
        return stateValue != null && stateValue.startsWith(NOT_RETRIEVED + " (");
    }

    /**
     * The reason the render names the past records unknown now with, from the retrieval state it kept, or null when
     * the search finished (N-INS-4: shared with the inspector).
     */
    public static String notRetrievedReason(Map<?, ?> retrievalState) {
        return SecurityDecisionPromptValues.notRetrievedReason(SecurityDecisionPromptSections.RagState.fromMetadata(retrievalState));
    }

    /** The reason the render names the counted facts unknown with when it draws no counts line (N-INS-4: shared). */
    public static String countsUnknownReason(Map<?, ?> retrievalState) {
        return SecurityDecisionPromptValues.countsUnknownReason(SecurityDecisionPromptSections.RagState.fromMetadata(retrievalState));
    }
}
