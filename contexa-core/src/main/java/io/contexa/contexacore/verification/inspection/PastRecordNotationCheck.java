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
import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryRenderer;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.autonomous.context.support.PastRecordRelevance;
import io.contexa.contexacore.autonomous.tiered.prompt.PastRecordLineValues;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Whether the PAST RECORDS block keeps the notation of dictionary 7 that the line form alone does not show: the state
 * line counts the records the lines draw (each line counts its {@code ×n} records; a {@code +k more} line stands for
 * at least k more), each record line has the twelve fields, and the lines are ordered same target first, then the
 * latest first. Times are compared by their distance from the request, and by the date when the distances read the
 * same; the stored ID order of records of one time cannot be told from the text and is not checked. With the record
 * fields, the render's retrieval state and the event clock sealed, the state line and every record line are also
 * compared with what the render draws from them, and the counts line with the counted facts sealed with the render
 * (W3-18).
 */
public final class PastRecordNotationCheck implements PromptInspectionCheck {

    public static final String CODE = "PAST_RECORD_NOTATION";

    private static final String STATE = "PastRecordsState";
    private static final String COUNTS = "PastRecordCounts";
    private static final String RECORD = "PastRecord";
    private static final Pattern RECORD_LABEL = Pattern.compile(RECORD + "\\d+");
    private static final Pattern DISTANCE = Pattern.compile("\\(" + RelativeTime.DISTANCE.pattern() + "\\)");
    private static final String SOURCE = "ragResultsJson.relatedDocuments";
    private static final String CONTEXT_REQUEST_TIME = "canonicalContext.requestObservedAt";
    private static final String RETRIEVAL_STATE = "executionMetadata." + PromptExecutionMetadata.PROMPT_RAG_STATE;
    private static final String SEALED_COUNTS = PromptExecutionMetadata.PROMPT_PAST_RECORD_COUNTS;
    private static final String COUNTS_SOURCE = "executionMetadata." + SEALED_COUNTS;

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return true;
    }

    /** A drawn record line and what the order and the count read of it. */
    private record Drawn(InspectedPrompt.Line line, String[] fields, boolean sameTarget, Long minutesBefore,
                         Long dateKey, int records) {
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        InspectedPrompt.Line state = null;
        InspectedPrompt.Line counts = null;
        List<Drawn> drawn = new ArrayList<>();
        int hidden = 0;
        for (InspectedPrompt.Line line : tally.subject().prompt().lines()) {
            if (line.kind() != InspectedPrompt.Kind.ENTRY || line.block() != PromptBlock.PAST_RECORDS) {
                continue;
            }
            String label = line.entryLine().label();
            String value = line.entryLine().value();
            if (STATE.equals(label)) {
                state = line;
                continue;
            }
            if (COUNTS.equals(label)) {
                counts = line;
                continue;
            }
            if (!RECORD_LABEL.matcher(label).matches()) {
                continue;
            }
            Matcher overflow = PromptDictionaryRenderer.OVERFLOW.matcher(value);
            if (overflow.matches()) {
                hidden += Integer.parseInt(overflow.group(1));
                continue;
            }
            String[] fields = value.split(PastRecordLineValues.SEPARATOR, -1);
            if (fields.length != PastRecordLineValues.FIELDS) {
                tally.mismatch(finding(tally, line).expected(PastRecordLineValues.FIELDS + " fields").actual(fields.length + " fields")
                        .reason("a past record line has the twelve fields of dictionary 7").build());
                continue;
            }
            drawn.add(new Drawn(line, fields, (PastRecordLineValues.SAME_TARGET + PastRecordRelevance.YES).equals(fields[PastRecordLineValues.SAME_TARGET_FIELD]),
                    minutesBefore(fields[0]), dateKey(fields[0]), times(fields[0])));
        }
        count(tally, state, drawn, hidden);
        order(tally, drawn);
        sources(tally, state);
        counts(tally, counts);
    }

    /**
     * The counts line is the counted facts sealed with the render, times measured from the sealed request time
     * (W3-18). Counts sealed without a drawn line are a line the prompt left out, unless its budget took the entry out;
     * a drawn line of a package that seals no counts cannot be compared (a package of this form seals them, P3 extra 43).
     */
    private static void counts(PromptInspectionTally tally, InspectedPrompt.Line line) {
        PastRecordCounts sealed = PastRecordCounts.fromMetadata(tally.subject().executionMetadata().get(SEALED_COUNTS));
        if (line == null && (sealed == null || tally.subject().budgetOmittedEntries()
                .contains(PromptBlock.PAST_RECORDS.name() + "." + COUNTS))) {
            return;
        }
        if (sealed == null) {
            tally.unverifiable(tally.unverifiableFinding().block(PromptBlock.PAST_RECORDS.title()).entry(COUNTS)
                    .lineNumber(line.number()).sourceRef(COUNTS_SOURCE)
                    .reason("the package seals no counted past record facts").build());
            return;
        }
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        ZoneId zone = tally.subject().eventZone();
        if (context == null || context.getRequestObservedAt() == null || zone == null) {
            tally.unverifiable(tally.unverifiableFinding().block(PromptBlock.PAST_RECORDS.title()).entry(COUNTS)
                    .sourceRef(CONTEXT_REQUEST_TIME)
                    .reason("the times of the counted past records cannot be compared: the request time is not sealed")
                    .build());
            return;
        }
        String wanted = sealed.line(LocalDateTime.ofInstant(context.getRequestObservedAt(), zone));
        if (line == null) {
            tally.mismatch(tally.mismatchFinding().block(PromptBlock.PAST_RECORDS.title()).entry(COUNTS)
                    .expected(wanted).sourceRef(COUNTS_SOURCE)
                    .reason("the counted past record facts are sealed but not drawn").build());
            return;
        }
        if (wanted.equals(line.entryLine().value())) {
            tally.matched(line);
            return;
        }
        tally.mismatch(finding(tally, line).expected(wanted).actual(line.entryLine().value()).sourceRef(COUNTS_SOURCE)
                .reason("the counts line is not the counted past record facts sealed with the render").build());
    }

    /**
     * The drawn record lines are the lines the sealed records give, in drawn order (the render's own grouping, ordering
     * and cap, with the same-target field sealed with each record), and the state line counts the records the render
     * saw. A package that seals no retrieval state of the render or no event clock cannot be compared.
     */
    private static void sources(PromptInspectionTally tally, InspectedPrompt.Line state) {
        List<InspectedPrompt.Line> lines = new ArrayList<>();
        for (InspectedPrompt.Line line : tally.subject().prompt().lines()) {
            if (line.kind() == InspectedPrompt.Kind.ENTRY && line.block() == PromptBlock.PAST_RECORDS
                    && RECORD_LABEL.matcher(line.entryLine().label()).matches()) {
                lines.add(line);
            }
        }
        if (lines.isEmpty() && state == null) {
            return;
        }
        Map<String, Object> metadata = tally.subject().executionMetadata();
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        ZoneId zone = tally.subject().eventZone();
        if (!(metadata.get(PromptExecutionMetadata.PROMPT_RAG_STATE) instanceof Map<?, ?> ragState) || zone == null) {
            tally.unverifiable(tally.unverifiableFinding().block(PromptBlock.PAST_RECORDS.title()).sourceRef(SOURCE)
                    .reason("the package seals no retrieval state of the render or no event clock").build());
            return;
        }
        boolean requestTimeSealed = context != null && context.getRequestObservedAt() != null;
        if (!requestTimeSealed && !lines.isEmpty()) {
            // The render falls back to the event's time, which the package does not keep: the other fields are compared.
            tally.unverifiable(tally.unverifiableFinding().block(PromptBlock.PAST_RECORDS.title())
                    .sourceRef(CONTEXT_REQUEST_TIME)
                    .reason("the distances of the records from the request cannot be compared: the request time is "
                            + "not sealed").build());
        }
        if (state != null) {
            String wanted = PastRecordLineValues.state(ragState);
            if (wanted.equals(state.entryLine().value())) {
                tally.matched(state);
            }
            else {
                tally.mismatch(finding(tally, state).expected(wanted).actual(state.entryLine().value())
                        .sourceRef(RETRIEVAL_STATE)
                        .reason("the state line is not the retrieval state the render kept").build());
            }
        }
        if (tally.subject().unreadSources().contains(PromptInspectionSources.PAST_RECORDS)) {
            for (InspectedPrompt.Line line : lines) {
                tally.unverifiable(tally.unverifiableFinding().block(PromptBlock.PAST_RECORDS.title())
                        .entry(line.entryLine().label()).lineNumber(line.number()).actual(line.entryLine().value())
                        .sourceRef(SOURCE).reason("the sealed past records do not read").build());
            }
            return;
        }
        List<String> expected = PastRecordLineValues.of(tally.subject().sources().pastRecords(),
                document -> {
                    Object sameTarget = document.getMetadata().get("sameTarget");
                    return sameTarget != null ? sameTarget.toString() : PastRecordRelevance.NOT_KNOWN;
                },
                requestTimeSealed ? LocalDateTime.ofInstant(context.getRequestObservedAt(), zone) : null);
        for (int index = 0; index < Math.max(lines.size(), expected.size()); index++) {
            InspectedPrompt.Line line = index < lines.size() ? lines.get(index) : null;
            String wanted = index < expected.size() ? expected.get(index) : null;
            String drawnValue = line == null ? null
                    : requestTimeSealed ? line.entryLine().value()
                    : DISTANCE.matcher(line.entryLine().value()).replaceFirst("").replace("  ", " ");
            if (line != null && wanted != null && wanted.equals(drawnValue)) {
                tally.matched(line);
                continue;
            }
            PromptInspectionFinding.Builder finding = line != null ? finding(tally, line)
                    : tally.mismatchFinding().block(PromptBlock.PAST_RECORDS.title()).entry(RECORD + (index + 1));
            tally.mismatch(finding.expected(wanted != null ? wanted : "no line (the sealed records give no more)")
                    .actual(line != null ? line.entryLine().value() : null).sourceRef(SOURCE)
                    .reason(line == null ? "a sealed record is not drawn"
                            : wanted == null ? "the line draws a record the sealed records do not hold"
                            : "the record line is not what the sealed record says")
                    .build());
        }
    }

    /** The state line counts the drawn records. */
    private static void count(PromptInspectionTally tally, InspectedPrompt.Line state, List<Drawn> drawn, int hidden) {
        if (state == null) {
            return;
        }
        String value = state.entryLine().value();
        int shown = drawn.stream().mapToInt(Drawn::records).sum();
        Matcher counted = PastRecordLineValues.COUNTED_STATE.matcher(value);
        if (counted.matches()) {
            int stated = Integer.parseInt(counted.group(1));
            boolean kept = hidden > 0 ? stated >= shown + hidden : stated == shown;
            if (kept && hidden > 0) {
                // Only a lower bound reads from the text; the exact count is compared with the sealed records.
                return;
            }
            if (kept) {
                tally.matched(state);
            }
            else {
                tally.mismatch(finding(tally, state)
                        .expected(hidden > 0 ? "at least " + (shown + hidden) + " records" : shown + " records")
                        .actual(stated + " records")
                        .reason("the state line's record count differs from the records the lines draw").build());
            }
            return;
        }
        if (PastRecordLineValues.EMPTY_STATE.matcher(value).matches()) {
            if (shown == 0 && hidden == 0) {
                tally.matched(state);
            }
            else {
                tally.mismatch(finding(tally, state).expected(shown + hidden + " records").actual(value)
                        .reason("the state line's record count says none while lines draw records").build());
            }
        }
    }

    /** Same target first, then the latest first. */
    private static void order(PromptInspectionTally tally, List<Drawn> drawn) {
        for (int index = 0; index < drawn.size(); index++) {
            Drawn current = drawn.get(index);
            if (index == 0) {
                tally.matched(current.line());
                continue;
            }
            Drawn previous = drawn.get(index - 1);
            if (current.sameTarget() && !previous.sameTarget()) {
                tally.mismatch(finding(tally, current.line()).actual(current.fields()[PastRecordLineValues.SAME_TARGET_FIELD])
                        .expected("after the records of the same target")
                        .reason("past records are ordered same target first").build());
                continue;
            }
            if (current.sameTarget() == previous.sameTarget() && newer(current, previous)) {
                tally.mismatch(finding(tally, current.line()).actual(current.fields()[0])
                        .expected("not newer than " + previous.fields()[0])
                        .reason("past records of one kind are ordered latest first").build());
                continue;
            }
            tally.matched(current.line());
        }
    }

    /** Whether the record is newer than the one before it, as far as the text can tell. */
    private static boolean newer(Drawn record, Drawn before) {
        if (record.minutesBefore() == null) {
            return false;
        }
        if (before.minutesBefore() == null) {
            return true;
        }
        if (!record.minutesBefore().equals(before.minutesBefore())) {
            return record.minutesBefore() < before.minutesBefore();
        }
        return record.dateKey() != null && before.dateKey() != null && record.dateKey() > before.dateKey()
                && record.dateKey() - before.dateKey() < 300L * 24L * 60L;
    }

    /** The distance before the request in minutes at the precision the line gives; null without a time. */
    private static Long minutesBefore(String timeField) {
        Matcher distance = DISTANCE.matcher(timeField);
        if (!distance.find()) {
            return null;
        }
        long amount = Long.parseLong(distance.group(1));
        long minutes = switch (distance.group(2)) {
            case "min" -> amount;
            case "h" -> amount * 60L;
            default -> amount * 24L * 60L;
        };
        return "after".equals(distance.group(3)) ? -minutes : minutes;
    }

    /** Month, day, hour and minute as one comparable number; null without a date. */
    private static Long dateKey(String timeField) {
        Matcher date = PastRecordLineValues.TIME.matcher(timeField);
        if (!date.find()) {
            return null;
        }
        return ((Long.parseLong(date.group(1)) * 31L + Long.parseLong(date.group(2))) * 24L
                + Long.parseLong(date.group(3))) * 60L + Long.parseLong(date.group(4));
    }

    private static int times(String timeField) {
        Matcher times = PastRecordLineValues.REPEAT_COUNT.matcher(timeField);
        return times.find() ? Integer.parseInt(times.group(1)) : 1;
    }

    private static PromptInspectionFinding.Builder finding(PromptInspectionTally tally, InspectedPrompt.Line line) {
        return tally.mismatchFinding().block(PromptBlock.PAST_RECORDS.title()).entry(line.entryLine().label())
                .lineNumber(line.number());
    }
}
