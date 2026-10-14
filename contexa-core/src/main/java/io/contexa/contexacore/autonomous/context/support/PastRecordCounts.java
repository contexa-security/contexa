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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.time.format.TextStyle;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * The counted facts of a request's past allowed records of its action family (W3-18): on the request's target, on
 * other targets (a record whose target cannot be compared is counted apart), and through the request's entry point,
 * the path template with the HTTP method. The same target is the same path, or the same values of the template's
 * variables through another entry point ({@link PastRecordRelevance#sameTarget}). The counts come from an exact
 * lookup of the store, so the prompt and the sealed evidence state them as numbers, not as a search's subset.
 *
 * @param action            the request's action family
 * @param entryPoint        the request's HTTP method and path template
 * @param sameTarget        records on the request's target
 * @param sameTargetLast    the latest of them, null when none states a time
 * @param otherTargets      records on other targets
 * @param otherTargetsLast  the latest of them, null when none states a time
 * @param targetNotKnown    records whose target cannot be compared with the request's
 * @param entryPointRecords records through the request's entry point, on any target
 */
public record PastRecordCounts(String action, String entryPoint, long sameTarget, @Nullable LocalDateTime sameTargetLast,
                               long otherTargets, @Nullable LocalDateTime otherTargetsLast, long targetNotKnown,
                               long entryPointRecords) {

    /** The event metadata of the counts; a {@code rag} key, so a past record search copy of the event returns it. */
    public static final String EVENT_METADATA_KEY = "ragPastRecordCounts";

    private static final String ACTION = "action";
    private static final String ENTRY_POINT = "entryPoint";
    private static final String SAME_TARGET = "sameTarget";
    private static final String SAME_TARGET_LAST = "sameTargetLast";
    private static final String OTHER_TARGETS = "otherTargets";
    private static final String OTHER_TARGETS_LAST = "otherTargetsLast";
    private static final String TARGET_NOT_KNOWN = "targetNotKnown";
    private static final String ENTRY_POINT_RECORDS = "entryPointRecords";

    public PastRecordCounts {
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(entryPoint, "entryPoint");
    }

    /** The counts of the groups of a past record scope against the request, whose action family is known. */
    public static PastRecordCounts of(PastRecordRelevance.Subject request, List<PastRecordGroup> groups) {
        Objects.requireNonNull(request.actionFamily(), "the request's action family");
        long sameTarget = 0;
        long otherTargets = 0;
        long targetNotKnown = 0;
        long entryPointRecords = 0;
        LocalDateTime sameTargetLast = null;
        LocalDateTime otherTargetsLast = null;
        for (PastRecordGroup group : groups) {
            PastRecordRelevance.Subject record = PastRecordRelevance.Subject.ofRecord(recordMetadata(group), null);
            switch (PastRecordRelevance.sameTarget(request, record)) {
                case PastRecordRelevance.YES -> {
                    sameTarget += group.records();
                    sameTargetLast = later(sameTargetLast, group.latest());
                }
                case PastRecordRelevance.NO -> {
                    otherTargets += group.records();
                    otherTargetsLast = later(otherTargetsLast, group.latest());
                }
                default -> targetNotKnown += group.records();
            }
            if (sameEntryPoint(request, group)) {
                entryPointRecords += group.records();
            }
        }
        return new PastRecordCounts(request.actionFamily().name(), entryPoint(request), sameTarget, sameTargetLast,
                otherTargets, otherTargetsLast, targetNotKnown, entryPointRecords);
    }

    /**
     * The dictionary line ({@code EXPORT on this target 3 (last 30 min before this request); on other targets 9 (...);
     * entry point POST /api/projects/{projectKey}/exports used 12 times before}), times measured from the request.
     */
    public String line(@Nullable LocalDateTime requestTime) {
        StringBuilder line = new StringBuilder()
                .append(action).append(" on this target ").append(sameTarget).append(last(sameTarget, sameTargetLast, requestTime))
                .append("; on other targets ").append(otherTargets).append(last(otherTargets, otherTargetsLast, requestTime));
        if (targetNotKnown > 0) {
            line.append("; target not known ").append(targetNotKnown);
        }
        line.append("; entry point ").append(entryPoint);
        if (entryPointRecords == 0) {
            line.append(" first used now");
        }
        else {
            line.append(" used ").append(entryPointRecords).append(entryPointRecords == 1 ? " time" : " times").append(" before");
        }
        return line.toString();
    }

    /** The records the lookup counted: on the target, on other targets and those whose target is not known. */
    public long total() {
        return sameTarget + otherTargets + targetNotKnown;
    }

    /** The counts as metadata of the event and the sealed evidence; times in ISO local form. */
    public Map<String, Object> toMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put(ACTION, action);
        metadata.put(ENTRY_POINT, entryPoint);
        metadata.put(SAME_TARGET, sameTarget);
        metadata.put(SAME_TARGET_LAST, sameTargetLast != null ? sameTargetLast.toString() : null);
        metadata.put(OTHER_TARGETS, otherTargets);
        metadata.put(OTHER_TARGETS_LAST, otherTargetsLast != null ? otherTargetsLast.toString() : null);
        metadata.put(TARGET_NOT_KNOWN, targetNotKnown);
        metadata.put(ENTRY_POINT_RECORDS, entryPointRecords);
        return metadata;
    }

    /** The counts read back from {@link #toMetadata()}, or null when the value is not a complete set. */
    @Nullable
    public static PastRecordCounts fromMetadata(@Nullable Object value) {
        if (!(value instanceof Map<?, ?> metadata)) {
            return null;
        }
        String action = text(metadata.get(ACTION));
        String entryPoint = text(metadata.get(ENTRY_POINT));
        Long sameTarget = number(metadata.get(SAME_TARGET));
        Long otherTargets = number(metadata.get(OTHER_TARGETS));
        Long targetNotKnown = number(metadata.get(TARGET_NOT_KNOWN));
        Long entryPointRecords = number(metadata.get(ENTRY_POINT_RECORDS));
        if (action == null || entryPoint == null || sameTarget == null || otherTargets == null || targetNotKnown == null
                || entryPointRecords == null) {
            return null;
        }
        return new PastRecordCounts(action, entryPoint, sameTarget, time(metadata.get(SAME_TARGET_LAST)), otherTargets,
                time(metadata.get(OTHER_TARGETS_LAST)), targetNotKnown, entryPointRecords);
    }

    private static Map<String, Object> recordMetadata(PastRecordGroup group) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (group.path() != null) {
            metadata.put("requestPath", group.path());
        }
        if (group.pathFamily() != null) {
            metadata.put("pathFamily", group.pathFamily());
        }
        if (group.httpMethod() != null) {
            metadata.put("httpMethod", group.httpMethod());
        }
        return metadata;
    }

    private static boolean sameEntryPoint(PastRecordRelevance.Subject request, PastRecordGroup group) {
        if (request.pathFamily() == null || !request.pathFamily().equals(group.pathFamily())) {
            return false;
        }
        return request.httpMethod() == null || group.httpMethod() == null
                || request.httpMethod().equalsIgnoreCase(group.httpMethod());
    }

    private static String entryPoint(PastRecordRelevance.Subject request) {
        String template = request.pathFamily() != null ? request.pathFamily() : "path not known";
        return request.httpMethod() != null ? request.httpMethod().toUpperCase(Locale.ROOT) + " " + template : template;
    }

    private static String last(long count, @Nullable LocalDateTime latest, @Nullable LocalDateTime requestTime) {
        if (count == 0) {
            return "";
        }
        if (latest == null) {
            return " (last time not recorded)";
        }
        String relative = RelativeTime.of(latest, requestTime);
        return relative != null ? " (last " + relative + ")"
                : String.format(Locale.ROOT, " (last %02d-%02d %s %02d:%02d)", latest.getMonthValue(),
                latest.getDayOfMonth(), latest.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.ROOT),
                latest.getHour(), latest.getMinute());
    }

    @Nullable
    private static LocalDateTime later(@Nullable LocalDateTime current, @Nullable LocalDateTime candidate) {
        if (candidate == null) {
            return current;
        }
        return current == null || candidate.isAfter(current) ? candidate : current;
    }

    @Nullable
    private static String text(@Nullable Object value) {
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }

    @Nullable
    private static Long number(@Nullable Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return Long.parseLong(text);
        }
        catch (NumberFormatException exception) {
            return null;
        }
    }

    @Nullable
    private static LocalDateTime time(@Nullable Object value) {
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return LocalDateTime.parse(text);
        }
        catch (DateTimeParseException exception) {
            return null;
        }
    }
}
