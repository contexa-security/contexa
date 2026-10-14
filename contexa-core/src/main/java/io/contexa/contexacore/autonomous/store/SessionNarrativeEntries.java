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
package io.contexa.contexacore.autonomous.store;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * A session narrative entry as the stores keep it: the time of the request it records, a tab, and its value. A
 * session's requests can be decided, and so recorded, out of the order they were made; the entries are read in the
 * order the requests were made (N-SES-1). An entry kept without its request time keeps its place after the entry
 * before it.
 */
final class SessionNarrativeEntries {

    private static final char SEPARATOR = '\t';

    private record Entry(long at, String value) {
    }

    private SessionNarrativeEntries() {
    }

    static String encode(long requestTimestamp, String value) {
        return requestTimestamp + String.valueOf(SEPARATOR) + value;
    }

    /** The values of the most recent {@code count} entries, kept oldest first, in the order their requests were made. */
    static List<String> recentInRequestOrder(List<?> entries, int count) {
        if (entries == null || entries.isEmpty() || count <= 0) {
            return new ArrayList<>();
        }
        List<Entry> ordered = new ArrayList<>(entries.size());
        long at = Long.MIN_VALUE;
        for (Object entry : entries) {
            if (entry == null) {
                continue;
            }
            String text = entry.toString();
            int separator = text.indexOf(SEPARATOR);
            Long time = separator > 0 ? time(text.substring(0, separator)) : null;
            if (time != null) {
                at = time;
                text = text.substring(separator + 1);
            }
            ordered.add(new Entry(at, text));
        }
        ordered.sort(Comparator.comparingLong(Entry::at));
        List<String> values = new ArrayList<>(Math.min(count, ordered.size()));
        for (Entry entry : ordered.subList(Math.max(0, ordered.size() - count), ordered.size())) {
            values.add(entry.value());
        }
        return values;
    }

    /** The intervals of the most recent {@code count} entries in the order their requests were made. */
    static List<Long> recentIntervalsInRequestOrder(List<?> entries, int count) {
        List<Long> intervals = new ArrayList<>();
        for (String value : recentInRequestOrder(entries, count)) {
            Long interval = time(value);
            if (interval != null) {
                intervals.add(interval);
            }
        }
        return intervals;
    }

    private static Long time(String text) {
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
