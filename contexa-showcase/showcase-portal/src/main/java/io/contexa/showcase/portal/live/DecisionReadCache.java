package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keeps control D's decision record of a request for a short while (docs/showcase/데모-재설계.md 10.2 R-29): every
 * visitor screen asks for the analysis of its run several times a second, and 50 visitors at once would otherwise read
 * control D and the engine database about 170 times a second. A record whose analysis has ended (an error event, or
 * the applied event with the decision record written) does not change any more and is kept until it is evicted; any
 * other record is read again after {@link #FRESH}. The cache only repeats what control D answered; it never makes up a
 * record.
 */
public class DecisionReadCache {

    /** How long a record of an analysis still running is reused. */
    static final Duration FRESH = Duration.ofSeconds(1);
    /** How long any record is kept at most. */
    static final Duration KEPT = Duration.ofMinutes(10);
    static final int MAX_ENTRIES = 2000;

    /** Reads control D's decision record of a request. */
    @FunctionalInterface
    public interface Reader {
        JsonNode read(String requestId) throws IOException;
    }

    private record Entry(JsonNode record, Instant readAt, boolean ended) {
    }

    private final Reader reader;
    private final Clock clock;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    public DecisionReadCache(Reader reader, Clock clock) {
        this.reader = reader;
        this.clock = clock;
    }

    public JsonNode get(String requestId) throws IOException {
        Instant now = clock.instant();
        Entry entry = entries.get(requestId);
        if (entry != null && (entry.ended() && now.isBefore(entry.readAt().plus(KEPT))
                || now.isBefore(entry.readAt().plus(FRESH)))) {
            return entry.record();
        }
        JsonNode record = reader.read(requestId);
        if (entries.size() >= MAX_ENTRIES) {
            entries.entrySet().removeIf(old -> !now.isBefore(old.getValue().readAt().plus(KEPT)));
            if (entries.size() >= MAX_ENTRIES) {
                entries.clear();
            }
        }
        entries.put(requestId, new Entry(record, now, ended(record)));
        return record;
    }

    static boolean ended(JsonNode record) {
        boolean decided = record.path("records").isArray() && !record.path("records").isEmpty();
        for (JsonNode event : record.path("events")) {
            String type = event.path("type").asText();
            if ("ANALYSIS_ERROR".equals(type) || ("DECISION_APPLIED".equals(type) && decided)) {
                return true;
            }
        }
        return false;
    }
}
