package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** The analysis read is repeated from a short cache, never invented (docs/showcase/데모-재설계.md R-29). */
class DecisionReadCacheTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void aRunningAnalysisIsReadAgainAfterASecondAndAnEndedOneIsKept() throws IOException {
        AtomicInteger reads = new AtomicInteger();
        MovingClock clock = new MovingClock(Instant.parse("2026-10-06T12:00:00Z"));
        String[] answer = {"{\"events\":[{\"type\":\"LAYER1_START\"}]}"};
        DecisionReadCache cache = new DecisionReadCache(id -> {
            reads.incrementAndGet();
            return JSON.readTree(answer[0]);
        }, clock);

        cache.get("r-1");
        cache.get("r-1");
        assertThat(reads).as("within a second").hasValue(1);

        clock.advance(Duration.ofSeconds(1));
        answer[0] = "{\"records\":[{}],\"events\":[{\"type\":\"LAYER1_START\"},{\"type\":\"DECISION_APPLIED\"}]}";
        JsonNode ended = cache.get("r-1");
        assertThat(reads).hasValue(2);
        assertThat(ended.path("events")).hasSize(2);

        clock.advance(Duration.ofMinutes(5));
        cache.get("r-1");
        assertThat(reads).as("an ended analysis does not change").hasValue(2);

        clock.advance(Duration.ofMinutes(5));
        cache.get("r-1");
        assertThat(reads).as("kept at most ten minutes").hasValue(3);
    }

    @Test
    void anAppliedEventBeforeTheDecisionRecordIsReadAgain() throws IOException {
        AtomicInteger reads = new AtomicInteger();
        MovingClock clock = new MovingClock(Instant.parse("2026-10-06T12:00:00Z"));
        DecisionReadCache cache = new DecisionReadCache(id -> {
            reads.incrementAndGet();
            return JSON.readTree("{\"records\":[],\"events\":[{\"type\":\"DECISION_APPLIED\"}]}");
        }, clock);

        cache.get("r-2");
        clock.advance(Duration.ofSeconds(1));
        cache.get("r-2");
        assertThat(reads).as("no decision record yet, so the analysis is not taken as ended").hasValue(2);
    }

    @Test
    void anAnalysisErrorEndsTheAnalysisWithoutARecord() throws IOException {
        assertThat(DecisionReadCache.ended(JSON.readTree("{\"events\":[{\"type\":\"ANALYSIS_ERROR\"}]}")))
                .isTrue();
    }

    private static final class MovingClock extends Clock {
        private Instant now;

        MovingClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
