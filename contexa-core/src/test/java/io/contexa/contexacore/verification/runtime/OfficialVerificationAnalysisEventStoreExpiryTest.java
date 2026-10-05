package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore.AnalysisEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationAnalysisEventStoreExpiryTest {

    private final OfficialVerificationAnalysisEventStore store = new OfficialVerificationAnalysisEventStore();

    @Test
    void bucketsWhoseLatestEventIsOlderThanTheCutOffAreReleased() {
        Instant now = Instant.now();
        store.append(event("request-old", now.minus(Duration.ofHours(2))));
        store.append(event("request-mixed", now.minus(Duration.ofHours(2))));
        store.append(event("request-mixed", now.minus(Duration.ofMinutes(1))));

        store.removeEventsObservedBefore(now.minus(Duration.ofHours(1)));

        assertThat(store.findByRequestId("request-old")).isEmpty();
        assertThat(store.findByRequestId("request-mixed")).hasSize(2);
    }

    private static AnalysisEvent event(String requestId, Instant observedAt) {
        return new AnalysisEvent("user", requestId, requestId, "LAYER1_COMPLETE", "LAYER1", "COMPLETED", "ALLOW",
                "/documents", null, 10L, observedAt, Map.of());
    }
}
