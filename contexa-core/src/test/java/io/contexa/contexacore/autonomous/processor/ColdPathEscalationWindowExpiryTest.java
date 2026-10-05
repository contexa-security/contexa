package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;

class ColdPathEscalationWindowExpiryTest {

    private final ColdPathEventProcessor processor = new ColdPathEventProcessor(null, null, null);

    @Test
    void aFullWindowIsReleasedBecauseItsNextRecordWouldResetIt() {
        SecurityEvent event = event("alice");
        for (int analysis = 0; analysis < 100; analysis++) {
            processor.recordEscalationProtectionSample(event, "/exports", analysis % 2 == 0);
        }
        processor.recordEscalationProtectionSample(event, "/documents/7", true);

        processor.removeInactiveEscalationWindows(System.currentTimeMillis());

        assertThat(processor.escalationWindowCount()).isEqualTo(1);
    }

    @Test
    void aWindowIdleForADayIsReleased() {
        SecurityEvent event = event("bob");
        processor.recordEscalationProtectionSample(event, "/documents/8", true);

        processor.removeInactiveEscalationWindows(System.currentTimeMillis() + Duration.ofHours(23).toMillis());
        assertThat(processor.escalationWindowCount()).isEqualTo(1);

        processor.removeInactiveEscalationWindows(System.currentTimeMillis() + Duration.ofHours(25).toMillis());
        assertThat(processor.escalationWindowCount()).isZero();
    }

    private static SecurityEvent event(String userId) {
        return SecurityEvent.builder().userId(userId).metadata(new LinkedHashMap<>()).build();
    }
}
