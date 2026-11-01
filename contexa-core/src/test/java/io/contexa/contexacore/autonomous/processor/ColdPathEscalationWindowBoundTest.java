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
package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the escalation protection windows are kept within a count bound on top of the day an idle window is kept;
 * past it the windows idle the longest go first.
 */
class ColdPathEscalationWindowBoundTest {

    private final ColdPathEventProcessor processor = new ColdPathEventProcessor(null, null, null);

    @Test
    void pastTheBoundTheWindowsIdleTheLongestGoFirst() throws InterruptedException {
        processor.setMaxEscalationWindows(3);
        for (int document = 1; document <= 5; document++) {
            processor.recordEscalationProtectionSample(event("alice"), "/documents/" + document, true);
            Thread.sleep(5);
        }
        // Recorded again, so it is the window idle the shortest.
        processor.recordEscalationProtectionSample(event("alice"), "/documents/1", false);

        processor.removeInactiveEscalationWindows(System.currentTimeMillis());

        assertThat(processor.escalationWindowKeys()).containsExactlyInAnyOrder(
                "user:alice|/documents/1", "user:alice|/documents/4", "user:alice|/documents/5");
    }

    @Test
    void windowsWithinTheBoundStayAndKeepTheirCount() {
        processor.setMaxEscalationWindows(10);
        for (int analysis = 0; analysis < 12; analysis++) {
            processor.recordEscalationProtectionSample(event("bob"), "/exports", true);
        }
        processor.recordEscalationProtectionSample(event("bob"), "/documents/2", false);

        processor.removeInactiveEscalationWindows(System.currentTimeMillis());

        assertThat(processor.escalationWindowCount()).isEqualTo(2);
        assertThat(String.valueOf(processor.recordEscalationProtectionSample(event("bob"), "/exports", true)))
                .isEqualTo("EscalationProtectionSample[escalates=13, total=13]");
    }

    @Test
    void theBoundIsAtLeastOneWindowAndDefaultsToTenThousand() {
        assertThat(processor.getMaxEscalationWindows()).isEqualTo(ColdPathEventProcessor.DEFAULT_MAX_ESCALATION_WINDOWS);
        assertThat(ColdPathEventProcessor.DEFAULT_MAX_ESCALATION_WINDOWS).isEqualTo(10_000);

        processor.setMaxEscalationWindows(0);

        assertThat(processor.getMaxEscalationWindows()).isEqualTo(1);
    }

    private static SecurityEvent event(String userId) {
        return SecurityEvent.builder().userId(userId).metadata(new LinkedHashMap<>()).build();
    }
}
