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
package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** W6-6 (P6-CHANGE-4): a Layer2 that drew its own prompt completes the trace, so the seal holds the applied stage. */
class SealedEvidenceLayer2CompletionAspectTest {

    @Test
    void theTraceIsCompletedAfterLayer2() {
        List<SecurityEvent> completed = new ArrayList<>();
        SecurityEvent event = SecurityEvent.builder().eventId("evt-l2").build();

        new SealedEvidenceLayer2CompletionAspect(completed::add).completeAfterLayer2(event);

        assertThat(completed).containsExactly(event);
    }
}
