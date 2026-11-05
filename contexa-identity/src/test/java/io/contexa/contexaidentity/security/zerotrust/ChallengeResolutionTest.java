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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Q-12 (PR-62): the answer of one session releases that session. */
class ChallengeResolutionTest {

    private static final String VICTIM = "context-victim";
    private static final String ATTACKER = "context-attacker";
    private static final String SECOND_DEVICE = "context-second-device";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final SecurityLearningService learning = mock(SecurityLearningService.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/contexa/step-up/code/verify");

    private ChallengeResolution resolution(ZeroTrustActionRepository repository) {
        return new ChallengeResolution(repository, learning, null, null, null, null, null);
    }

    private void challenged() {
        actions.saveAction("mail-k5", ZeroTrustAction.CHALLENGE, Map.of("contextBindingHash", ATTACKER));
    }

    @Test
    @DisplayName("the victim passes the code: the victim goes on, the attacker's session stays stopped")
    void theVictimsCodeDoesNotFreeTheAttacker() {
        challenged();

        assertThat(resolution(actions).releaseChallenge("mail-k5", VICTIM, request, null)).isTrue();

        assertThat(actions.getCurrentAction("mail-k5", VICTIM)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(actions.getCurrentAction("mail-k5", ATTACKER)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a second device answers for itself; the challenged request is learned once")
    void aSecondDeviceAnswersForItself() {
        challenged();
        ChallengeResolution resolution = resolution(actions);
        resolution.releaseChallenge("mail-k5", VICTIM, request, null);

        assertThat(resolution.releaseChallenge("mail-k5", SECOND_DEVICE, request, null)).isTrue();

        assertThat(actions.getCurrentAction("mail-k5", SECOND_DEVICE)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(actions.getCurrentAction("mail-k5", ATTACKER)).isEqualTo(ZeroTrustAction.CHALLENGE);
        verify(learning, times(1)).learnAndStore(eq("mail-k5"), any(), any());
    }

    @Test
    @DisplayName("an answer that cannot be kept to its session releases no one")
    void aHoldThatFailsReleasesNoOne() {
        ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
        when(repository.getActionFromHash("mail-k5")).thenReturn(ZeroTrustAction.CHALLENGE);
        doThrow(new IllegalStateException("store down")).when(repository).holdChallengeForOtherSessions("mail-k5", VICTIM);

        assertThat(resolution(repository).releaseChallenge("mail-k5", VICTIM, request, null)).isFalse();

        verify(repository, never()).saveActionWithPrevious(anyString(), any(), any());
    }

    @Test
    @DisplayName("an ESCALATE waits for its review whichever session answers")
    void anEscalateWaits() {
        actions.saveAction("mail-k5", ZeroTrustAction.ESCALATE, Map.of());

        assertThat(resolution(actions).releaseChallenge("mail-k5", VICTIM, request, null)).isFalse();

        assertThat(actions.getCurrentAction("mail-k5", VICTIM)).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    @DisplayName("nothing to answer leaves the store as it is")
    void nothingToAnswer() {
        assertThat(resolution(actions).releaseChallenge("mail-k5", VICTIM, request, null)).isTrue();

        assertThat(actions.getAnalysisData("mail-k5").action()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name());
    }
}
