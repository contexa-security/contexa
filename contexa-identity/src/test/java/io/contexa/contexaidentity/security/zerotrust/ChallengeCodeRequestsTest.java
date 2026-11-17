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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Console design 6.2: a code mailed to a challenged user is the challenge's "code requested". */
class ChallengeCodeRequestsTest {

    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final ZeroTrustDecisionOutcomes outcomes = mock(ZeroTrustDecisionOutcomes.class);
    private final ChallengeCodeRequests requests = new ChallengeCodeRequests(() -> actions, () -> outcomes);

    @Test
    void aCodeMailedToAChallengedUserIsKeptForTheChallengedRequest() {
        ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = new ZeroTrustActionRepository.ZeroTrustAnalysisData(
                "CHALLENGE", null, null, null, 1, null, null, null, "request-1", null, null);
        when(actions.getActionFromHash("alice")).thenReturn(ZeroTrustAction.CHALLENGE);
        when(actions.getAnalysisData("alice")).thenReturn(analysis);

        requests.accept(" alice ");

        verify(outcomes).record("request-1", "alice", null, ZeroTrustDecisionOutcomes.Kind.CHALLENGE_CODE_REQUESTED,
                "alice", null);
    }

    @Test
    void aCodeMailedToAUserNotChallengedIsNoStepOfAChallenge() {
        when(actions.getActionFromHash("bob")).thenReturn(ZeroTrustAction.ALLOW);

        requests.accept("bob");
        requests.accept(" ");
        new ChallengeCodeRequests(() -> null, () -> outcomes).accept("bob");

        verify(outcomes, never()).record(anyString(), anyString(), any(), any(), anyString(), any());
    }
}
