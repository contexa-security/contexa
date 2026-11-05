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
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Q-16 (PR-66): the decisions after a passed step-up are told of it. The release keeps it as a fact of the context the
 * client goes on in, so only that context's requests carry it. It is the same under both ownerships.
 */
class ChallengeResolutionVerifiedFactTest {

    private static final String USER = "alice";
    private static final String CONTEXT = "context-after-the-step-up";

    private final ZeroTrustActionRepository repository = mock(ZeroTrustActionRepository.class);
    private final SecurityContextDataStore store = mock(SecurityContextDataStore.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private ChallengeResolution resolution;

    @BeforeEach
    void setUp() {
        resolution = new ChallengeResolution(repository, null, () -> null, () -> store, null, null, null);
        when(repository.getActionFromHash(USER)).thenReturn(ZeroTrustAction.CHALLENGE);
    }

    @Test
    void aReleasedChallengeIsKeptAsAFactOfTheContextTheClientGoesOnIn() {
        assertThat(resolution.releaseChallenge(USER, CONTEXT, request, null)).isTrue();

        verify(store).markChallengeVerified(eq(USER), eq(CONTEXT), any(Instant.class));
    }

    @Test
    void aStepUpPassedAfterTheChallengeEndedIsAFactAsWell() {
        when(repository.getActionFromHash(USER)).thenReturn(null);

        assertThat(resolution.releaseChallenge(USER, CONTEXT, request, null)).isTrue();

        verify(store).markChallengeVerified(eq(USER), eq(CONTEXT), any(Instant.class));
    }

    @Test
    void anEscalateIsNotReleasedAndLeavesNoFact() {
        when(repository.getActionFromHash(USER)).thenReturn(ZeroTrustAction.ESCALATE);

        assertThat(resolution.releaseChallenge(USER, CONTEXT, request, null)).isFalse();

        verify(store, never()).markChallengeVerified(any(), any(), any());
    }

    @Test
    void aStoreThatFailsDoesNotUndoTheRelease() {
        doThrow(new IllegalStateException("store")).when(store).markChallengeVerified(any(), any(), any());

        assertThat(resolution.releaseChallenge(USER, CONTEXT, request, null)).isTrue();

        verify(repository).saveActionWithPrevious(USER, ZeroTrustAction.ALLOW, CONTEXT);
    }
}
