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
package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionCleanupScheduler;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import jakarta.servlet.http.HttpSessionEvent;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** K73: a tracked session that ends is no longer active; one that ended without a word goes after its idle limit. */
class ActiveSessionEndListenerTest {

    private final SessionManagementService sessions = mock(SessionManagementService.class);
    private final ActiveSessionEndListener listener = new ActiveSessionEndListener(sessions);

    @Test
    void aTrackedSessionThatEndsIsMarkedExpired() {
        MockHttpSession session = new MockHttpSession(null, "sess-ended");
        session.setAttribute(SessionTrackingFilter.TRACKED_AT, 1L);

        listener.sessionDestroyed(new HttpSessionEvent(session));

        verify(sessions).markExpired("sess-ended");
    }

    @Test
    void anUntrackedSessionEndsWithoutAWrite() {
        listener.sessionDestroyed(new HttpSessionEvent(new MockHttpSession(null, "sess-anonymous")));

        verify(sessions, never()).markExpired(any());
    }

    @Test
    void aReplacedIdEndsTheOldRowAndTheSessionIsTrackedAgainAtOnce() {
        MockHttpSession session = new MockHttpSession(null, "sess-new");
        session.setAttribute(SessionTrackingFilter.TRACKED_AT, 1L);

        listener.sessionIdChanged(new HttpSessionEvent(session), "sess-old");

        verify(sessions).markExpired("sess-old");
        verify(sessions, never()).markExpired("sess-new");
        assertThat(session.getAttribute(SessionTrackingFilter.TRACKED_AT))
                .as("the next request tracks the new id without waiting for the throttle").isNull();
    }

    @Test
    void aDatabaseThatCannotBeWrittenDoesNotStopTheSessionsEnd() {
        MockHttpSession session = new MockHttpSession(null, "sess-ended");
        session.setAttribute(SessionTrackingFilter.TRACKED_AT, 1L);
        doThrow(new IllegalStateException("database down")).when(sessions).markExpired(any());

        listener.sessionDestroyed(new HttpSessionEvent(session));

        verify(sessions).markExpired("sess-ended");
    }

    @Test
    void theCleanupEndsTheSessionsIdleBeyondTheirLimitAndTheExpiredOnesPastTheirRetention() {
        when(sessions.endIdleSessions(any())).thenReturn(2);

        new ActiveSessionCleanupScheduler(sessions, Duration.ofMinutes(45)).cleanup();

        verify(sessions).endIdleSessions(Duration.ofMinutes(47));
        verify(sessions).cleanupExpiredSessions();
    }

    @Test
    void theContainersDefaultLimitWithoutOneAndNoneForSessionsThatNeverTimeOut() {
        new ActiveSessionCleanupScheduler(sessions, null).cleanup();
        verify(sessions).endIdleSessions(Duration.ofMinutes(32));

        SessionManagementService forever = mock(SessionManagementService.class);
        new ActiveSessionCleanupScheduler(forever, Duration.ZERO).cleanup();
        verify(forever).endIdleSessions(Duration.ZERO);
        verify(forever).cleanupExpiredSessions();
    }
}
