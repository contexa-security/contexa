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

import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionCleanupScheduler;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import jakarta.servlet.http.HttpSessionEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.time.Duration;
import java.util.Collections;

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
    private final TrackedSessionMarks marks = new TrackedSessionMarks();
    private final ActiveSessionEndListener listener = new ActiveSessionEndListener(sessions, marks);

    @Test
    void aTrackedSessionThatEndsIsMarkedExpired() {
        MockHttpSession session = new MockHttpSession(null, "sess-ended");
        marks.trackDue(RequestFactRedaction.sessionReference("sess-ended"));

        listener.sessionDestroyed(new HttpSessionEvent(session));

        verify(sessions).markExpired("sess-ended");
        assertThat(marks.trackDue(RequestFactRedaction.sessionReference("sess-ended")))
                .as("the marks of a session that ended go with it").isTrue();
    }

    /**
     * Sessions shared between nodes (Spring Session, distributed mode): the node a session ends on may not be the one that
     * tracked it. Its end is recorded by its row, not by what this node remembers.
     */
    @Test
    @DisplayName("다른 노드가 추적한 세션이 이 노드에서 끝나도 그 행을 끝낸다(분산 구성)")
    void aSessionAnotherNodeTrackedIsEndedWhereItEnds() {
        listener.sessionDestroyed(new HttpSessionEvent(new MockHttpSession(null, "sess-elsewhere")));

        verify(sessions).markExpired("sess-elsewhere");
    }

    @Test
    @DisplayName("다른 노드가 추적한 세션의 id가 이 노드에서 바뀌어도 옛 id의 행을 끝낸다(분산 구성)")
    void aReplacedIdOfASessionAnotherNodeTrackedEndsTheOldRow() {
        listener.sessionIdChanged(new HttpSessionEvent(new MockHttpSession(null, "sess-new")), "sess-elsewhere-old");

        verify(sessions).markExpired("sess-elsewhere-old");
        verify(sessions, never()).markExpired("sess-new");
    }

    @Test
    void aReplacedIdEndsTheOldRowAndTheSessionIsTrackedAgainAtOnce() {
        MockHttpSession session = new MockHttpSession(null, "sess-new");
        marks.trackDue(RequestFactRedaction.sessionReference("sess-old"));

        listener.sessionIdChanged(new HttpSessionEvent(session), "sess-old");

        verify(sessions).markExpired("sess-old");
        verify(sessions, never()).markExpired("sess-new");
        assertThat(marks.trackDue(RequestFactRedaction.sessionReference("sess-new")))
                .as("the next request tracks the new id without waiting for the throttle").isTrue();
        assertThat(marks.trackDue(RequestFactRedaction.sessionReference("sess-old"))).as("the old id's marks went").isTrue();
    }

    /** R-8: the end of a session is read from its id; nothing is read from or written into the application's session. */
    @Test
    @DisplayName("세션이 끝날 때 앱 세션의 값을 읽거나 지우지 않는다(R-8)")
    void theEndOfASessionLeavesTheApplicationsSessionAsItIs() {
        MockHttpSession session = new MockHttpSession(null, "sess-new");
        session.setAttribute("cart", "3 items");
        marks.trackDue(RequestFactRedaction.sessionReference("sess-old"));

        listener.sessionIdChanged(new HttpSessionEvent(session), "sess-old");

        assertThat(Collections.list(session.getAttributeNames())).containsExactly("cart");
    }

    @Test
    void aDatabaseThatCannotBeWrittenDoesNotStopTheSessionsEnd() {
        MockHttpSession session = new MockHttpSession(null, "sess-ended");
        marks.trackDue(RequestFactRedaction.sessionReference("sess-ended"));
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
