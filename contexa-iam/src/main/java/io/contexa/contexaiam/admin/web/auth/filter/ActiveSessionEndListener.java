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

import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;
import lombok.extern.slf4j.Slf4j;

/**
 * K73: a tracked session that ends is no longer active. The servlet container destroys an HTTP session at a logout, at
 * its idle limit and when the application invalidates it, and replaces its id when the person signs in again; the row
 * the session was tracked under is marked expired then, so the console counts and lists only the sessions that are.
 * Whether the session has such a row is the database's answer, not this node's: where nodes share their sessions, the
 * node a session ends on may not be the one that tracked it. The end is one update of the row by the session's
 * reference, which changes nothing for a session that has none. A session whose id was replaced is tracked again under
 * its new id at its next request. Only the session's id is read, and nothing is written into the session.
 */
@Slf4j
public class ActiveSessionEndListener implements HttpSessionListener, HttpSessionIdListener {

    private final SessionManagementService sessionManagementService;
    /** The marks {@link SessionTrackingFilter} keeps of the sessions it tracks; they go with the session. */
    private final TrackedSessionMarks marks;

    public ActiveSessionEndListener(SessionManagementService sessionManagementService, TrackedSessionMarks marks) {
        this.sessionManagementService = sessionManagementService;
        this.marks = marks;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        String sessionId = idOf(event.getSession());
        forget(sessionId);
        end(sessionId);
    }

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
        forget(oldSessionId);
        end(oldSessionId);
    }

    private void forget(String sessionId) {
        String reference = RequestFactRedaction.sessionReference(sessionId);
        if (reference != null) {
            marks.forget(reference);
        }
    }

    private static String idOf(HttpSession session) {
        try {
            return session != null ? session.getId() : null;
        } catch (IllegalStateException invalidated) {
            return null;
        }
    }

    private void end(String sessionId) {
        if (sessionId == null) {
            return;
        }
        // Contexa's own work beside the application's: bounded as the tracking filter's is
        RequestPathScope.enter();
        try {
            sessionManagementService.markExpired(sessionId);
        } catch (RuntimeException e) {
            // the tracked sessions live in Contexa's database: the periodic cleanup ends the row when this cannot
            log.warn("The end of a tracked session could not be recorded; the periodic cleanup ends it: {}",
                    e.toString());
        } finally {
            RequestPathScope.leave();
        }
    }
}
