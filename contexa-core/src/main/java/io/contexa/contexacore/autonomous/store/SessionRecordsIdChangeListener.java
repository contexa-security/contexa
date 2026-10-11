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
package io.contexa.contexacore.autonomous.store;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import lombok.extern.slf4j.Slf4j;

/**
 * Carries a session's Zero Trust records to its new id when the servlet container replaces the id of the same session,
 * as session fixation protection does at sign-in and at a step-up MFA. Without it the next request of the session
 * reads nothing under the new id: it looks like the first request of a new session and the decisions that led to the
 * step-up (a challenge) are no longer part of the session.
 */
@Slf4j
public class SessionRecordsIdChangeListener implements HttpSessionIdListener {

    private final SecurityContextDataStore dataStore;

    public SessionRecordsIdChangeListener(SecurityContextDataStore dataStore) {
        this.dataStore = dataStore;
    }

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
        try {
            dataStore.moveSessionRecords(oldSessionId, event.getSession().getId());
        } catch (RuntimeException e) {
            log.error("[SessionRecordsIdChange] Failed to carry the session records to the new session id", e);
        }
    }
}
