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
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** W1-11: when the container replaces a session's id, the session's records move to the new id. */
class SessionRecordsIdChangeListenerTest {

    @Test
    void theRecordsMoveToTheNewId() {
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);

        new SessionRecordsIdChangeListener(dataStore)
                .sessionIdChanged(new HttpSessionEvent(new MockHttpSession(null, "session-new")), "session-old");

        verify(dataStore).moveSessionRecords("session-old", "session-new");
    }

    @Test
    void aFailedMoveDoesNotBreakTheIdChange() {
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        doThrow(new IllegalStateException("store down")).when(dataStore).moveSessionRecords("session-old", "session-new");

        new SessionRecordsIdChangeListener(dataStore)
                .sessionIdChanged(new HttpSessionEvent(new MockHttpSession(null, "session-new")), "session-old");

        verify(dataStore).moveSessionRecords("session-old", "session-new");
    }
}
