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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Map;

/**
 * Turns the tracked sessions a database kept under their raw identifiers into their references
 * ({@link RequestFactRedaction#sessionReference}), the value the console shows and the audit names. The raw value is
 * what a session's cookie carries, so it is not kept. A session forced out stays forced out: when a row of its
 * reference was written meanwhile, the two are merged and either one forced out forces the session out. It runs at
 * every start and moves nothing once every row is a reference.
 */
@Slf4j
public class ActiveSessionReferences {

    /** The rows whose identifier is not a reference: the references are {@code sid-} and 24 hexadecimal digits. */
    private static final String RAW_ROWS = "select session_id, expired from ctxa_active_sessions "
            + "where session_id !~ '^sid-[0-9a-f]{24}$'";

    private final JdbcOperations jdbc;

    public ActiveSessionReferences(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Moves the rows at the start of the application. A database that cannot be read now stops nothing: the rows stay
     * where they are, and the next start moves them.
     */
    public void atStart() {
        try {
            referenceStoredSessions();
        } catch (RuntimeException e) {
            log.error("[SessionManagement] The tracked sessions kept under their raw identifiers could not be moved to "
                    + "their references; a session forced out before stays out only once they are: {}", e.toString());
        }
    }

    /** @return how many tracked sessions were turned into their references */
    public int referenceStoredSessions() {
        List<Map<String, Object>> raw = jdbc.queryForList(RAW_ROWS);
        int moved = 0;
        for (Map<String, Object> row : raw) {
            String sessionId = (String) row.get("session_id");
            String reference = RequestFactRedaction.sessionReference(sessionId);
            if (reference == null || reference.equals(sessionId)) {
                continue;
            }
            boolean forcedOut = Boolean.TRUE.equals(row.get("expired"));
            List<Boolean> referenced = jdbc.queryForList(
                    "select expired from ctxa_active_sessions where session_id = ?", Boolean.class, reference);
            if (referenced.isEmpty()) {
                jdbc.update("update ctxa_active_sessions set session_id = ? where session_id = ?", reference, sessionId);
            } else {
                if (forcedOut) {
                    jdbc.update("update ctxa_active_sessions set expired = true where session_id = ?", reference);
                }
                jdbc.update("delete from ctxa_active_sessions where session_id = ?", sessionId);
            }
            moved++;
        }
        if (moved > 0) {
            log.info("[SessionManagement] {} tracked session(s) kept under their raw identifiers are now kept under "
                    + "their references", moved);
        }
        return moved;
    }
}
