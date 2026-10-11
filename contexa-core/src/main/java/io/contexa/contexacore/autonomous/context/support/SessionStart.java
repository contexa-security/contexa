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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacommon.domain.SecurityEvent;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * When the session of a request started, and on what basis: the session's sign-in time (LOGIN), else the servlet
 * session's creation time, which the publisher only passes when the event clock is the server clock (SESSION_CREATED).
 * When neither is known the session starts at its first analysed request (FIRST_ANALYSED_REQUEST), which the caller
 * keeps itself.
 */
public record SessionStart(Instant at, String basis) {

    public static final String LOGIN = "LOGIN";
    public static final String SESSION_CREATED = "SESSION_CREATED";
    public static final String FIRST_ANALYSED_REQUEST = "FIRST_ANALYSED_REQUEST";

    /** The start known from the event; null when the session can only be started at its first analysed request. */
    public static SessionStart of(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        if (metadata == null) {
            return null;
        }
        Instant signIn = instant(metadata.get("authenticationTime"));
        if (signIn != null) {
            return new SessionStart(signIn, LOGIN);
        }
        Instant created = instant(metadata.get("sessionCreatedAt"));
        return created != null ? new SessionStart(created, SESSION_CREATED) : null;
    }

    private static Instant instant(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochMilli(number.longValue());
        }
        if (value == null || value.toString().isBlank()) {
            return null;
        }
        String text = value.toString().trim();
        try {
            return Instant.parse(text);
        } catch (RuntimeException ignored) {
            try {
                return OffsetDateTime.parse(text).toInstant();
            } catch (RuntimeException alsoIgnored) {
                return null;
            }
        }
    }
}
