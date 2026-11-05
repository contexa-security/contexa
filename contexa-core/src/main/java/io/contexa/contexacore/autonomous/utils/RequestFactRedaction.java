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
package io.contexa.contexacore.autonomous.utils;

import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * What of a request may leave the running application (Q-11): the records, the vector store and the model's input keep
 * the facts a decision reads and not the values that open something. A live session id signs its owner in, so it stays
 * in the event and the session stores, and whatever is kept names the session by a reference: two records of one session
 * carry the same reference, and the reference opens nothing. A query keeps the names of its parameters, not their values.
 */
public final class RequestFactRedaction {

    /** How a reference starts, which tells a value that already is one. */
    static final String SESSION_REFERENCE_PREFIX = "sid-";

    private static final int SESSION_REFERENCE_BYTES = 12;

    private RequestFactRedaction() {
    }

    /** The reference of a session, the same for the same session; a reference stays as it is; null without a session. */
    @Nullable
    public static String sessionReference(@Nullable String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return null;
        }
        String id = sessionId.trim();
        if (id.startsWith(SESSION_REFERENCE_PREFIX)) {
            return id;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.UTF_8));
            return SESSION_REFERENCE_PREFIX + HexFormat.of().formatHex(digest, 0, SESSION_REFERENCE_BYTES);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /**
     * The names of a query's parameters, joined as the query joins them ({@code pin&newPwd}), in their order and as many
     * times as they came; null when none is left. A part without {@code =} is left out: it may be the value itself.
     */
    @Nullable
    public static String queryNames(@Nullable String queryString) {
        if (!StringUtils.hasText(queryString)) {
            return null;
        }
        List<String> names = new ArrayList<>();
        for (String part : queryString.split("&")) {
            int nameEnd = part.indexOf('=');
            if (nameEnd > 0) {
                names.add(part.substring(0, nameEnd));
            }
        }
        return names.isEmpty() ? null : String.join("&", names);
    }
}
