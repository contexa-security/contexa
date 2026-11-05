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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

/**
 * What of a request may leave the running application (Q-11): the records, the vector store and the model's input keep
 * the facts a decision reads and not the values that open something. A live session id signs its owner in, so it stays
 * in the event and the session stores, and whatever is kept names the session by a reference: two records of one session
 * carry the same reference, and the reference opens nothing. A query keeps the names of its parameters, not their values;
 * a reference tells one query from another for as long as this process runs.
 */
public final class RequestFactRedaction {

    /** The event's fact that holds a query's reference. */
    public static final String QUERY_REFERENCE = "queryReference";

    /** How a reference starts, which tells a value that already is one. */
    static final String SESSION_REFERENCE_PREFIX = "sid-";

    private static final int SESSION_REFERENCE_BYTES = 12;
    private static final String QUERY_REFERENCE_PREFIX = "qry-";
    private static final String QUERY_REFERENCE_ALGORITHM = "HmacSHA256";
    /** This process's own: a value short enough to guess ({@code pin=1234}) cannot be tried against a reference. */
    private static final byte[] QUERY_REFERENCE_KEY = randomKey();

    /** A reference as this class writes it: a session id that only starts alike is still a session id. */
    private static final Pattern SESSION_REFERENCE =
            Pattern.compile(SESSION_REFERENCE_PREFIX + "[0-9a-f]{" + SESSION_REFERENCE_BYTES * 2 + "}");

    private RequestFactRedaction() {
    }

    /** The reference of a session, the same for the same session; a reference stays as it is; null without a session. */
    @Nullable
    public static String sessionReference(@Nullable String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return null;
        }
        String id = sessionId.trim();
        if (SESSION_REFERENCE.matcher(id).matches()) {
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

    /**
     * A reference of a whole query, values included: the same query has the same reference in this process, and another
     * process reads another one. It tells nothing of the values. Null without a query.
     */
    @Nullable
    public static String queryReference(@Nullable String queryString) {
        if (!StringUtils.hasText(queryString)) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance(QUERY_REFERENCE_ALGORITHM);
            mac.init(new SecretKeySpec(QUERY_REFERENCE_KEY, QUERY_REFERENCE_ALGORITHM));
            byte[] keyed = mac.doFinal(queryString.getBytes(StandardCharsets.UTF_8));
            return QUERY_REFERENCE_PREFIX + HexFormat.of().formatHex(keyed, 0, SESSION_REFERENCE_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(QUERY_REFERENCE_ALGORITHM + " is not available", e);
        }
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }
}
