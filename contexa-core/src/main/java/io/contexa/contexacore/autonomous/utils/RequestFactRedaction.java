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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What of a request may leave the running application (Q-11): the records, the vector store and the model's input keep
 * the facts a decision reads and not the values that open something. A live session id signs its owner in, so it stays
 * in the event and the session stores, and whatever is kept names the session by a reference: two records of one session
 * carry the same reference, and the reference opens nothing. A query keeps the names of its parameters, not their values;
 * a reference tells one query from another for as long as this process runs. What a person is asked to confirm is the
 * one exception: the values are what is confirmed, so only the ones that open something are masked.
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

    private static final String MASK = "[MASKED]";

    /** How often an escaped value is unescaped: a value can be escaped once for each hop it is forwarded through. */
    private static final int UNESCAPE_ROUNDS = 3;

    /** The words of a parameter's name that say its value opens something. */
    private static final Set<String> SECRET_WORDS = Set.of("auth", "authorization", "bearer", "cookie", "credential",
            "credentials", "cvc", "cvv", "jsessionid", "otp", "pass", "passcode", "passphrase", "passwd", "password", "pin",
            "pwd", "secret", "session", "sessionid", "sid", "sig", "signature", "ssn", "token");

    /** The same for a name written as one word ({@code accesstoken}): only how it ends tells. */
    private static final Pattern SECRET_NAME_ENDING =
            Pattern.compile(".*(accesskey|apikey|credentials?|passphrase|passcode|passwd|password|privatekey|pwd|secret|token)");

    private static final Pattern NAME_WORD_BREAK = Pattern.compile("[^\\p{Alnum}]+|(?<=\\p{Lower})(?=\\p{Upper})");

    /** A value that gives itself away: a signed token, a bearer value, a provider's key, a private key, a national id. */
    private static final Pattern SECRET_VALUE = Pattern.compile(String.join("|",
            "eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*",
            "(?i:bearer)[\\s+]+[A-Za-z0-9._~+/=-]{8,}",
            "sk-[A-Za-z0-9_-]{16,}",
            "AKIA[0-9A-Z]{16}",
            "gh[pousr]_[A-Za-z0-9]{20,}",
            "xox[abeoprs]-[A-Za-z0-9-]{10,}",
            "-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "(?<![0-9-])[0-9]{6}-[1-8][0-9]{6}(?![0-9-])",
            "(?<![0-9-])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9-])"));

    /** A path parameter: {@code ;jsessionid=...} rides on the path, up to the next one or the next segment. */
    private static final Pattern PATH_PARAMETER = Pattern.compile(";([^;/=]+)=([^;/]*)");

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
     * A request's path and query as a person reads them to confirm the request: as it came, but for the values that open
     * something, by the name of their parameter or by their own shape, an escaped or nested value included. Only what the
     * person reads changes: the request stays bound by its own hash.
     */
    @Nullable
    public static String readableTarget(@Nullable String target) {
        if (!StringUtils.hasText(target)) {
            return target;
        }
        int queryStart = target.indexOf('?');
        String path = queryStart < 0 ? target : target.substring(0, queryStart);
        return queryStart < 0 ? readablePath(path)
                : readablePath(path) + "?" + readableQuery(target.substring(queryStart + 1));
    }

    private static String readablePath(String path) {
        String masked = PATH_PARAMETER.matcher(path).replaceAll(parameter -> Matcher.quoteReplacement(
                secretName(parameter.group(1)) ? ";" + parameter.group(1) + "=" + MASK : parameter.group()));
        return SECRET_VALUE.matcher(masked).replaceAll(MASK);
    }

    private static String readableQuery(String query) {
        StringBuilder masked = new StringBuilder(query.length());
        int start = 0;
        for (int end = 0; end <= query.length(); end++) {
            if (end == query.length() || query.charAt(end) == '&' || query.charAt(end) == ';') {
                masked.append(readableParameter(query.substring(start, end)));
                if (end < query.length()) {
                    masked.append(query.charAt(end));
                }
                start = end + 1;
            }
        }
        return masked.toString();
    }

    private static String readableParameter(String parameter) {
        int nameEnd = parameter.indexOf('=');
        if (nameEnd < 0) {
            return secretValue(parameter) ? MASK : parameter;
        }
        String value = parameter.substring(nameEnd + 1);
        boolean secret = (nameEnd > 0 && secretName(parameter.substring(0, nameEnd))) || secretValue(value);
        return secret ? parameter.substring(0, nameEnd + 1) + MASK : parameter;
    }

    /** Whether the name says its value opens something; a name that cannot be read is taken for one that does. */
    private static boolean secretName(String name) {
        String readable = unescaped(name);
        if (readable == null) {
            return true;
        }
        String normalized = Normalizer.normalize(readable, Normalizer.Form.NFKC);
        for (String word : NAME_WORD_BREAK.split(normalized)) {
            if (SECRET_WORDS.contains(word.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        String oneWord = normalized.replaceAll("[^\\p{Alnum}]", "").toLowerCase(Locale.ROOT);
        return SECRET_NAME_ENDING.matcher(oneWord).matches();
    }

    /** Whether the value has the shape of a secret, or carries a parameter of its own that says it is one. */
    private static boolean secretValue(String value) {
        String readable = unescaped(value);
        String text = readable != null ? readable : value;
        if (SECRET_VALUE.matcher(text).find()) {
            return true;
        }
        for (String part : text.split("[?&;]")) {
            int nameEnd = part.indexOf('=');
            if (nameEnd > 0 && secretName(part.substring(0, nameEnd))) {
                return true;
            }
        }
        return false;
    }

    /** The text with its escapes undone, as often as they were applied; null when it does not unescape at all. */
    @Nullable
    private static String unescaped(String text) {
        String current = text;
        for (int round = 0; round < UNESCAPE_ROUNDS; round++) {
            String next;
            try {
                next = URLDecoder.decode(current, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                return round == 0 ? null : current;
            }
            if (next.equals(current)) {
                break;
            }
            current = next;
        }
        return current;
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
