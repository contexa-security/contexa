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
package io.contexa.contexaiam.admin.promptquality.report;

import org.springframework.lang.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The masking of one quality report (quality plan 3.2: a case of the operation holds a real user, addresses and the
 * user's baseline, and is masked when it is exported).
 *
 * <ul>
 * <li>The person a decision or a case is about is named by a pseudonym: a keyed hash of the identifier under a key
 * drawn at random for this report and never written. The same person is the same pseudonym within the report, so its
 * decisions can be counted together, and another pseudonym in the next one; without the key no list of identifiers
 * can be hashed to find who it is.</li>
 * <li>A free text an administrator wrote (a reason, a note, a rationale, a title, a failure) is kept, since who did
 * what and why is the evidence, with every known identifier of such a person replaced by its pseudonym and every
 * e-mail address and IP address replaced by a mark.</li>
 * <li>What is never read into the report is not masked here: the input of a case (its context, request facts,
 * authentication state, baselines and past records), the rationale of a case, a decision's request, path, address,
 * session or summary, and the note an administrator wrote on an overturned decision.</li>
 * </ul>
 * The administrators who acted are named as they are: the report is the record of who approved what.
 */
final class QualityReportMasking {

    /** What starts a pseudonym. */
    static final String SUBJECT_PREFIX = "subject-";
    /** What an e-mail address is replaced by. */
    static final String EMAIL_MARK = "[email]";
    /** What an IP address is replaced by. */
    static final String ADDRESS_MARK = "[ip]";
    /** The longest free text kept; a longer one is cut. */
    static final int TEXT_LIMIT = 2000;

    /** The rules, as the report names them. */
    static final List<String> RULES = List.of("SUBJECT_PSEUDONYM_KEYED_PER_REPORT", "FREE_TEXT_SUBJECTS_REPLACED",
            "FREE_TEXT_EMAIL_REPLACED", "FREE_TEXT_IP_REPLACED", "CASE_INPUT_OMITTED", "CASE_RATIONALE_OMITTED",
            "BASELINE_OMITTED", "REQUEST_OMITTED", "DECISION_NOTE_OMITTED");

    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern IPV4 = Pattern.compile("(?<![0-9.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9])");
    /** Three colons or more, or a double colon, among hexadecimal groups: times (two colons) are not taken. */
    private static final Pattern IPV6 = Pattern.compile(
            "(?i)(?<![0-9a-f:])(?:(?:[0-9a-f]{0,4}:){3,7}[0-9a-f]{0,4}|[0-9a-f]{0,4}::[0-9a-f]{0,4})(?![0-9a-f:])");
    private static final int PSEUDONYM_BYTES = 8;

    private final byte[] key;
    private final Map<String, String> pseudonyms = new LinkedHashMap<>();
    private final Set<String> known = new LinkedHashSet<>();
    private Pattern knownPattern;
    private int scrubbed;

    QualityReportMasking(SecureRandom random) {
        this.key = new byte[32];
        random.nextBytes(key);
    }

    /** The pseudonym of the person; null for none. */
    @Nullable
    String subject(@Nullable String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return null;
        }
        String id = identifier.trim();
        know(List.of(id));
        return pseudonyms.computeIfAbsent(id, this::pseudonym);
    }

    /** Persons whose identifiers are replaced in the free texts, though the report does not name them itself. */
    void know(Collection<String> identifiers) {
        boolean added = false;
        for (String identifier : identifiers) {
            if (identifier != null && !identifier.isBlank() && known.add(identifier.trim())) {
                added = true;
            }
        }
        if (added) {
            knownPattern = null;
        }
    }

    /** The free text with the persons, e-mail addresses and IP addresses replaced; null for none. */
    @Nullable
    String text(@Nullable String text) {
        if (text == null) {
            return null;
        }
        String result = text.length() > TEXT_LIMIT ? text.substring(0, TEXT_LIMIT) : text;
        String before = result;
        Pattern persons = knownPattern();
        if (persons != null) {
            Matcher matcher = persons.matcher(result);
            StringBuilder replaced = new StringBuilder();
            while (matcher.find()) {
                matcher.appendReplacement(replaced, Matcher.quoteReplacement(subject(matcher.group())));
            }
            matcher.appendTail(replaced);
            result = replaced.toString();
        }
        result = EMAIL.matcher(result).replaceAll(Matcher.quoteReplacement(EMAIL_MARK));
        result = IPV4.matcher(result).replaceAll(Matcher.quoteReplacement(ADDRESS_MARK));
        result = IPV6.matcher(result).replaceAll(Matcher.quoteReplacement(ADDRESS_MARK));
        if (!result.equals(before)) {
            scrubbed++;
        }
        return result;
    }

    /** The distinct persons named by a pseudonym. */
    int subjects() {
        return pseudonyms.size();
    }

    /** The free texts in which something was replaced. */
    int scrubbedTexts() {
        return scrubbed;
    }

    /** The known identifiers, the longest first, each standing alone (not inside a longer word). */
    @Nullable
    private Pattern knownPattern() {
        if (known.isEmpty()) {
            return null;
        }
        if (knownPattern == null) {
            List<String> sorted = new ArrayList<>(known);
            sorted.sort(Comparator.comparingInt(String::length).reversed());
            StringBuilder alternatives = new StringBuilder();
            for (String identifier : sorted) {
                if (!alternatives.isEmpty()) {
                    alternatives.append('|');
                }
                alternatives.append(Pattern.quote(identifier));
            }
            knownPattern = Pattern.compile("(?<![\\p{L}\\p{N}_.@-])(?:" + alternatives + ")(?![\\p{L}\\p{N}_@-])");
        }
        return knownPattern;
    }

    private String pseudonym(String identifier) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] digest = mac.doFinal(identifier.getBytes(StandardCharsets.UTF_8));
            byte[] head = new byte[PSEUDONYM_BYTES];
            System.arraycopy(digest, 0, head, 0, PSEUDONYM_BYTES);
            return SUBJECT_PREFIX + HexFormat.of().formatHex(head);
        }
        catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("HmacSHA256 is not available", unavailable);
        }
    }
}
