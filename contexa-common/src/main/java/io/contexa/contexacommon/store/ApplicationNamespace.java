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
package io.contexa.contexacommon.store;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/**
 * Which application's state a Redis key, a Kafka topic or a Kafka consumer group belongs to, for applications that share
 * one Redis and one Kafka cluster.
 * <p>
 * The identifier is the application's {@code spring.application.name}, normalized (see {@link #normalize}); it is bound
 * once at the start. An application with a name keeps everything Contexa writes to Redis under {@code ctxa:<name>:}, so
 * a block, a session or a decision of one application is never read by another, while the servers of one application
 * (the same name) share all of it. An application without a name keeps the keys it always had. Contexa's Kafka topics
 * are {@code ctxa.<name>.} and the topic's name, or {@code ctxa.} and the topic's name without a name of the application
 * (see {@link #topic}).
 * <p>
 * This class is the only place that builds the namespace: every key, pattern, lock name and channel Contexa uses goes
 * through {@link #key}, and every topic through {@link #topic}. The prefix is made of characters that mean nothing in a
 * glob pattern, so a key and a SCAN pattern are qualified the same way.
 */
public final class ApplicationNamespace {

    /** What every key of a named application starts with. */
    public static final String PREFIX = "ctxa:";

    /** What the name of every Kafka topic Contexa uses starts with, with or without a name of the application. */
    public static final String TOPIC_PREFIX = "ctxa.";

    /** The longest identifier; a longer name is cut and ends in a digest of the whole, so that two long names differ. */
    public static final int MAX_IDENTIFIER_LENGTH = 48;

    private static final int DIGEST_CHARACTERS = 12;
    private static final char ESCAPE = '~';
    private static final String KEPT_PUNCTUATION = "._-";
    private static final char TOPIC_ESCAPE = '_';
    private static final String KEPT_TOPIC_PUNCTUATION = "-";

    private static final Naming UNNAMED = new Naming("", "", TOPIC_PREFIX);
    private static volatile Naming current = UNNAMED;

    private ApplicationNamespace() {
    }

    /** The identifier of this application, or the empty string when it has no name. */
    public static String identifier() {
        return current.identifier();
    }

    public static boolean isNamed() {
        return !current.identifier().isEmpty();
    }

    /**
     * A key, a pattern, a lock name or a channel as this application keeps it: {@code ctxa:<identifier>:} before the name
     * the key has always had, and the name unchanged for an application without a name.
     */
    public static String key(String key) {
        Objects.requireNonNull(key, "key");
        Naming naming = current;
        return naming.keyPrefix().isEmpty() ? key : naming.keyPrefix() + key;
    }

    /**
     * A key exactly as an application without a name keeps it, for the one purpose of finding what was kept before the
     * application had a name. It changes nothing; it says, where it stands, that the key is deliberately not this
     * application's own.
     */
    public static String withoutName(String key) {
        return Objects.requireNonNull(key, "key");
    }

    /** The Kafka consumer group of this application: the group with the identifier after it, or the group as it is. */
    public static String consumerGroup(String group) {
        Objects.requireNonNull(group, "group");
        Naming naming = current;
        return naming.identifier().isEmpty() ? group : group + "." + naming.identifier();
    }

    /**
     * A Kafka topic of Contexa's as this application names it: {@code ctxa.<topic identifier>.} before the name the topic
     * has always had (see {@link #topicIdentifier}), or {@code ctxa.} alone for an application without a name. The prefix
     * keeps Contexa's topics apart from those of the other applications on the cluster, whose names Contexa cannot know,
     * and the topics of two applications with different names apart from each other. A name the operator set for a topic
     * is not given to this: it is used as it is.
     */
    public static String topic(String name) {
        Objects.requireNonNull(name, "name");
        return current.topicPrefix() + name;
    }

    /**
     * Binds the name of the application ({@code spring.application.name}); a missing or blank name leaves the
     * application without one.
     */
    public static void configure(String applicationName) {
        String identifier = normalize(applicationName);
        current = identifier.isEmpty() ? UNNAMED : new Naming(identifier, PREFIX + identifier + ":",
                TOPIC_PREFIX + topicIdentifier(applicationName) + ".");
    }

    /**
     * Binds a name until the returned scope is closed, then restores what was bound before. For tests and for a process
     * that runs several applications one after another; a running application binds its name once, at the start.
     */
    public static Scope using(String applicationName) {
        Naming previous = current;
        configure(applicationName);
        return () -> current = previous;
    }

    /**
     * The identifier of an application name: lower case, with the characters {@code a-z 0-9 . _ -} kept and every other
     * byte of its UTF-8 form written as {@code ~} and two hex digits, which keeps two different names different and keeps
     * {@code :}, {@code *} and the other characters that mean something in a key out of the identifier. A name longer than
     * {@value #MAX_IDENTIFIER_LENGTH} characters is cut and ends in a digest of the whole. A missing or blank name gives
     * the empty string.
     */
    public static String normalize(String applicationName) {
        return identifierOf(applicationName, KEPT_PUNCTUATION, ESCAPE);
    }

    /**
     * The identifier of an application name in a Kafka topic, by the rule of {@link #normalize} with fewer characters
     * kept: a topic name holds only {@code a-z A-Z 0-9 . _ -}, the {@code .} after the identifier is where it ends, and
     * Kafka takes {@code .} and {@code _} for one character when it compares topic names. So {@code a-z 0-9 -} are kept and
     * every other byte is written as {@code _} and two hex digits: two different names stay different to Kafka too, and
     * the identifier holds no {@code .}, so the topics of one application never fall under the name of another. The length
     * is cut as in {@link #normalize}. A missing or blank name gives the empty string.
     */
    public static String topicIdentifier(String applicationName) {
        return identifierOf(applicationName, KEPT_TOPIC_PUNCTUATION, TOPIC_ESCAPE);
    }

    private static String identifierOf(String applicationName, String keptPunctuation, char escape) {
        if (applicationName == null || applicationName.isBlank()) {
            return "";
        }
        byte[] bytes = applicationName.strip().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
        StringBuilder identifier = new StringBuilder(bytes.length);
        HexFormat hex = HexFormat.of();
        for (byte b : bytes) {
            char c = (char) (b & 0xff);
            if (b >= 0 && (c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || keptPunctuation.indexOf(c) >= 0)) {
                identifier.append(c);
            } else {
                identifier.append(escape).append(hex.toHexDigits(b));
            }
        }
        if (identifier.length() <= MAX_IDENTIFIER_LENGTH) {
            return identifier.toString();
        }
        String digest = digestOf(identifier.toString());
        return identifier.substring(0, MAX_IDENTIFIER_LENGTH - DIGEST_CHARACTERS - 1) + escape + digest;
    }

    private static String digestOf(String text) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, DIGEST_CHARACTERS / 2);
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is part of every Java platform", unavailable);
        }
    }

    /** The end of {@link #using}. */
    @FunctionalInterface
    public interface Scope extends AutoCloseable {

        @Override
        void close();
    }

    private record Naming(String identifier, String keyPrefix, String topicPrefix) {
    }
}
