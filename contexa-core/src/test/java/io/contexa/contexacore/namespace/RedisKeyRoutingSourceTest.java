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
package io.contexa.contexacore.namespace;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The names Contexa gives in Redis and Kafka are the application's own, and nothing in the sources of the five modules
 * makes one that skips that: a source of the main code that uses a Redis client is on a list that says whether it makes
 * keys, a key it makes goes through the namespace, and a literal that looks like a key is never handed to Redis as it is.
 * A new class that uses Redis, or a new key literal, fails here until it is routed or listed with its reason.
 */
class RedisKeyRoutingSourceTest {

    private static final List<String> MODULES = List.of("contexa-common", "contexa-core", "contexa-identity", "contexa-iam",
            "contexa-autoconfigure");

    /** What routes a name through the namespace: the class itself, the key builders, or the cache settings that wrap it. */
    private static final List<String> ROUTES = List.of("ApplicationNamespace.", "ZeroTrustRedisKeys.", "qualifiedKeyPrefix(",
            "qualifiedChannel(", "SecurityEventOrigin.");

    /** A statement that makes the name of a key through the namespace. */
    private static final List<String> QUALIFIERS = List.of("ApplicationNamespace.", "qualified(");

    /** The classes that use a Redis client and make a key, a lock name or a channel. */
    private static final Set<String> KEY_MAKERS = Set.of(
            "RedisBaselineDataStore", "BlockingDecisionRegistry", "RedisProtectableRapidReentryRepository",
            "ZeroTrustActionRedisRepository", "RedisBlockMfaStateStore", "RedisSecurityContextDataStore",
            "RedisThreatScoreUtil", "PolicyReloadBroadcaster", "RedisDistributedLockService", "UnifiedRedisConfiguration",
            "RedisSessionIdGenerator", "RedisMfaRepository", "RedisAsyncSecurityContextProvider",
            "RedisZeroTrustSecurityService", "MfaStateMachineServiceImpl", "RedisStepUpOptionsStore",
            "RedisContexaCacheService", "ContexaCacheAutoConfiguration");

    /** The classes that name a Redis client and make no key: they build the clients, hand them over, or read a host's own key. */
    private static final Map<String, String> NO_KEYS = Map.ofEntries(
            Map.entry("CoreAutonomousAutoConfiguration", "wires stores to their templates"),
            Map.entry("CoreAutonomousEventAutoConfiguration", "wires the block registry to Redisson"),
            Map.entry("CoreInfrastructureAutoConfiguration", "wires the template"),
            Map.entry("CoreSessionAutoConfiguration", "wires the MFA session repository"),
            Map.entry("IamSecurityCoreAutoConfiguration", "wires stores to their templates"),
            Map.entry("IamAiamWebAutoConfiguration", "wires the block MFA store"),
            Map.entry("IamXacmlPapAutoConfiguration", "wires the policy reload broadcaster"),
            Map.entry("IdentityStateMachineAutoConfiguration", "wires the state machine; the keyspaces are ApplicationStateMachineKeyspaces"),
            Map.entry("StepUpOptionsStoreAutoConfiguration", "wires the step-up store"),
            Map.entry("CommonRedisAutoConfiguration", "builds the templates"),
            Map.entry("ContexaRedisRequestPath", "the connections of the request path"),
            Map.entry("RedisClusterNotice", "a notice at the start"),
            Map.entry("WatchedRedisTemplate", "a template that watches its waits"),
            Map.entry("WatchedStringRedisTemplate", "a template that watches its waits"),
            Map.entry("RedissonConfiguration", "builds the Redisson client"),
            Map.entry("ZeroTrustRedisConfig", "builds the connection and a template"),
            Map.entry("RedisSessionIdResolver", "reads the Spring Session key of the host application, which is the host's own"));

    /**
     * The sources whose key-like literals are not keys Contexa writes: defaults of properties that nothing reads, the
     * in-memory persist, the host's own Spring Session key, and the cache properties whose readers qualify them.
     */
    private static final Map<String, String> LITERALS_THAT_ARE_NOT_KEYS = Map.ofEntries(
            Map.entry("SecurityRedisProperties", "channel and stream defaults that no code reads"),
            Map.entry("SecurityPlaneProperties", "channel defaults that no code reads"),
            Map.entry("SecuritySessionProperties", "a channel default that no code reads"),
            Map.entry("MfaSettings", "a key prefix default that no code reads"),
            Map.entry("StateMachineProperties", "a key prefix default that no code reads"),
            Map.entry("InMemoryStateMachinePersist", "keys of a map in memory"),
            Map.entry("ContexaCacheProperties", "defaults read through qualifiedKeyPrefix and qualifiedChannel"),
            Map.entry("RedisSessionIdResolver", "the host's Spring Session key"),
            Map.entry("ZeroTrustChallengeFilter", "names a lock to the DistributedLockService, whose Redis form qualifies it"));

    private static final Pattern REDIS_CLIENT = Pattern.compile("\\b(RedisTemplate|StringRedisTemplate|RedissonClient|"
            + "RedisConnectionFactory|RedisMessageListenerContainer|ChannelTopic|RTopic|RLock|RedisConnection|"
            + "ReactiveRedis\\w*|RedisOperations)\\b");

    /** A literal that names a Redis key, a lock or a channel of Contexa. */
    private static final Pattern KEY_LIKE = Pattern.compile("^(security|threat_score|mfa|mfa_lock|contexa|async|distributed|soar):"
            + "|^RedisRepository");

    /** The key builders write their keys as formats that start with the namespace of the old keys. */
    private static final Pattern KEY_FORMAT = Pattern.compile("^%s:");

    private static final Pattern CONSTANT = Pattern.compile("\\b((?:public|protected|private)\\s+)?static\\s+final\\s+String\\s+(\\w+)\\s*=\\s*\"$");

    @Test
    @DisplayName("every main class that names a Redis client is on the list of those that make keys or of those that make none")
    void everyClassUsingARedisClientIsClassified() {
        Set<String> found = new TreeSet<>();
        for (Source source : sources()) {
            if (REDIS_CLIENT.matcher(source.codeWithoutImports()).find()) {
                found.add(source.name());
            }
        }
        Set<String> known = new TreeSet<>(KEY_MAKERS);
        known.addAll(NO_KEYS.keySet());

        Set<String> unclassified = new TreeSet<>(found);
        unclassified.removeAll(known);
        Set<String> gone = new TreeSet<>(known);
        gone.removeAll(found);
        assertThat(unclassified).as("classes that use Redis and are on neither list: route their names through ApplicationNamespace "
                + "and add them to KEY_MAKERS, or add them to NO_KEYS with the reason they make no key").isEmpty();
        assertThat(gone).as("classes on the lists that no longer use a Redis client").isEmpty();
    }

    @Test
    @DisplayName("every class that makes keys reaches the namespace")
    void everyKeyMakerReachesTheNamespace() {
        for (Source source : sources()) {
            if (KEY_MAKERS.contains(source.name())) {
                assertThat(ROUTES.stream().anyMatch(source.code()::contains))
                        .as("%s makes keys but does not reach ApplicationNamespace, ZeroTrustRedisKeys or the qualified cache settings", source.name())
                        .isTrue();
            }
        }
    }

    @Test
    @DisplayName("a literal that looks like a key is handed to the namespace in the statement that makes the key, or is a constant used only so")
    void noKeyLiteralReachesRedisAsItIs() {
        List<Source> sources = sources();
        Map<String, Source> publicConstants = new LinkedHashMap<>();
        List<String> problems = new ArrayList<>();
        int keyLikeLiterals = 0;

        for (Source source : sources) {
            if (LITERALS_THAT_ARE_NOT_KEYS.containsKey(source.name())) {
                continue;
            }
            for (Literal literal : source.literals()) {
                boolean keyLike = KEY_LIKE.matcher(literal.content()).find()
                        || source.name().equals("ZeroTrustRedisKeys") && KEY_FORMAT.matcher(literal.content()).find();
                if (!keyLike) {
                    continue;
                }
                keyLikeLiterals++;
                String statement = source.statementAround(literal.start());
                if (QUALIFIERS.stream().anyMatch(statement::contains)) {
                    continue;
                }
                Matcher constant = CONSTANT.matcher(source.statementBefore(literal.start()));
                if (!constant.find()) {
                    problems.add(source.name() + ": the key literal \"" + literal.content() + "\" is not made through the namespace");
                    continue;
                }
                String constantName = constant.group(2);
                if (constant.group(1) != null && constant.group(1).startsWith("public")) {
                    publicConstants.put(constantName, source);
                }
                problems.addAll(source.usesOutsideTheNamespace(constantName, literal.start()));
            }
        }
        for (Map.Entry<String, Source> constant : publicConstants.entrySet()) {
            for (Source source : sources) {
                if (source != constant.getValue()) {
                    problems.addAll(source.usesOutsideTheNamespace(constant.getKey(), -1));
                }
            }
        }

        assertThat(keyLikeLiterals).as("key-like literals found in the sources").isGreaterThan(20);
        assertThat(problems).isEmpty();
    }

    @Test
    @DisplayName("nobody reads the cache prefix or the invalidation channel without the namespace")
    void theCacheSettingsAreReadQualified() {
        for (Source source : sources()) {
            if (source.name().equals("ContexaCacheProperties")) {
                continue;
            }
            assertThat(source.code()).as(source.name()).doesNotContain(".getKeyPrefix()")
                    .doesNotContain("getPubsub().getChannel()");
        }
    }

    @Test
    @DisplayName("Kafka: every listener names a group through the namespace, and every send goes through SecurityEventOrigin")
    void kafkaGroupsAndSendsGoThroughTheNamespace() {
        for (Source source : sources()) {
            Matcher listener = Pattern.compile("@KafkaListener\\s*\\(").matcher(source.code());
            for (Source ignored : List.of(source)) {
                while (listener.find()) {
                    String declaration = source.rawFrom(listener.start(), 700);
                    assertThat(declaration).as("%s: a @KafkaListener must name a group through ApplicationNamespace.consumerGroup",
                            source.name()).contains("ApplicationNamespace).consumerGroup(");
                }
            }
            if (!source.name().equals("SecurityEventOrigin")) {
                assertThat(source.code()).as("%s sends to Kafka through SecurityEventOrigin.send", source.name())
                        .doesNotContain("kafkaTemplate.send(").doesNotContain("KafkaTemplate.send(");
            }
        }
    }

    private static List<Source> sources() {
        Path root = Path.of("").toAbsolutePath().getParent();
        List<Source> sources = new ArrayList<>();
        for (String module : MODULES) {
            Path main = root.resolve(module).resolve("src/main/java");
            assertThat(main).as("the sources of %s next to this module", module).isDirectory();
            try (Stream<Path> files = Files.walk(main)) {
                for (Path file : files.filter(path -> path.toString().endsWith(".java")).sorted().collect(Collectors.toList())) {
                    sources.add(new Source(file));
                }
            } catch (IOException failure) {
                throw new UncheckedIOException(failure);
            }
        }
        assertThat(sources).as("sources of the five modules").hasSizeGreaterThan(2500);
        return sources;
    }

    private record Literal(int start, String content, int rawLength) {
    }

    /** A source file with comments blanked, and the string literals found. */
    private static final class Source {

        private final Path path;
        private final String raw;
        /** Comments and the content of literals blanked, so that a ';' or a '{' inside either is nothing. */
        private final String masked;
        private final List<Literal> literals = new ArrayList<>();

        Source(Path path) {
            this.path = path;
            try {
                this.raw = Files.readString(path, StandardCharsets.UTF_8);
            } catch (IOException failure) {
                throw new UncheckedIOException(failure);
            }
            this.masked = mask(raw);
        }

        String name() {
            String file = path.getFileName().toString();
            return file.substring(0, file.length() - ".java".length());
        }

        List<Literal> literals() {
            return literals;
        }

        /** The code with comments and the content of literals blanked. */
        String code() {
            return masked;
        }

        /** The code with the content of literals kept and comments blanked, from a position on. */
        String rawFrom(int start, int length) {
            return codeKeepingLiterals().substring(start, Math.min(raw.length(), start + length));
        }

        String codeWithoutImports() {
            return masked.lines().filter(line -> !line.strip().startsWith("import ")).collect(Collectors.joining("\n"));
        }

        String statementAround(int position) {
            return masked.substring(statementStart(position), statementEnd(position));
        }

        String statementBefore(int position) {
            return masked.substring(statementStart(position), position);
        }

        /**
         * The uses of a constant that are not in a statement made through the namespace. A constant of another class is
         * used as {@code Owner.NAME}; one of this class by its name.
         */
        List<String> usesOutsideTheNamespace(String constant, int declaredAt) {
            List<String> problems = new ArrayList<>();
            String name = Pattern.quote(constant);
            Matcher use = Pattern.compile(declaredAt >= 0 ? "\\b" + name + "\\b" : "\\b[A-Z]\\w*\\." + name + "\\b")
                    .matcher(masked);
            while (use.find()) {
                if (declaredAt >= 0 && statementStart(use.start()) == statementStart(declaredAt)) {
                    continue;
                }
                String statement = statementAround(use.start());
                if (QUALIFIERS.stream().noneMatch(statement::contains)) {
                    problems.add(name() + ": " + constant + " holds a key and is used outside the namespace: "
                            + statement.strip().replaceAll("\\s+", " "));
                }
            }
            return problems;
        }

        private int statementStart(int position) {
            int start = position;
            while (start > 0) {
                char before = masked.charAt(start - 1);
                if (before == ';' || before == '{' || before == '}') {
                    break;
                }
                start--;
            }
            return start;
        }

        private int statementEnd(int position) {
            int end = position;
            while (end < masked.length() && masked.charAt(end) != ';' && masked.charAt(end) != '{' && masked.charAt(end) != '}') {
                end++;
            }
            return end;
        }

        private String keptLiterals;

        private String codeKeepingLiterals() {
            if (keptLiterals == null) {
                StringBuilder kept = new StringBuilder(masked);
                for (Literal literal : literals) {
                    kept.replace(literal.start(), literal.start() + literal.rawLength(),
                            raw.substring(literal.start(), literal.start() + literal.rawLength()));
                }
                keptLiterals = kept.toString();
            }
            return keptLiterals;
        }

        /** Blanks comments and the content of literals, and records each literal where its content starts. */
        private String mask(String source) {
            StringBuilder out = new StringBuilder(source.length());
            int i = 0;
            int length = source.length();
            while (i < length) {
                char c = source.charAt(i);
                char next = i + 1 < length ? source.charAt(i + 1) : '\0';
                if (c == '"' && source.startsWith("\"\"\"", i)) {
                    int end = source.indexOf("\"\"\"", i + 3);
                    end = end < 0 ? length : end;
                    out.append("\"\"\"");
                    appendBlank(out, source, i + 3, end);
                    if (end < length) {
                        out.append("\"\"\"");
                    }
                    i = Math.min(length, end + 3);
                } else if (c == '"') {
                    int end = i + 1;
                    StringBuilder content = new StringBuilder();
                    while (end < length && source.charAt(end) != '"') {
                        if (source.charAt(end) == '\\' && end + 1 < length) {
                            content.append(source.charAt(end + 1));
                            end++;
                        } else {
                            content.append(source.charAt(end));
                        }
                        end++;
                    }
                    out.append('"');
                    literals.add(new Literal(out.length(), content.toString(), end - (i + 1)));
                    appendBlank(out, source, i + 1, end);
                    out.append('"');
                    i = end + 1;
                } else if (c == '\'') {
                    int end = i + 1;
                    while (end < length && source.charAt(end) != '\'') {
                        end += source.charAt(end) == '\\' ? 2 : 1;
                    }
                    out.append('\'');
                    appendBlank(out, source, i + 1, Math.min(end, length));
                    out.append('\'');
                    i = end + 1;
                } else if (c == '/' && next == '/') {
                    int end = source.indexOf('\n', i);
                    end = end < 0 ? length : end;
                    appendBlank(out, source, i, end);
                    i = end;
                } else if (c == '/' && next == '*') {
                    int end = source.indexOf("*/", i + 2);
                    end = end < 0 ? length : end + 2;
                    appendBlank(out, source, i, end);
                    i = end;
                } else {
                    out.append(c);
                    i++;
                }
            }
            return out.toString();
        }

        private static void appendBlank(StringBuilder out, String source, int from, int to) {
            for (int index = from; index < to && index < source.length(); index++) {
                out.append(source.charAt(index) == '\n' ? '\n' : ' ');
            }
        }
    }
}
