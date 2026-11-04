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
package io.contexa.autoconfigure.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How the way of running Contexa is decided, kept in one place: the operating profile reads it, one condition asks it, the
 * planes carry it and one strategy answers at run time. A second way of asking is how the modes got tangled before.
 */
class ContexaOperatingProfileContractTest {

    private static final Pattern READS_THE_SETTING = Pattern.compile("getProperty\\(\\s*\"contexa\\.(bridge\\.ownership|ai\\.security\\.mode)\"");
    private static final Pattern COMPARES_THE_TEXT = Pattern.compile("\"(HOST|CONTEXA)_OWNED\"\\s*\\.\\s*equals");
    private static final Pattern PROPERTY_CONDITION = Pattern.compile("@ConditionalOnProperty\\([^)]*\"ownership\"", Pattern.DOTALL);

    private static final Pattern ASYNC_CALL = Pattern.compile("CompletableFuture\\.(?:supply|run)Async\\(");

    private static List<Path> mainSources() throws IOException {
        List<Path> sources = new ArrayList<>();
        Path root = Path.of("").toAbsolutePath().getParent();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.filter(path -> path.getFileName().toString().startsWith("contexa-")).toList()) {
                Path main = module.resolve("src/main/java");
                if (Files.isDirectory(main)) {
                    try (Stream<Path> files = Files.walk(main)) {
                        files.filter(path -> path.toString().endsWith(".java")).forEach(sources::add);
                    }
                }
            }
        }
        assertThat(sources).as("the guards read the sources of every module").hasSizeGreaterThan(1500);
        return sources;
    }

    private static String read(Path path) throws IOException {
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static boolean isTheProfile(Path path) {
        return path.getFileName().toString().equals("ContexaOperatingProfile.java");
    }

    /** G-21. */
    @Test
    void nothingButTheProfileReadsTheSettings() throws IOException {
        List<String> readers = new ArrayList<>();
        for (Path source : mainSources()) {
            String text = read(source);
            if (!isTheProfile(source) && (READS_THE_SETTING.matcher(text).find() || COMPARES_THE_TEXT.matcher(text).find())) {
                readers.add(source.getFileName().toString());
            }
        }
        assertThat(readers).isEmpty();
    }

    /** G-22. */
    @Test
    void theOwnershipIsNeverComparedByAPropertyCondition() throws IOException {
        List<String> conditions = new ArrayList<>();
        for (Path source : mainSources()) {
            if (PROPERTY_CONDITION.matcher(read(source)).find()) {
                conditions.add(source.getFileName().toString());
            }
        }
        assertThat(conditions).isEmpty();
    }

    /** G-23. */
    @Test
    void theOwnershipConditionSitsOnAPlaneClassNeverOnOneBean() throws IOException {
        List<String> beanLevel = new ArrayList<>();
        for (Path source : mainSources()) {
            List<String> lines = Files.readAllLines(source, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).trim().startsWith("@ConditionalOnOwnership")) {
                    int next = i + 1;
                    while (next < lines.size() && !isDeclaration(lines.get(next))) {
                        next++;
                    }
                    if (next == lines.size() || !lines.get(next).contains("class ")) {
                        beanLevel.add(source.getFileName() + ":" + (i + 1));
                    }
                }
            }
        }
        assertThat(beanLevel).isEmpty();
    }

    private static boolean isDeclaration(String line) {
        String trimmed = line.trim();
        return !trimmed.isEmpty() && !trimmed.startsWith("@") && !trimmed.startsWith(")") && !trimmed.startsWith("prefix") && !trimmed.startsWith("name")
                && !trimmed.startsWith("havingValue") && !trimmed.startsWith("matchIfMissing") && !trimmed.startsWith("\"");
    }

    /** An application may have several of these: asked for by type alone, Contexa would stop its start. */
    @Test
    void theSignInFindsItsStoreAndItsDecoderInOneWay() throws IOException {
        List<String> byType = new ArrayList<>();
        for (Path source : mainSources()) {
            String text = read(source);
            if (text.contains("getBean(UserDetailsService.class)") || text.contains("getBean(JwtDecoder.class)")) {
                byType.add(source.getFileName().toString());
            }
        }
        assertThat(byType).isEmpty();
    }

    /** These pools belong to the JVM: a call to a slow model held a thread of the application's own parallel streams. */
    @Test
    void contexasBlockingWorkStaysOffThePoolsOfTheJvm() throws IOException {
        List<String> shared = new ArrayList<>();
        for (Path source : mainSources()) {
            if (source.endsWith("ContexaBackgroundExecution.java")) {
                continue;
            }
            String text = read(source);
            if (text.contains("Schedulers.boundedElastic()") || text.contains("ForkJoinPool.commonPool()")
                    || hasAsyncCallWithoutExecutor(text)) {
                shared.add(source.getFileName().toString());
            }
        }
        assertThat(shared).isEmpty();
    }

    /** With a single argument, supplyAsync and runAsync use ForkJoinPool.commonPool(). */
    private static boolean hasAsyncCallWithoutExecutor(String text) {
        Matcher call = ASYNC_CALL.matcher(text);
        while (call.find()) {
            int depth = 1;
            boolean executor = false;
            for (int i = call.end(); i < text.length() && depth > 0; i++) {
                char character = text.charAt(i);
                if (character == '(' || character == '{') {
                    depth++;
                } else if (character == ')' || character == '}') {
                    depth--;
                } else if (character == ',' && depth == 1) {
                    executor = true;
                }
            }
            if (!executor) {
                return true;
            }
        }
        return false;
    }

    /** Without the name they run on the application's scheduler when it turns scheduling on, which Boot sizes at one thread. */
    @Test
    void everyScheduleOfContexaNamesContexasScheduler() throws IOException {
        List<String> unnamed = new ArrayList<>();
        for (Path source : mainSources()) {
            String text = read(source);
            if (text.contains("@Scheduled(") && text.split("@Scheduled\\(", -1).length - 1
                    != text.split("@Scheduled\\(scheduler = \"contexaTaskScheduler\"", -1).length - 1) {
                unnamed.add(source.getFileName().toString());
            }
        }
        assertThat(unnamed).isEmpty();
    }

    /** G-24. */
    @Test
    void atRunTimeCodeAsksTheStrategyNotWhoOwnsTheSignIn() throws IOException {
        List<String> askers = new ArrayList<>();
        for (Path source : mainSources()) {
            String name = source.getFileName().toString();
            if (!name.equals("OwnershipBehaviour.java") && !name.equals("BridgeProperties.java") && read(source).contains("getOwnership()")) {
                askers.add(name);
            }
        }
        assertThat(askers).isEmpty();
    }
}
