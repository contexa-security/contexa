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
package io.contexa.contexacore.infra;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every timed operator of Reactor in the sources of every module names the scheduler it waits on: without one it waits on Reactor's
 * {@code parallel} scheduler, which the whole JVM shares. A timeout, a delay, an interval, a timed buffer or take, a delayed
 * element or subscription takes Contexa's timer or Contexa's blocking scheduler; a {@code Retry.backoff} or
 * {@code Retry.fixedDelay} its {@code scheduler(...)}.
 */
class ContexaReactorTimersSourceTest {

    private static final Pattern TIMED = Pattern.compile(
            "(\\.timeout|Mono\\.delay|Flux\\.interval|\\.delayElements|\\.delayElement|\\.delaySubscription|\\.buffer|\\.take|\\.sample"
                    + "|\\.skip|\\.cache|\\.window|\\.bufferTimeout|\\.windowTimeout)\\(");
    private static final Pattern RETRY = Pattern.compile("Retry\\.(backoff|fixedDelay)\\(");
    private static final List<String> SCHEDULERS = List.of("ContexaReactorResources.timer()", "ContexaBackgroundExecution.scheduler()");

    @Test
    void everyTimedOperatorOfContexaNamesAContexaScheduler() throws IOException {
        Path root = Path.of("..").toAbsolutePath().normalize();
        List<String> offenders = new ArrayList<>();
        int checked = 0;
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.filter(path -> Files.isDirectory(path.resolve("src/main/java"))).toList()) {
                try (Stream<Path> sources = Files.walk(module.resolve("src/main/java"))) {
                    for (Path source : sources.filter(path -> path.toString().endsWith(".java")).toList()) {
                        String text = Files.readString(source);
                        if (!text.contains("import reactor.core.publisher.")) {
                            continue;
                        }
                        checked++;
                        offenders.addAll(offenders(root.relativize(source).toString(), text));
                    }
                }
            }
        }
        assertThat(checked).as("sources with Reactor's publishers that were read").isGreaterThan(20);
        assertThat(offenders).as("timed operators waiting on Reactor's parallel scheduler").isEmpty();
    }

    @Test
    void theCheckFindsATimedOperatorWithoutAScheduler() {
        // the control: what the sources had
        assertThat(offenders("Example.java", "flux.timeout(Duration.ofMillis(timeout)).buffer(Duration.ofMillis(bufferMs));"))
                .hasSize(2);
        assertThat(offenders("Example.java", "Retry.backoff(4, Duration.ofSeconds(2)).maxBackoff(max).filter(this::retryable);"))
                .hasSize(1);
        assertThat(offenders("Example.java", "flux.timeout(Duration.ofMillis(timeout), ContexaReactorResources.timer());")).isEmpty();
        assertThat(offenders("Example.java", "flux.buffer(16).take(3).cache();")).isEmpty();
    }

    /** The timed operators of a source that name no scheduler of Contexa's. */
    private static List<String> offenders(String source, String text) {
        List<String> offenders = new ArrayList<>();
        Matcher timed = TIMED.matcher(text);
        while (timed.find()) {
            String arguments = arguments(text, timed.end());
            boolean timedByDuration = arguments.contains("Duration") || arguments.contains("TIMEOUT") || arguments.contains("Timeout")
                    || timed.group(1).equals("Mono.delay") || timed.group(1).equals("Flux.interval") || timed.group(1).equals(".timeout");
            if (timedByDuration && SCHEDULERS.stream().noneMatch(arguments::contains)) {
                offenders.add(source + ": " + timed.group(1) + "(" + arguments + ")");
            }
        }
        Matcher retry = RETRY.matcher(text);
        while (retry.find()) {
            int end = text.indexOf(';', retry.end());
            String statement = text.substring(retry.start(), end < 0 ? text.length() : end);
            if (!statement.contains(".scheduler(")) {
                offenders.add(source + ": " + statement.lines().findFirst().orElse(statement));
            }
        }
        return offenders;
    }

    /** The text between the parenthesis that opens at {@code from} and the one that closes it. */
    private static String arguments(String text, int from) {
        int depth = 1;
        for (int i = from; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return text.substring(from, i);
            }
        }
        return text.substring(from);
    }
}
