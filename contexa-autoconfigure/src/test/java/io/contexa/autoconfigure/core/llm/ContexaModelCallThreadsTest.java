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
package io.contexa.autoconfigure.core.llm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The threads of a servlet application that mounts Contexa's model clients, read from a JVM that runs nothing else
 * ({@link ModelCallThreadsProbe}). Reactor Netty runs a client given no event loop on the JVM's global one,
 * {@code reactor-http-nio-N}, all of its threads (as many as cores) at its first use, and Reactor runs a time limit given no
 * scheduler on its global {@code parallel-N}: an application's own WebClient and reactive code share both. Contexa's model calls
 * must start neither, run on threads of its own whose names say so, share nothing with the application's WebClient, and leave no
 * thread behind when the application closes.
 */
@Timeout(240)
class ContexaModelCallThreadsTest {

    private static final int EVENT_LOOP_THREADS = 2;
    private static final int TIMER_THREADS = 2;

    @TempDir
    Path workDir;

    @Test
    void contexasModelCallsStartNoThreadOfTheJvmsSharedPoolsAndLeaveNoneBehind() throws Exception {
        Map<String, String> probe = run("contexa-only");

        assertThat(probe.get("RESULT")).contains("chat=ALLOW").contains("ALLOW for this request").contains("embedding=3");
        // an application whose Contexa has made no call yet has no thread of Contexa's event loop or timer
        assertThat(names(probe, "THREADS started")).noneMatch(name -> name.startsWith("contexa-ai-"))
                .noneMatch(name -> name.startsWith("contexa-timer-"));
        Set<String> before = names(probe, "THREADS before");
        Set<String> added = added(before, names(probe, "THREADS contexa"));
        assertThat(added).as("threads that the application and Contexa's calls added").isNotEmpty()
                .noneMatch(name -> name.startsWith("reactor-http-nio-"))
                .noneMatch(name -> name.startsWith("parallel-"));
        assertThat(added.stream().filter(name -> name.startsWith("contexa-ai-"))).hasSizeBetween(1, EVENT_LOOP_THREADS);
        assertThat(added.stream().filter(name -> name.startsWith("contexa-timer-"))).hasSizeBetween(1, TIMER_THREADS);

        Set<String> afterClose = names(probe, "THREADS closed");
        assertThat(afterClose).noneMatch(name -> name.startsWith("contexa-ai-")).noneMatch(name -> name.startsWith("contexa-timer-"));
        // what the same application without Contexa has once it has closed, and what is left with Contexa beyond it
        Set<String> leftByContexa = added(names(run("no-contexa"), "THREADS closed"), afterClose);
        System.out.println("[probe] left after the close beyond the application without Contexa: " + leftByContexa);
        assertThat(leftByContexa).noneMatch(name -> name.startsWith("reactor-http-nio-")).noneMatch(name -> name.startsWith("parallel-"))
                .noneMatch(name -> name.startsWith("contexa-ai-")).noneMatch(name -> name.startsWith("contexa-timer-"));
    }

    @Test
    void theApplicationsWebClientKeepsItsThreadsAndContexasCallsDoNotRunOnThem() throws Exception {
        Map<String, String> probe = run("host-webclient");

        assertThat(probe.get("RESULT")).contains("chat=ALLOW").contains("ALLOW for this request").contains("embedding=3");
        // the application's own calls run on the JVM's event loop, as they do without Contexa
        assertThat(probe.get("HOSTCALL")).startsWith("reactor-http-nio-");
        Set<String> hostLoops = names(probe, "THREADS host").stream().filter(name -> name.startsWith("reactor-http-nio-"))
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> afterContexa = names(probe, "THREADS contexa");
        assertThat(afterContexa.stream().filter(name -> name.startsWith("reactor-http-nio-")).toList()).containsExactlyElementsOf(hostLoops);
        assertThat(afterContexa).noneMatch(name -> name.startsWith("parallel-"));
        // the connections on the application's event loop are the application's: Contexa's calls registered none there
        assertThat(globalChannels(probe.get("CHANNELS contexa"))).isEqualTo(globalChannels(probe.get("CHANNELS host")));
        assertThat(afterContexa.stream().filter(name -> name.startsWith("contexa-ai-"))).hasSizeBetween(1, EVENT_LOOP_THREADS);
    }

    private static String globalChannels(String channels) {
        assertThat(channels).startsWith("global=");
        return channels.substring("global=".length(), channels.indexOf(' '));
    }

    private static Set<String> added(Set<String> before, Set<String> after) {
        Set<String> added = new TreeSet<>(after);
        added.removeAll(before);
        return added;
    }

    private static Set<String> names(Map<String, String> probe, String key) {
        String names = probe.get(key);
        assertThat(names).as(key).isNotNull();
        return new TreeSet<>(Arrays.asList(names.split("\\|")));
    }

    /** What the probe printed, by the words that start each line (the last line of each kind). */
    private Map<String, String> run(String scenario) throws IOException, InterruptedException {
        Path arguments = workDir.resolve(scenario + ".args");
        Path output = workDir.resolve(scenario + ".out");
        String classPath = Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
                .map(entry -> entry.replace('\\', '/')).collect(Collectors.joining(File.pathSeparator));
        Files.writeString(arguments, "-cp \"" + classPath + "\"\n-Dfile.encoding=UTF-8\n"
                + ModelCallThreadsProbe.class.getName() + "\n" + scenario + "\n", StandardCharsets.UTF_8);
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        Process process = new ProcessBuilder(java.toString(), "@" + arguments)
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        boolean ended = process.waitFor(180, TimeUnit.SECONDS);
        if (!ended) {
            process.destroyForcibly();
        }
        List<String> lines = Files.readAllLines(output, StandardCharsets.UTF_8);
        assertThat(ended).as("the probe ended: %s", tail(lines)).isTrue();
        assertThat(process.exitValue()).as("the probe's exit: %s", tail(lines)).isZero();
        Map<String, String> printed = new HashMap<>();
        for (String line : lines) {
            if (line.startsWith("PROBE ")) {
                String text = line.substring("PROBE ".length());
                String key = text.startsWith("THREADS ") || text.startsWith("CHANNELS ")
                        ? text.substring(0, text.indexOf(' ', text.indexOf(' ') + 1)) : text.substring(0, text.indexOf(' '));
                printed.put(key, text.substring(key.length()).trim());
            }
        }
        new TreeMap<>(printed).forEach((key, value) -> System.out.println("[probe " + scenario + "] " + key + " = " + value));
        return printed;
    }

    private static String tail(List<String> lines) {
        List<String> last = new ArrayList<>(lines.subList(Math.max(0, lines.size() - 40), lines.size()));
        return String.join(System.lineSeparator(), last);
    }
}
