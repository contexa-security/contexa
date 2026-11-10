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
package io.contexa.contexacommon.cache;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ContexaCaffeineTest {

    /** The work a cache does after the call that caused it: here the removal listener of an entry that was evicted. */
    private static String threadOfTheMaintenance(Caffeine<Object, Object> builder) throws Exception {
        CompletableFuture<String> where = new CompletableFuture<>();
        Cache<String, String> cache = builder.maximumSize(1).removalListener((key, value, cause) -> where.complete(Thread.currentThread().getName())).build();
        cache.put("a", "1");
        cache.put("b", "2");
        cache.cleanUp();
        return where.get(10, TimeUnit.SECONDS);
    }

    @Test
    void theMaintenanceOfAContexaCacheRunsOnAPoolOfContexasOwnAndNotOnTheCommonPool() throws Exception {
        String name = threadOfTheMaintenance(ContexaCaffeine.newBuilder());
        assertThat(name).startsWith("contexa-cache-maintenance-");
    }

    @Test
    void aBuilderOfCaffeineAsItIsRunsItOnTheCommonPoolWhichIsWhatThisClassKeepsContexaFrom() throws Exception {
        // the control: without the executor the same listener runs on a thread of the JVM's common pool
        String name = threadOfTheMaintenance(Caffeine.newBuilder());
        assertThat(name).startsWith("ForkJoinPool.commonPool-worker-");
        assertThat(ForkJoinPool.commonPool().getPoolSize()).isGreaterThan(0);
    }

    @Test
    void theThreadsOfThePoolAreDaemonsSoTheyNeverKeepTheJvmAlive() throws Exception {
        CompletableFuture<Boolean> daemon = new CompletableFuture<>();
        Cache<String, String> cache = ContexaCaffeine.newBuilder().maximumSize(1).removalListener((key, value, cause) -> daemon.complete(Thread.currentThread().isDaemon())).build();
        cache.put("a", "1");
        cache.put("b", "2");
        cache.cleanUp();
        assertThat(daemon.get(10, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void noCacheOfContexaIsBuiltOutsideThisClass() throws IOException {
        // every module of the repository: a cache built with Caffeine.newBuilder() directly would take the common pool again
        Path root = Path.of("..").toAbsolutePath().normalize();
        List<String> offenders = new ArrayList<>();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.filter(path -> Files.isDirectory(path.resolve("src/main/java"))).toList()) {
                try (Stream<Path> sources = Files.walk(module.resolve("src/main/java"))) {
                    for (Path source : sources.filter(path -> path.toString().endsWith(".java") && !path.getFileName().toString().equals("ContexaCaffeine.java")).toList()) {
                        if (Files.readString(source).replace("ContexaCaffeine.newBuilder()", "").contains("Caffeine.newBuilder()")) {
                            offenders.add(root.relativize(source).toString());
                        }
                    }
                }
            }
        }
        assertThat(offenders).as("a cache built with Caffeine.newBuilder() takes the JVM's common pool: use ContexaCaffeine.newBuilder()").isEmpty();
    }
}
