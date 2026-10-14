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
package io.contexa.contexacore.verification.inspection;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * The short retention of the sealed packages whose latest inspection found nothing wrong (R4-S5): on the sealed
 * package retention's schedule, such a package captured longer ago than the clean period is removed with its results,
 * in batches under one lock across instances. A package whose inspection found something, that was not inspected or
 * that an official verification names keeps the default retention; no sealed row is changed.
 */
public class PromptInspectionCleanPackageRetentionScheduler {

    public static final String LOCK_NAME = "promptInspectionCleanPackageRetention";

    /** The clean period by default, which the settings class starts from too. */
    public static final Duration DEFAULT_CLEAN_PERIOD = Duration.ofDays(30);

    /** The packages one store call removes; a run calls again while a call removes a whole batch. */
    static final int BATCH_SIZE = 500;

    private final PromptInspectionResultStore store;
    private final Duration cleanPeriod;
    private final Clock clock;

    public PromptInspectionCleanPackageRetentionScheduler(PromptInspectionResultStore store, Duration cleanPeriod) {
        this(store, cleanPeriod, Clock.systemUTC());
    }

    public PromptInspectionCleanPackageRetentionScheduler(PromptInspectionResultStore store, Duration cleanPeriod,
                                                          Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        if (cleanPeriod == null || cleanPeriod.isZero() || cleanPeriod.isNegative()) {
            throw new IllegalArgumentException("cleanPeriod must be positive");
        }
        this.cleanPeriod = cleanPeriod;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Scheduled(cron = "${contexa.pqa.oss.sealed-evidence.retention.cleanup-cron:0 30 3 * * *}")
    @SchedulerLock(name = LOCK_NAME, lockAtMostFor = "PT30M", lockAtLeastFor = "PT1M")
    public void removeCleanPackages() {
        Instant before = clock.instant().minus(cleanPeriod);
        int removed;
        do {
            removed = store.removeCleanPackagesCapturedBefore(before, BATCH_SIZE);
        } while (removed >= BATCH_SIZE);
    }
}
