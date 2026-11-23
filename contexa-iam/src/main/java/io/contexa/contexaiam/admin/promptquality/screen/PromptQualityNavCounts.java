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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Count;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Quality plan 3.8: the counts beside the menus of the bar, read from the services of the screens. The cases, the
 * measurements and the versions are counted on each page, by the indexes of their scope, so the bar shows a case or a
 * measurement the moment it is added. The decisions sealed in the period are many and change with every decision: their
 * count is read again once a minute at most. A count whose service is not there, or that cannot be read, is no count:
 * the bar shows the menu without it.
 */
public class PromptQualityNavCounts {

    private static final Logger log = LoggerFactory.getLogger(PromptQualityNavCounts.class);

    /** How long the count of sealed decisions is shown before it is read again. */
    static final Duration SEALED_KEPT = Duration.ofMinutes(1);

    /** The prompt the cases, the measurements and the trials are of: only the security decision has them (plan 3.4). */
    static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;

    private final Supplier<PromptQualityCases> cases;
    private final Supplier<PromptQualityMeasurements> measurements;
    private final Supplier<PromptVersionTrials> trials;
    private final Supplier<PromptVersionService> versions;
    private final Supplier<SealedEvidencePackageRepository> sealed;
    private final Clock clock;
    private volatile SealedCount sealedCount;

    private record SealedCount(long count, Instant readAt) {
    }

    /**
     * Each service is asked for when a count is read and may be absent: the measurements and the trials stand on the
     * replay of sealed decisions, the sealed decisions on the store of the evidence.
     */
    public PromptQualityNavCounts(Supplier<PromptQualityCases> cases, Supplier<PromptQualityMeasurements> measurements,
                                  Supplier<PromptVersionTrials> trials, Supplier<PromptVersionService> versions,
                                  Supplier<SealedEvidencePackageRepository> sealed, @Nullable Clock clock) {
        this.cases = Objects.requireNonNull(cases, "cases");
        this.measurements = Objects.requireNonNull(measurements, "measurements");
        this.trials = Objects.requireNonNull(trials, "trials");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.sealed = Objects.requireNonNull(sealed, "sealed");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** The count of the kind in the scope (the platform's when none is given), or null when there is none to show. */
    @Nullable
    public Long count(Count count, @Nullable String scope) {
        try {
            return switch (count) {
                case CASES -> cases(scope);
                case MEASUREMENTS -> measurements(scope);
                case VERSIONS -> versions(scope);
                case SEALED -> sealed();
            };
        }
        catch (DataAccessException unreadable) {
            log.warn("The {} count of the prompt quality menu bar could not be read; the bar shows the menu without it: {}",
                    count, unreadable.getMessage());
            return null;
        }
    }

    @Nullable
    private Long cases(@Nullable String scope) {
        PromptQualityCases service = cases.get();
        return service != null ? service.count(scope, PROMPT) : null;
    }

    /** Both kinds of measurement are one list on the screen: on the labelled cases and on sealed decisions. */
    @Nullable
    private Long measurements(@Nullable String scope) {
        PromptQualityMeasurements onCases = measurements.get();
        PromptVersionTrials onSealed = trials.get();
        if (onCases == null && onSealed == null) {
            return null;
        }
        return (onCases != null ? onCases.count(scope, PROMPT) : 0L) + (onSealed != null ? onSealed.count(scope, PROMPT) : 0L);
    }

    @Nullable
    private Long versions(@Nullable String scope) {
        PromptVersionService service = versions.get();
        return service != null ? service.count(scope, PROMPT) : null;
    }

    @Nullable
    private Long sealed() {
        SealedEvidencePackageRepository store = sealed.get();
        if (store == null) {
            return null;
        }
        Instant now = clock.instant();
        SealedCount last = sealedCount;
        if (last != null && last.readAt().plus(SEALED_KEPT).isAfter(now)) {
            return last.count();
        }
        long count = store.countCapturedSince(now.minus(PromptQualityScreens.SEALED_PERIOD));
        sealedCount = new SealedCount(count, now);
        return count;
    }
}
