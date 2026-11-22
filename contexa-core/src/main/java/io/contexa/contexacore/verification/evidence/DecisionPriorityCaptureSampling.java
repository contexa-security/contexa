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
package io.contexa.contexacore.verification.evidence;

import io.contexa.contexacore.util.ErrorLogThrottle;
import lombok.extern.slf4j.Slf4j;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.ToLongFunction;

/**
 * Which decisions are sealed (plan 3.6): the decisions worth replaying first, within a daily limit.
 *
 * <ol>
 * <li>The window after a change and the stable share of the requests are sealed as before
 * ({@link VersionChangeCaptureSampling}), whatever the limit says.</li>
 * <li>A decision that stopped the request (CHALLENGE, ESCALATE, BLOCK) is sealed.</li>
 * <li>A decision that allowed the request is sealed when something about it says it may be a miss
 * ({@link SealedCaptureDecision#allowedWithRisk}); an allowed decision without such a sign is left to the share.</li>
 * <li>Rules 2 and 3 seal only while fewer than the daily limit of packages were sealed in the UTC day, counting every
 * package of the day. Once the limit is reached the day falls back to rule 1 alone.</li>
 * </ol>
 *
 * <p>The day's count is the store's: it is read again every {@link #REFRESH} on the capture thread, never on a
 * decision thread, and counted locally in between, so the servers that share a store stay near one limit; they can
 * pass it by what they seal between two reads. A decision rules 2 and 3 would have sealed past the limit is counted
 * ({@link #notSealedOverLimit()}) and reported in the log at most once per {@link #REPORT}.</p>
 */
@Slf4j
public class DecisionPriorityCaptureSampling implements SealedEvidenceCaptureSampling {

    /** The packages sealed in one UTC day before rules 2 and 3 stop, by default. */
    public static final int DEFAULT_DAILY_LIMIT = 2000;

    /** The unknown decision facts from which an allowed decision is sealed, by default. */
    public static final int DEFAULT_UNKNOWN_FACT_THRESHOLD = 3;

    /** How long the day's count is kept before the store is asked again. */
    static final Duration REFRESH = Duration.ofSeconds(30);

    /** The least time between two log lines that say the limit holds decisions back. */
    static final Duration REPORT = Duration.ofMinutes(10);

    private final SealedEvidenceCaptureSampling base;
    private final int dailyLimit;
    private final int unknownFactThreshold;
    private final ToLongFunction<Instant> sealedSince;
    private final Clock clock;
    private final AtomicLong notSealedOverLimit = new AtomicLong();
    private final ErrorLogThrottle limitReport;

    private LocalDate day;
    private Instant readAt;
    private long sealedAtRead;
    private long sealedSinceRead;

    /**
     * @param base                 the window and the share sealed whatever the limit says
     * @param dailyLimit           the packages of a UTC day up to which stopped and risky decisions are sealed; 0 seals
     *                             by the window and the share alone
     * @param unknownFactThreshold the unknown decision facts from which an allowed decision is sealed, at least 1
     * @param sealedSince          how many packages the store holds that were captured at or after a time
     */
    public DecisionPriorityCaptureSampling(SealedEvidenceCaptureSampling base, int dailyLimit, int unknownFactThreshold,
                                           ToLongFunction<Instant> sealedSince, Clock clock) {
        if (dailyLimit < 0) {
            throw new IllegalArgumentException("dailyLimit must not be negative");
        }
        if (unknownFactThreshold < 1) {
            throw new IllegalArgumentException("unknownFactThreshold must be at least 1");
        }
        this.base = Objects.requireNonNull(base, "base");
        this.dailyLimit = dailyLimit;
        this.unknownFactThreshold = unknownFactThreshold;
        this.sealedSince = Objects.requireNonNull(sealedSince, "sealedSince");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.limitReport = new ErrorLogThrottle(REPORT, () -> this.clock.millis());
    }

    /** Without what the capture knows of the decision, the window and the share alone decide. */
    @Override
    public boolean shouldSeal(SealedEvidencePackage evidencePackage) {
        return shouldSeal(evidencePackage, null);
    }

    @Override
    public boolean shouldSeal(SealedEvidencePackage evidencePackage, SealedCaptureDecision decision) {
        if (base.shouldSeal(evidencePackage)) {
            counted();
            return true;
        }
        if (dailyLimit == 0 || decision == null
                || !(decision.stopped() || decision.allowedWithRisk(unknownFactThreshold))) {
            return false;
        }
        if (takeFromTheDay()) {
            return true;
        }
        long notSealed = notSealedOverLimit.incrementAndGet();
        long notReported = limitReport.tryAcquire();
        if (notReported != ErrorLogThrottle.SUPPRESSED) {
            log.info("[SealedEvidence] The daily limit of {} sealed decisions is reached: until the next UTC day stopped "
                            + "and risky decisions are sealed by the window and the sample share only, "
                            + "notSealedOverLimit={}, similarSinceLastReport={}", dailyLimit, notSealed, notReported);
        }
        return false;
    }

    /** The decisions rules 2 and 3 would have sealed while the daily limit was reached, since the start. */
    public long notSealedOverLimit() {
        return notSealedOverLimit.get();
    }

    /** A package the window or the share sealed counts toward the day. */
    private synchronized void counted() {
        if (dailyLimit == 0) {
            return;
        }
        refresh();
        sealedSinceRead++;
    }

    private synchronized boolean takeFromTheDay() {
        refresh();
        if (sealedAtRead + sealedSinceRead >= dailyLimit) {
            return false;
        }
        sealedSinceRead++;
        return true;
    }

    /** Reads the day's count from the store when the day changed or the last read is older than the refresh time. */
    private void refresh() {
        Instant now = clock.instant();
        LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        boolean newDay = !today.equals(day);
        if (!newDay && readAt != null && Duration.between(readAt, now).compareTo(REFRESH) < 0) {
            return;
        }
        if (newDay) {
            day = today;
            sealedAtRead = 0;
            sealedSinceRead = 0;
        }
        readAt = now;
        try {
            sealedAtRead = sealedSince.applyAsLong(today.atStartOfDay(ZoneOffset.UTC).toInstant());
            sealedSinceRead = 0;
        } catch (RuntimeException e) {
            // The count goes on from what this server knows; the next refresh asks again.
            log.error("[SealedEvidence] The packages sealed today could not be counted, the daily limit goes on from "
                    + "this server's own count", e);
        }
    }
}
