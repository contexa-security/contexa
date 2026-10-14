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

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The operator's re-inspection: one sealed package at once, or a capture period by removing this inspector version's
 * results of it, so that the automatic round inspects them again; the period's progress is how many of its packages
 * have no result of this version yet (R1b-6).
 */
public class PromptInspectionReinspection {

    /**
     * A capture period's re-inspection as the store counts it.
     *
     * @param packages    the period's packages that the automatic round samples
     * @param uninspected those of them without a result of this inspector version yet
     */
    public record PeriodStatus(Instant from, Instant to, long packages, long uninspected) {
    }

    private final PromptInspectionService service;
    private final PromptInspectionResultStore results;
    private final int samplePercent;

    public PromptInspectionReinspection(PromptInspectionService service, PromptInspectionResultStore results,
                                        int samplePercent) {
        this.service = Objects.requireNonNull(service, "service");
        this.results = Objects.requireNonNull(results, "results");
        if (samplePercent < 1 || samplePercent > 100) {
            throw new IllegalArgumentException("samplePercent must be between 1 and 100");
        }
        this.samplePercent = samplePercent;
    }

    /** Inspects the package again at once; empty when no package has that id. */
    public Optional<PromptInspectionResult> reinspect(String packageId) {
        return service.inspect(packageId, PromptInspectionTrigger.OPERATOR);
    }

    /**
     * Leaves the packages captured from {@code from} to {@code to} (both included) to the automatic round to inspect
     * again: this inspector version's results of them are removed, within the share the round samples.
     */
    public PeriodStatus request(Instant from, Instant to) {
        requirePeriod(from, to);
        results.removeResults(PromptInspector.INSPECTOR_VERSION, from, to, samplePercent);
        return status(from, to);
    }

    /** How far the round has come with the period: its sampled packages still without a result of this version. */
    public PeriodStatus status(Instant from, Instant to) {
        requirePeriod(from, to);
        PromptInspectionResultStore.PeriodCount count = results.countPeriod(PromptInspector.INSPECTOR_VERSION, from,
                to, samplePercent);
        return new PeriodStatus(from, to, count.packages(), count.uninspected());
    }

    private static void requirePeriod(Instant from, Instant to) {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        if (to.isBefore(from)) {
            throw new IllegalArgumentException("to must not be before from");
        }
    }
}
