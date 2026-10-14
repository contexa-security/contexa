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
import java.util.List;

/**
 * Where inspection results and their findings are kept: one result per sealed package and inspector version, removed
 * with the package. Matching items are kept as counts only.
 */
public interface PromptInspectionResultStore {

    /**
     * The sealed packages without a result of this inspector version, oldest capture first.
     *
     * @param samplePercent the share of packages inspected, 1 to 100; a package is in the sample by a stable hash of
     *                      its id, so a package left out stays out
     */
    List<String> findUninspectedPackageIds(String inspectorVersion, int limit, int samplePercent);

    /** Keeps the result as the package's result of its inspector version, in place of an earlier one. */
    void save(PromptInspectionResult result, PromptInspectionTrigger trigger, Instant inspectedAt);

    /** Every stored inspection of the package, newest first, each with its own findings. */
    List<PromptInspectionRecord> findAll(String packageId);

    /**
     * Removes this inspector version's results, with their findings, of the packages captured from {@code from} to
     * {@code to} (both included) that the automatic round samples, so that the round inspects them again (R1b-6). A
     * package outside the sample keeps its result: the round would not inspect it again.
     *
     * @return how many results were removed
     */
    int removeResults(String inspectorVersion, Instant from, Instant to, int samplePercent);

    /**
     * Removes up to {@code limit} sealed packages captured before {@code before}, oldest capture first, whose latest
     * result found nothing wrong (PASS or NOT_APPLICABLE) and that no official verification run names, with their
     * results (R4-S5). The sealed rows are deleted, never changed. A package whose latest result is FAIL,
     * INCOMPLETE or ERROR, or that has no result, is left to the default retention.
     *
     * @return how many packages were removed
     */
    int removeCleanPackagesCapturedBefore(Instant before, int limit);

    /** The packages captured in the period that the round samples, and how many have no result of this version. */
    PeriodCount countPeriod(String inspectorVersion, Instant from, Instant to, int samplePercent);

    /** A capture period's sampled packages and those of them without a result of the inspector version. */
    record PeriodCount(long packages, long uninspected) {
    }
}
