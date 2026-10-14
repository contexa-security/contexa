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

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import lombok.extern.slf4j.Slf4j;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Inspects sealed packages and stores the results. It runs apart from the decision path: nothing a decision does
 * waits for it, and a failed inspection never touches a decision or a sealed package.
 */
@Slf4j
public class PromptInspectionService {

    private final PromptInspector inspector;
    private final SealedEvidencePackageRepository packages;
    private final PromptInspectionResultStore results;
    private final Clock clock;
    /** Packages whose inspection failed lately, tried after the others (R1b-5); the oldest are let go past the cap. */
    private final Set<String> failed = Collections.synchronizedSet(new LinkedHashSet<>());

    static final int FAILED_KEPT = 1_000;

    public PromptInspectionService(PromptInspector inspector, SealedEvidencePackageRepository packages,
                                   PromptInspectionResultStore results, Clock clock) {
        this.inspector = Objects.requireNonNull(inspector, "inspector");
        this.packages = Objects.requireNonNull(packages, "packages");
        this.results = Objects.requireNonNull(results, "results");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Inspects the package and stores the result; empty when no package has that id. */
    public Optional<PromptInspectionResult> inspect(String packageId, PromptInspectionTrigger trigger) {
        return packages.findByPackageId(packageId).map(evidencePackage -> inspectAndStore(evidencePackage, trigger));
    }

    /** Inspects the package as it was read and stores the result. */
    public PromptInspectionResult inspectAndStore(SealedEvidencePackage evidencePackage, PromptInspectionTrigger trigger) {
        PromptInspectionResult result = inspector.inspect(evidencePackage);
        results.save(result, trigger, clock.instant());
        return result;
    }

    /**
     * One automatic round: the oldest packages without a result of this inspector version, up to the batch, those whose
     * inspection failed lately after the others so that they never hold the front of a round. A package that cannot be
     * inspected or stored is left for a later round; a source a check reads that is unavailable now stops the round,
     * and the package is tried again in the next one (R1b-5).
     *
     * @return how many results were stored
     */
    public int inspectUninspected(int batchSize, int samplePercent) {
        Set<String> lately;
        synchronized (failed) {
            lately = new LinkedHashSet<>(failed);
        }
        List<String> candidates = results.findUninspectedPackageIds(PromptInspector.INSPECTOR_VERSION,
                batchSize + lately.size(), samplePercent);
        List<String> ordered = new ArrayList<>();
        candidates.stream().filter(packageId -> !lately.contains(packageId)).forEach(ordered::add);
        candidates.stream().filter(lately::contains).forEach(ordered::add);
        int stored = 0;
        for (String packageId : ordered.subList(0, Math.min(batchSize, ordered.size()))) {
            try {
                if (inspect(packageId, PromptInspectionTrigger.AUTO).isPresent()) {
                    stored++;
                }
                failed.remove(packageId);
            }
            catch (PromptInspectionUnavailableException exception) {
                log.error("Prompt inspection round stopped at sealed package {}: {}", packageId, exception.getMessage());
                break;
            }
            catch (RuntimeException exception) {
                log.error("Prompt inspection of sealed package {} was not stored", packageId, exception);
                remember(packageId);
            }
        }
        return stored;
    }

    private void remember(String packageId) {
        synchronized (failed) {
            failed.remove(packageId);
            failed.add(packageId);
            Iterator<String> oldest = failed.iterator();
            while (failed.size() > FAILED_KEPT && oldest.hasNext()) {
                oldest.next();
                oldest.remove();
            }
        }
    }
}
