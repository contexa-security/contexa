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
package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityContributor;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class ContexaCapabilityRegistry {

    private final List<CapabilityContributor> contributors;
    private final AtomicReference<List<CapabilityCheckResult>> lastResults = new AtomicReference<>(List.of());

    public ContexaCapabilityRegistry(List<CapabilityContributor> contributors) {
        this.contributors = contributors == null ? List.of() : List.copyOf(contributors);
    }

    public List<CapabilityCheckResult> evaluate() {
        List<CapabilityCheckResult> results = new ArrayList<>();
        for (CapabilityContributor contributor : contributors) {
            results.addAll(contributor.check());
        }
        results.sort(Comparator.comparing(result -> result.capability().name()));
        List<CapabilityCheckResult> immutableResults = List.copyOf(results);
        lastResults.set(immutableResults);
        return immutableResults;
    }

    public List<CapabilityCheckResult> lastResults() {
        List<CapabilityCheckResult> results = lastResults.get();
        return results.isEmpty() ? evaluate() : results;
    }
}
