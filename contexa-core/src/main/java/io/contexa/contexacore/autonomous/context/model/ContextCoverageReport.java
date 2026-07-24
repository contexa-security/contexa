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
package io.contexa.contexacore.autonomous.context.model;

import java.util.List;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageLevel;

public record ContextCoverageReport(
        ContextCoverageLevel level,
        List<String> availableFacts,
        List<String> missingCriticalFacts,
        List<String> remediationHints,
        List<String> confidenceWarnings,
        String summary) {

    public ContextCoverageReport {
        availableFacts = availableFacts == null ? List.of() : List.copyOf(availableFacts);
        missingCriticalFacts = missingCriticalFacts == null ? List.of() : List.copyOf(missingCriticalFacts);
        remediationHints = remediationHints == null ? List.of() : List.copyOf(remediationHints);
        confidenceWarnings = confidenceWarnings == null ? List.of() : List.copyOf(confidenceWarnings);
    }
}
