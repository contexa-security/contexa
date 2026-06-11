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
package io.contexa.contexacommon.security.bridge.coverage;

import io.contexa.contexacommon.security.bridge.BridgeSemanticBoundaryPolicy;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public record BridgeCoverageReport(
        BridgeCoverageLevel level,
        int score,
        Set<MissingBridgeContext> missingContexts,
        String summary,
        List<String> remediationHints
) {

    public BridgeCoverageReport {
        level = level == null ? BridgeCoverageLevel.NONE : level;
        missingContexts = missingContexts == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(missingContexts));
        summary = summary == null ? "" : summary.trim();
        remediationHints = remediationHints == null ? List.of() : List.copyOf(new LinkedHashSet<>(remediationHints));
    }

    public String purpose() {
        return BridgeSemanticBoundaryPolicy.BRIDGE_COMPLETENESS_ONLY;
    }
}
