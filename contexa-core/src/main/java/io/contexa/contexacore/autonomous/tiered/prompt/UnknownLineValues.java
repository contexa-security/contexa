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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;

import java.util.List;

/**
 * The UNKNOWN Coverage parts a v20 prompt draws from the sealed coverage report and bridge: the same functions the render
 * uses, for the prompt inspector to compare the drawn line with the sealed sources (R1b-2).
 */
public final class UnknownLineValues {

    private UnknownLineValues() {
    }

    /** {@code context coverage PARTIAL}. */
    public static String coverageLevel(ContextCoverageReport coverage) {
        return SecurityDecisionPromptValues.coverageLevel(coverage);
    }

    /** {@code missing A, B}, or null when the report misses nothing. */
    public static String missingFacts(ContextCoverageReport coverage) {
        return SecurityDecisionPromptValues.missingFacts(coverage);
    }

    /** {@code bridge FULL}, or {@code bridge UNAVAILABLE} without a bridge or its level. */
    public static String bridgeLevel(CanonicalSecurityContext.Bridge bridge) {
        return SecurityDecisionPromptValues.bridgeLevel(bridge);
    }

    /** The whole coverage line with the usual-behaviour view the warnings read, or null without a report and a bridge. */
    public static String coverage(CanonicalSecurityContext context, BaselineView view) {
        return SecurityDecisionPromptValues.coverageLine(context, view);
    }

    /**
     * The entries the render names unknown for want of a source, as {@code BLOCK.Entry} keys; without a context, every
     * entry it may name so (N-INS-2).
     */
    public static List<String> withoutSource(CanonicalSecurityContext context) {
        return SecurityDecisionPromptValues.withoutSource(context);
    }
}
