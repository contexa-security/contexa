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
package io.contexa.contexacore.std.components.prompt.quality;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * The verdict of the quality gate on a candidate (plan 3.4).
 *
 * @param status      the most severe result of the conditions
 * @param findings    the conditions in the order of the table, each with its result and numbers
 * @param comparisons the paired comparison of every rate; empty when the two versions could not be compared
 * @param changes     the cases the two versions answer differently
 */
public record QualityGateResult(QualityGateStatus status, List<QualityGateFinding> findings,
                                Map<QualityMetric, QualityComparison> comparisons, QualityCaseChanges changes) {

    public QualityGateResult {
        findings = List.copyOf(findings);
        comparisons = comparisons.isEmpty() ? Map.of() : Collections.unmodifiableMap(new EnumMap<>(comparisons));
    }

    public QualityGateFinding finding(QualityGateCondition condition) {
        return findings.stream().filter(finding -> finding.condition() == condition).findFirst().orElseThrow();
    }
}
