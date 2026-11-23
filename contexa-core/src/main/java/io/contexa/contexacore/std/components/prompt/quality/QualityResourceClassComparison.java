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
import java.util.Map;

/**
 * The paired comparison of two versions over the cases of one resource class (quality P46): the same comparison as
 * over the whole set, root by root, on the cases of the class alone, and the cases of the class the two versions
 * answer differently. It is shown beside the gate and decides nothing: the gate reads the whole set.
 *
 * @param resourceClass the class, or {@link QualityCaseResource#UNCLASSIFIED}
 * @param cases         the cases of the class
 * @param stopRoots     the distinct roots of the cases of the class that must be stopped
 * @param allowRoots    the distinct roots of the cases of the class that must be allowed
 * @param comparisons   the comparison of every rate over the cases of the class; empty when no case has the class
 * @param changes       the cases of the class the two versions answer differently
 */
public record QualityResourceClassComparison(String resourceClass, int cases, int stopRoots, int allowRoots,
                                             Map<QualityMetric, QualityComparison> comparisons,
                                             QualityCaseChanges changes) {

    public QualityResourceClassComparison {
        comparisons = comparisons.isEmpty() ? Map.of() : Collections.unmodifiableMap(new EnumMap<>(comparisons));
    }

    /** Whether the class has a case to compare. */
    public boolean compared() {
        return cases > 0;
    }

    /** How many cases of the class the two versions answer differently, every way counted. */
    public int changedCases() {
        return changes.newlyMissed().size() + changes.newlyCaught().size() + changes.newlyStopped().size()
                + changes.newlyReleased().size();
    }

    public QualityComparison comparison(QualityMetric metric) {
        return comparisons.get(metric);
    }
}
