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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the quality gate found for one condition (plan 3.4): its result and the numbers behind it.
 *
 * @param condition   the condition
 * @param status      passed, a warning, blocked, or not evaluated
 * @param figures     the numbers the result rests on, by name, in the order they were taken
 * @param comparisons the paired comparisons the condition read
 * @param caseKeys    the cases the condition names
 */
public record QualityGateFinding(QualityGateCondition condition, QualityGateStatus status, Map<String, Number> figures,
                                 List<QualityComparison> comparisons, List<String> caseKeys) {

    public QualityGateFinding {
        figures = Collections.unmodifiableMap(new LinkedHashMap<>(figures));
        comparisons = List.copyOf(comparisons);
        caseKeys = List.copyOf(caseKeys);
    }
}
