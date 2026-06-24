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
package io.contexa.contexacore.hcad.projection;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record HcadBaselineComparison(
        boolean available,
        boolean established,
        long updateCount,
        int minSamples,
        int comparedDimensions,
        int mismatchCount,
        double matchRatio,
        boolean materialMismatch,
        List<String> matchedDimensions,
        List<String> mismatchedDimensions,
        List<String> missingDimensions,
        Map<String, Object> currentValues,
        Map<String, Object> baselineValues,
        Instant lastUpdated
) {

    public HcadBaselineComparison {
        matchedDimensions = matchedDimensions == null ? List.of() : List.copyOf(matchedDimensions);
        mismatchedDimensions = mismatchedDimensions == null ? List.of() : List.copyOf(mismatchedDimensions);
        missingDimensions = missingDimensions == null ? List.of() : List.copyOf(missingDimensions);
        currentValues = currentValues == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(currentValues));
        baselineValues = baselineValues == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(baselineValues));
    }

    public static HcadBaselineComparison unavailable(int minSamples) {
        return new HcadBaselineComparison(
                false,
                false,
                0L,
                minSamples,
                0,
                0,
                0.0d,
                false,
                List.of(),
                List.of(),
                List.of("personalBaselineUnavailable"),
                Map.of(),
                Map.of(),
                null);
    }
}
