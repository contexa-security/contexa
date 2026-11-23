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

import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.OptionalDouble;

/**
 * How far two measurements of the same version differ, per rate (plan 3.3, 3.4): the width inside which two versions
 * count as the same. Only a difference beyond it can be called better or worse. A rate without a width is not
 * measured yet; its comparison then says "the same" only for no difference at all and is undecidable otherwise, so a
 * version is not stopped on a difference nobody has shown to be more than noise.
 *
 * @param widths the width of each measured rate, as a difference of rates
 */
public record QualityNoise(Map<QualityMetric, Double> widths) {

    public QualityNoise {
        Map<QualityMetric, Double> copy = new EnumMap<>(QualityMetric.class);
        widths.forEach((metric, width) -> {
            if (width == null || width.isNaN() || width < 0) {
                throw new IllegalArgumentException("The noise of " + metric + " is not a width: " + width);
            }
            copy.put(metric, width);
        });
        widths = Collections.unmodifiableMap(copy);
    }

    /** No noise measured yet. */
    public static QualityNoise unknown() {
        return new QualityNoise(Map.of());
    }

    /**
     * The noise two measurements of one version show: for each rate, the difference of the two over the cases both
     * scored. A rate one of them cannot give stays unmeasured.
     */
    public static QualityNoise between(Collection<QualityCase> cases, QualityMeasurement first,
                                       QualityMeasurement second, QualityActionBasis basis) {
        if (!first.promptVersion().equals(second.promptVersion()) || !first.comparableWith(second)) {
            throw new IllegalArgumentException("The noise is taken from two measurements of the same version, case set"
                    + " version, model setting and number of runs");
        }
        QualityTally one = QualityTally.of(cases, first.answers(), basis);
        QualityTally other = QualityTally.of(cases, second.answers(), basis);
        Map<QualityMetric, Double> widths = new EnumMap<>(QualityMetric.class);
        for (QualityMetric metric : QualityMetric.values()) {
            QualityComparison comparison = QualityComparator.compare(metric, one, other, OptionalDouble.empty(), 1.0);
            if (comparison.pairedCases() > 0) {
                widths.put(metric, Math.abs(comparison.difference()));
            }
        }
        return new QualityNoise(widths);
    }

    /** The width of the rate, or empty when it is not measured. */
    public OptionalDouble width(QualityMetric metric) {
        Double width = widths.get(metric);
        return width != null ? OptionalDouble.of(width) : OptionalDouble.empty();
    }
}
