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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * The median and the 95th value of a quantity over the answers of a measurement (plan 3.3): the decision time and the
 * answer tokens.
 *
 * @param count           how many answers carry the quantity
 * @param median          the median: the middle value, or the mean of the two middle values; NaN when there is none
 * @param ninetyFifth     the 95th value by nearest rank: the smallest value with at least 95% of the values at or
 *                        below it; NaN when there is none
 */
public record QualitySpread(int count, double median, double ninetyFifth) {

    /** The spread of the values; null values are left out. */
    public static QualitySpread of(Collection<? extends Number> values) {
        List<Double> sorted = new ArrayList<>();
        for (Number value : values) {
            if (value != null) {
                sorted.add(value.doubleValue());
            }
        }
        sorted.sort(Comparator.naturalOrder());
        int count = sorted.size();
        if (count == 0) {
            return new QualitySpread(0, Double.NaN, Double.NaN);
        }
        double median = count % 2 == 1 ? sorted.get(count / 2)
                : (sorted.get(count / 2 - 1) + sorted.get(count / 2)) / 2.0;
        int rank = (int) Math.ceil(0.95 * count);
        return new QualitySpread(count, median, sorted.get(Math.max(1, rank) - 1));
    }
}
