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
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * What a {@link QualityGateSource} found for a candidate and the version in use (plan 3.4).
 *
 * @param state  the state of the measurements
 * @param sides  the versions the state is about: which measurement is missing, stale or waiting; empty when measured
 *               or not measurable
 * @param input  the cases and the measurements the gate computes its verdict from: required when measured, and the
 *               measurements there are when missing, stale or waiting (null when there is none); always null when not
 *               measurable. The gate reads it with its own thresholds, not with the ones it carries.
 * @param detail why, in a code a screen or a log can name (such as why the replay cannot run); null when there is
 *               nothing to add
 */
public record QualityGateReading(QualityMeasurementState state, Set<QualityGateSide> sides, QualityGateInput input,
                                 String detail) {

    public QualityGateReading {
        Objects.requireNonNull(state, "state");
        Set<QualityGateSide> copy = EnumSet.noneOf(QualityGateSide.class);
        if (sides != null) {
            copy.addAll(sides);
        }
        sides = Collections.unmodifiableSet(copy);
        if (state == QualityMeasurementState.MEASURED && input == null) {
            throw new IllegalArgumentException("A measured reading carries the input of the gate");
        }
        if (state == QualityMeasurementState.UNMEASURABLE && input != null) {
            throw new IllegalArgumentException("A reading that cannot be measured carries no input");
        }
        if ((state == QualityMeasurementState.MISSING || state == QualityMeasurementState.STALE) && sides.isEmpty()) {
            throw new IllegalArgumentException("A missing or stale reading names the versions it is about");
        }
    }

    /** Both versions are measured: the gate computes its conditions from the input. */
    public static QualityGateReading measured(QualityGateInput input) {
        return new QualityGateReading(QualityMeasurementState.MEASURED, Set.of(), input, null);
    }

    /** The measurements of the sides are not there; the input holds the ones there are, or is null. */
    public static QualityGateReading missing(Set<QualityGateSide> sides, QualityGateInput input) {
        return new QualityGateReading(QualityMeasurementState.MISSING, sides, input, null);
    }

    /** The measurements of the sides were taken under a model setting the server no longer runs. */
    public static QualityGateReading stale(Set<QualityGateSide> sides, QualityGateInput input) {
        return new QualityGateReading(QualityMeasurementState.STALE, sides, input, null);
    }

    /** This installation cannot run the replay that measures; the detail says why. */
    public static QualityGateReading unmeasurable(String detail) {
        return new QualityGateReading(QualityMeasurementState.UNMEASURABLE, Set.of(), null, detail);
    }

    /** The version in use has no measurement yet and its first one is waiting; the input holds the candidate's. */
    public static QualityGateReading baselinePending(QualityGateInput input) {
        return new QualityGateReading(QualityMeasurementState.BASELINE_PENDING, Set.of(QualityGateSide.CURRENT), input,
                null);
    }
}
