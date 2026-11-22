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
import java.util.Set;

/**
 * What the release gate found of the quality of a version it is to use for decisions or start a canary of (plan 3.4).
 * The verdict is the one the nine conditions give; what is applied is that verdict in the mode of the gate and the
 * state of the measurements: in the warning mode a blocked verdict is applied as a warning, a version that cannot be
 * measured is warned of instead of blocked, and the missing measurement of the version in use while its first one
 * waits warns instead of blocking.
 *
 * @param measurement the state of the measurements; null for a rollback, which reads none
 * @param sides       the versions the state is about
 * @param detail      why, as the source said; null when it said nothing
 * @param mode        the mode of the gate
 * @param verdict     the verdict of the nine conditions as computed, a blocked one kept as blocked in the warning mode;
 *                    NOT_EVALUATED when nothing could be measured, or for a rollback
 * @param applied     what the gate applies: PASSED, WARNING or BLOCKED
 * @param result      the nine conditions with their numbers and the cases the versions answer differently; null for a
 *                    rollback
 * @param rollback    whether the version goes back to one this scope used for decisions before, which takes no
 *                    quality condition (plan 3.4)
 */
public record QualityGateVerdict(QualityMeasurementState measurement, Set<QualityGateSide> sides, String detail,
                                 QualityGateMode mode, QualityGateStatus verdict, QualityGateStatus applied,
                                 QualityGateResult result, boolean rollback) {

    public QualityGateVerdict {
        Set<QualityGateSide> copy = EnumSet.noneOf(QualityGateSide.class);
        if (sides != null) {
            copy.addAll(sides);
        }
        sides = Collections.unmodifiableSet(copy);
    }

    /** A version that goes back to one this scope used for decisions: no quality condition is read. */
    public static QualityGateVerdict rollback(QualityGateMode mode) {
        return new QualityGateVerdict(null, Set.of(), null, mode, QualityGateStatus.NOT_EVALUATED,
                QualityGateStatus.PASSED, null, true);
    }

    /** Whether the gate blocks the version on its quality. */
    public boolean blocks() {
        return applied == QualityGateStatus.BLOCKED;
    }

    /** Whether the gate warns of the quality of the version without blocking it. */
    public boolean warns() {
        return applied == QualityGateStatus.WARNING;
    }
}
