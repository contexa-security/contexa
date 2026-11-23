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

/**
 * What the measurements of a candidate and of the version in use are, as the quality gate reads them (plan 3.4).
 */
public enum QualityMeasurementState {

    /** Both versions are measured comparably enough to be read: the gate computes its conditions. */
    MEASURED,

    /** A measurement the gate needs is not there; the sides say which. The first condition blocks then. */
    MISSING,

    /**
     * A measurement was taken under a model setting the server no longer runs (plan 3.4: the model setting changed);
     * the sides say which. It is marked and the gate asks for it to be taken again.
     */
    STALE,

    /**
     * This installation cannot run the replay that measures (plan 3.4): not "below the bar" but "cannot be measured",
     * a warning only.
     */
    UNMEASURABLE,

    /**
     * The version in use has no measurement yet and its first one is waiting to run (plan 3.4: right after an
     * upgrade of an installation in use): a warning only, as far as the missing measurement of the version in use goes.
     */
    BASELINE_PENDING
}
