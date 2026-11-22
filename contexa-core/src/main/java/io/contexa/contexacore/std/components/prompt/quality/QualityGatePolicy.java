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
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The quality gate as the release gate applies it (plan 3.4, 5 step 5): the measurements from the source, the verdict
 * of {@link QualityGateEvaluator} with the thresholds of the installation, and the mode it is applied in.
 *
 * <ul>
 * <li>Measured, missing or stale: the nine conditions are computed from the measurements there are; a missing one
 * blocks on the first condition. A stale measurement is always warned of, so that it is taken again.</li>
 * <li>Cannot be measured: not "below the bar" but "cannot be measured"; the nine conditions are not evaluated and the
 * gate warns only.</li>
 * <li>The first measurement of the version in use waits: the first condition, which blocks for the missing
 * measurement of the version in use, warns instead; the conditions the candidate's own measurement decides keep their
 * result.</li>
 * <li>In the warning mode a blocked result is applied as a warning; the verdict keeps it as blocked.</li>
 * </ul>
 */
public final class QualityGatePolicy {

    private final QualityGateSource source;
    private final QualityGateMode mode;
    private final QualityGateSettings settings;

    /**
     * @param source   where the measurements are read; none when null
     * @param mode     warning or blocking; the warning mode when null
     * @param settings the thresholds; the defaults of the plan when null
     */
    public QualityGatePolicy(QualityGateSource source, QualityGateMode mode, QualityGateSettings settings) {
        this.source = source != null ? source : QualityGateSource.none();
        this.mode = mode != null ? mode : QualityGateMode.WARN;
        this.settings = settings != null ? settings : QualityGateSettings.defaults();
    }

    /** No store of measurements, the warning mode and the defaults of the plan. */
    public static QualityGatePolicy none() {
        return new QualityGatePolicy(null, null, null);
    }

    public QualityGateMode mode() {
        return mode;
    }

    public QualityGateSettings settings() {
        return settings;
    }

    /** The verdict on a version that goes back to one the scope used for decisions: no quality condition. */
    public QualityGateVerdict rollback() {
        return QualityGateVerdict.rollback(mode);
    }

    /**
     * The quality gate on a candidate against the version in use.
     *
     * @param current the version the scope decides with now; null when there is none to compare with
     */
    public QualityGateVerdict assess(String scope, String prompt, String candidate, String current) {
        QualityGateReading reading = Objects.requireNonNull(source.read(scope, prompt, candidate, current),
                "The source of the quality gate read nothing");
        QualityMeasurementState state = reading.state();
        if (state == QualityMeasurementState.UNMEASURABLE) {
            return new QualityGateVerdict(state, reading.sides(), reading.detail(), mode,
                    QualityGateStatus.NOT_EVALUATED, QualityGateStatus.WARNING, notEvaluated(), false);
        }
        QualityGateResult result = QualityGateEvaluator.evaluate(withSettings(reading.input()));
        QualityGateStatus adjusted = QualityGateStatus.NOT_EVALUATED;
        for (QualityGateFinding finding : result.findings()) {
            QualityGateStatus status = finding.status();
            if (state == QualityMeasurementState.BASELINE_PENDING
                    && finding.condition() == QualityGateCondition.COMPARABLE_MEASUREMENTS
                    && status == QualityGateStatus.BLOCKED) {
                status = QualityGateStatus.WARNING;
            }
            adjusted = adjusted.worse(status);
        }
        QualityGateStatus applied = mode == QualityGateMode.WARN && adjusted == QualityGateStatus.BLOCKED
                ? QualityGateStatus.WARNING : adjusted;
        if (state == QualityMeasurementState.STALE || state == QualityMeasurementState.BASELINE_PENDING) {
            applied = applied.worse(QualityGateStatus.WARNING);
        }
        return new QualityGateVerdict(state, reading.sides(), reading.detail(), mode, result.status(), applied, result,
                false);
    }

    /**
     * The state of the measurement of one version alone, as for a version that decides outside the gate (plan 3.4:
     * the setting, or the newest Contexa version): there is none to compare it with.
     */
    public QualityMeasurementState measurement(String scope, String prompt, String version) {
        QualityGateReading reading = source.read(scope, prompt, version, null);
        return reading != null ? reading.state() : QualityMeasurementState.UNMEASURABLE;
    }

    /** The input of the source with the thresholds of this installation; nothing measured when there is none. */
    private QualityGateInput withSettings(QualityGateInput input) {
        if (input == null) {
            return new QualityGateInput(List.of(), null, null, null, settings, null);
        }
        return new QualityGateInput(input.cases(), input.current(), input.candidate(), input.noise(), settings,
                input.candidateCreatedAt());
    }

    /** The nine conditions, none of them looked at. */
    private static QualityGateResult notEvaluated() {
        List<QualityGateFinding> findings = new ArrayList<>();
        for (QualityGateCondition condition : QualityGateCondition.values()) {
            findings.add(new QualityGateFinding(condition, QualityGateStatus.NOT_EVALUATED, Map.of(), List.of(),
                    List.of()));
        }
        return new QualityGateResult(QualityGateStatus.NOT_EVALUATED, findings, Map.of(), QualityCaseChanges.none());
    }
}
