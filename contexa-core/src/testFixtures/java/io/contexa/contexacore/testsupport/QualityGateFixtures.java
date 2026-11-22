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
package io.contexa.contexacore.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseEnvironment;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseOrigin;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * The quality gate without a model and without a store of measurements (plan 3.4): four cases (one that must be
 * caught, a threat, one that must not be blocked, normal work), measurements of a version that answers them soundly or
 * lets the case that must be caught through, and a source that answers every read with a reading it was given.
 */
public final class QualityGateFixtures {

    public static final String MODEL = "model-setting-a";
    public static final String CASE_SET = "case-set-version-a";
    public static final int RUNS = 2;
    /** Thresholds the four cases are enough for: one root on either side tells two versions apart. */
    public static final QualityGateSettings SETTINGS = new QualityGateSettings(0.05, 0.05, 1, 1);
    public static final String MUST_CATCH = "must-catch-1";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final List<QualityCase> CASES = List.of(
            of(MUST_CATCH, QualityCaseClass.THREAT, EnumSet.of(QualityAction.BLOCK), QualityCaseGrade.MUST_CATCH),
            of("threat-1", QualityCaseClass.THREAT, EnumSet.of(QualityAction.BLOCK, QualityAction.CHALLENGE,
                    QualityAction.ESCALATE), QualityCaseGrade.ORDINARY),
            of("must-not-block-1", QualityCaseClass.NORMAL, EnumSet.of(QualityAction.ALLOW, QualityAction.CHALLENGE),
                    QualityCaseGrade.MUST_NOT_BLOCK),
            of("normal-1", QualityCaseClass.NORMAL, EnumSet.of(QualityAction.ALLOW, QualityAction.CHALLENGE),
                    QualityCaseGrade.ORDINARY));

    private QualityGateFixtures() {
    }

    public static List<QualityCase> cases() {
        return CASES;
    }

    /** The version blocks the case that must be caught, challenges the threat and allows the normal work. */
    public static QualityMeasurement sound(String version) {
        return measurement(version, MODEL, QualityGateFixtures::soundly);
    }

    /** As sound, but the case that must be caught is allowed in every run. */
    public static QualityMeasurement missesTheMustCatchCase(String version) {
        return measurement(version, MODEL, item -> MUST_CATCH.equals(item.key()) ? QualityAction.ALLOW : soundly(item));
    }

    /** The cases and the two measurements; either may be null. */
    public static QualityGateInput input(QualityMeasurement current, QualityMeasurement candidate) {
        return new QualityGateInput(CASES, current, candidate, null, SETTINGS, null);
    }

    /** A source that answers every read with the reading and keeps what it was asked. */
    public static Source source(QualityGateReading reading) {
        return new Source(reading);
    }

    public static final class Source implements QualityGateSource {

        private final List<String> reads = new CopyOnWriteArrayList<>();
        private volatile QualityGateReading reading;

        private Source(QualityGateReading reading) {
            this.reading = reading;
        }

        @Override
        public QualityGateReading read(String scope, String prompt, String candidate, String current) {
            reads.add(scope + " " + prompt + " " + candidate + " " + current);
            return reading;
        }

        /** What it was asked: the scope, the prompt, the candidate and the version in use (null when none). */
        public List<String> reads() {
            return List.copyOf(reads);
        }

        public void answer(QualityGateReading reading) {
            this.reading = reading;
        }
    }

    private static QualityAction soundly(QualityCase item) {
        if (item.grade() == QualityCaseGrade.MUST_CATCH) {
            return QualityAction.BLOCK;
        }
        return item.shouldStop() ? QualityAction.CHALLENGE : QualityAction.ALLOW;
    }

    private static QualityMeasurement measurement(String version, String modelSetting,
                                                  Function<QualityCase, QualityAction> decision) {
        List<QualityAnswer> answers = new ArrayList<>();
        for (int run = 1; run <= RUNS; run++) {
            for (QualityCase item : CASES) {
                answers.add(new QualityAnswer(item.key(), run, decision.apply(item), null, false, false, 3, 3, 7000L,
                        120, false, null));
            }
        }
        return new QualityMeasurement(version, modelSetting, CASE_SET, RUNS, answers);
    }

    private static QualityCase of(String key, QualityCaseClass classification, Set<QualityAction> allowed,
                                  QualityCaseGrade grade) {
        return new QualityCase(key, new QualityCaseInput(JSON.createObjectNode(), JSON.createObjectNode(),
                JSON.createObjectNode(), JSON.createObjectNode(), JSON.createObjectNode(), null, null, null),
                new QualityCaseExpectation(allowed, null, classification,
                        classification == QualityCaseClass.NORMAL ? QualityCaseKind.NORMAL_WORK
                                : QualityCaseKind.OUTSIDER,
                        new QualityCaseRationale(null, "A case of the tests."), List.of()),
                grade, null, new QualityCaseEnvironment("UTC", QualityCaseEnvironment.FIRST_CONTEXT_FORMAT),
                QualityCaseOrigin.CONTEXA, null);
    }
}
