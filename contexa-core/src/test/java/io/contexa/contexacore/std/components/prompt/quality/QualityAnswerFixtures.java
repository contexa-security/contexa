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
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Answers and measurements for the tests of the quality scoring.
 */
final class QualityAnswerFixtures {

    static final String MODEL = "qwen3:8b|minimum-action=ENFORCE";
    static final String CASE_SET = "case-set-version-1";

    private QualityAnswerFixtures() {
    }

    /** An answer whose first answer took the action, with three cited facts, all accurate. */
    static QualityAnswer answer(String key, int run, QualityAction action) {
        return new QualityAnswer(key, run, action, null, false, false, 3, 3, 7000L, 120, false, null);
    }

    /** The answers of the runs: what the decision gives for each case, in every run. */
    static List<QualityAnswer> answers(Collection<QualityCase> cases, int runs,
                                       Function<QualityCase, QualityAction> decision) {
        List<QualityAnswer> answers = new ArrayList<>();
        for (int run = 1; run <= runs; run++) {
            for (QualityCase item : cases) {
                answers.add(answer(item.key(), run, decision.apply(item)));
            }
        }
        return answers;
    }

    /** The answers with those of one case replaced, in the runs given, by the action. */
    static List<QualityAnswer> with(List<QualityAnswer> answers, String key, Set<Integer> runs, QualityAction action) {
        List<QualityAnswer> changed = new ArrayList<>();
        for (QualityAnswer answer : answers) {
            changed.add(answer.caseKey().equals(key) && runs.contains(answer.run())
                    ? answer(key, answer.run(), action) : answer);
        }
        return changed;
    }

    static QualityMeasurement measurement(String promptVersion, int repeats, List<QualityAnswer> answers) {
        return new QualityMeasurement(promptVersion, MODEL, CASE_SET, repeats, answers);
    }

    /** A row of the local measurement as an answer: it wrote the first answer, and no closing rule ran. */
    static QualityAnswer toAnswer(QualityFixtures.LocalRow row) {
        return new QualityAnswer(row.caseKey(), row.run(), QualityAction.parse(row.action()), null, row.retried(),
                row.modelLess(), row.promptHasFactIds() ? row.cited() : 0,
                row.promptHasFactIds() ? row.onALine() - row.namedByTheCheck() : 0, row.elapsedMs(),
                row.outputTokens(), false, null);
    }

    /** The answers of a result file of the local measurement. */
    static List<QualityAnswer> localAnswers(String file) {
        return new ArrayList<>(QualityFixtures.localRows(file).stream().map(QualityAnswerFixtures::toAnswer).toList());
    }
}
