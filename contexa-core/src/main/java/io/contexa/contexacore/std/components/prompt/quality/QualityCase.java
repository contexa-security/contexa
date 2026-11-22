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

import java.time.Instant;
import java.util.Objects;

/**
 * A labelled case (plan 3.2): the input of a decision and its right answer, with what the measurement needs to know
 * about the case.
 *
 * @param key         the name of the case, unique in its set
 * @param input       the decision input
 * @param expectation the right answer
 * @param grade       ordinary, must be caught, or must not be blocked
 * @param rootCaseKey the original this case was made from by changing it, or null when the case is an original; a
 *                    variant of a variant names the first original
 * @param environment the environment the case fixes
 * @param origin      where the case comes from
 * @param addedAt     when the case came in, or null when that is not recorded
 */
public record QualityCase(String key, QualityCaseInput input, QualityCaseExpectation expectation,
                          QualityCaseGrade grade, String rootCaseKey, QualityCaseEnvironment environment,
                          QualityCaseOrigin origin, Instant addedAt) {

    public QualityCase {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(expectation, "expectation");
        Objects.requireNonNull(grade, "grade");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(origin, "origin");
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("A labelled case needs a key");
        }
        key = key.trim();
        rootCaseKey = rootCaseKey == null || rootCaseKey.isBlank() || rootCaseKey.trim().equals(key)
                ? null : rootCaseKey.trim();
        if (grade == QualityCaseGrade.MUST_CATCH
                && (!expectation.classification().shouldStop() || expectation.allows(QualityAction.ALLOW))) {
            throw new IllegalArgumentException("The case " + key + " must be caught, so its answer cannot allow");
        }
        if (grade == QualityCaseGrade.MUST_NOT_BLOCK && expectation.allows(QualityAction.BLOCK)) {
            throw new IllegalArgumentException("The case " + key + " must not be blocked, so its answer cannot block");
        }
    }

    /** The root the case counts under: its original, or the case itself when it is one (plan 3.2). */
    public String rootKey() {
        return rootCaseKey != null ? rootCaseKey : key;
    }

    /** Whether the request must be stopped: a threat or an uncertain case. */
    public boolean shouldStop() {
        return expectation.classification().shouldStop();
    }

    /** Whether the case came in after the moment; a case without a recorded time did not. */
    public boolean arrivedAfter(Instant moment) {
        return moment != null && addedAt != null && addedAt.isAfter(moment);
    }

    /**
     * The hash of the content of the case: its key, input, right answer, grade, root and environment. Where the case
     * comes from and when it came in are not content, so recording them later leaves the hash as it is.
     */
    public String contentHash() {
        return QualityCaseHashes.caseHash(this);
    }
}
