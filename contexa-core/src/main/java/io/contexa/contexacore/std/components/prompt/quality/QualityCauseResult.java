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

import java.util.List;
import java.util.Objects;

/**
 * The cause the rules put an answer down to (quality plan 3.5), with what each rule found, in the order of precedence
 * of {@link QualityCause#RULED}.
 *
 * @param cause  the first cause that applies, or {@link QualityCause#UNCLASSIFIED} when none does
 * @param basis  which action of a measured answer is wrong; null for a decision
 * @param checks what each of the seven rules found
 */
public record QualityCauseResult(QualityCause cause, QualityCauseBasis basis, List<QualityCauseCheck> checks) {

    public QualityCauseResult {
        Objects.requireNonNull(cause, "cause");
        checks = List.copyOf(checks);
        if (checks.size() != QualityCause.RULED.size()) {
            throw new IllegalArgumentException("A classification has a check for each of the seven causes");
        }
        for (int index = 0; index < checks.size(); index++) {
            if (checks.get(index).cause() != QualityCause.RULED.get(index)) {
                throw new IllegalArgumentException("The checks of a classification are in the order of precedence");
            }
        }
    }

    /** What the rule of the cause found. */
    public QualityCauseCheck check(QualityCause cause) {
        int index = QualityCause.RULED.indexOf(cause);
        if (index < 0) {
            throw new IllegalArgumentException("No rule decides " + cause);
        }
        return checks.get(index);
    }
}
