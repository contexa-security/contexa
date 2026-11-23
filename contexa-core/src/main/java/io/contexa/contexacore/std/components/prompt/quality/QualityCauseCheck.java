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
 * What one rule of the cause classification found of an answer (quality plan 3.5): whether its cause applies, does not
 * apply, or could not be computed for this answer, why, and the values it read, each written {@code name=value}.
 *
 * @param cause   the cause the rule decides
 * @param state   what it came to
 * @param reason  why, as one of the reason codes of {@link QualityCauseClassifier}
 * @param details the values it read, such as {@code fact=OnCall} or {@code level=IDENTITY_AWARE}
 */
public record QualityCauseCheck(QualityCause cause, State state, String reason, List<String> details) {

    /** What a rule came to for an answer. */
    public enum State {
        /** The cause applies. */
        APPLIES,
        /** The rule was computed, and the cause does not apply. */
        CLEAR,
        /** The rule could not be computed for this answer: what it reads is not there. */
        NOT_COMPUTED
    }

    public QualityCauseCheck {
        Objects.requireNonNull(cause, "cause");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(reason, "reason");
        details = details == null ? List.of() : List.copyOf(details);
    }

    public boolean applies() {
        return state == State.APPLIES;
    }
}
