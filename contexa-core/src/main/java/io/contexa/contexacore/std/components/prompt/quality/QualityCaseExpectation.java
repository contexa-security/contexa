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
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The right answer of a labelled case (plan 3.2).
 *
 * @param allowedActions  the actions that count as right, such as BLOCK, CHALLENGE and ESCALATE for a threat
 * @param preferredAction the most desirable of them, or null when nothing says which one it is
 * @param classification  the class of the request
 * @param kind            who is behind the request
 * @param rationale       why this is the answer
 * @param decidingFacts   the facts that decide the answer, when they are known
 */
public record QualityCaseExpectation(Set<QualityAction> allowedActions, QualityAction preferredAction,
                                     QualityCaseClass classification, QualityCaseKind kind,
                                     QualityCaseRationale rationale, List<String> decidingFacts) {

    public QualityCaseExpectation {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(rationale, "rationale");
        if (allowedActions == null || allowedActions.isEmpty()) {
            throw new IllegalArgumentException("A labelled case needs at least one allowed action");
        }
        allowedActions = Collections.unmodifiableSet(EnumSet.copyOf(allowedActions));
        if (preferredAction != null && !allowedActions.contains(preferredAction)) {
            throw new IllegalArgumentException("The preferred action " + preferredAction + " is not an allowed action");
        }
        decidingFacts = decidingFacts == null ? List.of() : List.copyOf(decidingFacts);
    }

    /** Whether the action is one of the allowed ones. */
    public boolean allows(QualityAction action) {
        return action != null && allowedActions.contains(action);
    }
}
