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
 * The closing rules of the engine as the scoring computes them from the server's settings (plan 3.3): the action a
 * decision ends in after the first answer. A first answer that does not defer is the action; an ESCALATE is followed by
 * the second pass, whose action that is not one of the four is replaced by CHALLENGE, and an ESCALATE left after the
 * second pass ends in the terminal action the server is set to (none while ESCALATE is allowed to stay). The overload
 * protection that ends an ESCALATE when one person's recent decisions defer too often depends on the load of the
 * moment, so a measurement cannot replay it and these rules leave it out ({@link #OVERLOAD_PROTECTION_LEFT_OUT}).
 *
 * @param escalateTerminalAction the action an ESCALATE left after the second pass ends in; null while ESCALATE stays
 */
public record QualityClosingRules(QualityAction escalateTerminalAction) {

    /** The action that replaces an action no rule of the engine can use. */
    public static final QualityAction UNUSABLE_ACTION_REPLACEMENT = QualityAction.CHALLENGE;

    /** What a measurement says of the overload protection, which it does not replay. */
    public static final String OVERLOAD_PROTECTION_LEFT_OUT = "ESCALATE_PROTECTION_NOT_REPLAYED";

    /** The rules of a server that ends an ESCALATE with CHALLENGE, as the engine does by default. */
    public static final QualityClosingRules DEFAULTS = new QualityClosingRules(QualityAction.CHALLENGE);

    public QualityClosingRules {
        if (escalateTerminalAction == QualityAction.ESCALATE) {
            escalateTerminalAction = null;
        }
    }

    /**
     * The action the decision ends in.
     *
     * @param firstAction        the action of the first answer as the pipeline answered it, or null without one
     * @param secondPassAnswered whether the second pass answered, as the measurement asked it after an ESCALATE
     * @param secondPassAction   the action of the second pass, or null without one
     * @return the final action, or null when it cannot be computed: the first answer has no action, or it deferred and
     *         the second pass gave no answer
     */
    public QualityAction finalAction(String firstAction, boolean secondPassAnswered, String secondPassAction) {
        if (firstAction == null || firstAction.isBlank()) {
            return null;
        }
        QualityAction first = usable(firstAction);
        if (first != QualityAction.ESCALATE) {
            return first;
        }
        if (!secondPassAnswered) {
            return null;
        }
        QualityAction second = secondPassAction == null || secondPassAction.isBlank()
                ? UNUSABLE_ACTION_REPLACEMENT : usable(secondPassAction);
        if (second == QualityAction.ESCALATE && escalateTerminalAction != null) {
            return escalateTerminalAction;
        }
        return second;
    }

    private static QualityAction usable(String action) {
        QualityAction parsed = QualityAction.parse(action);
        return parsed != null ? parsed : UNUSABLE_ACTION_REPLACEMENT;
    }
}
