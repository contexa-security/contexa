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
import java.util.Locale;

/**
 * The cause a wrong answer of a measurement, or a decision an administrator rated inadequate, is put down to (quality
 * plan 3.5). The rules decide the first seven, in this order of precedence: an answer that falls under several is put
 * down to the first of them.
 * <ol>
 *     <li>{@link #FORMAT_AND_MODEL} first: no answer of the model set the action (none came, or the engine replaced an
 *     answer that broke the contract), or the call ran over the time limit of the decisions, so the action says
 *     nothing of what the model judged. Every later cause supposes a judgement of the model that was used.</li>
 *     <li>{@link #ENGINE_CHANGED}: the model's own action was right, so what made the action wrong is the rule that
 *     changed it, whatever the input or the citations were.</li>
 *     <li>{@link #INPUT_ERROR}: a fact of the prompt is not what the host's records say, so the judgement stood on a
 *     wrong input; a wrong fact goes before a missing one.</li>
 *     <li>{@link #INPUT_SHORTAGE}: a fact that decides the answer was unknown to the prompt, or the context was low,
 *     so the model could not know it.</li>
 *     <li>{@link #GROUNDING_ERROR}: what the answer itself says is wrong: it cites a fact the prompt does not have, or
 *     a line that does not say it.</li>
 *     <li>{@link #UNSTABLE}: the same case gives another action in another run, so the wrong action is no steady
 *     judgement that a new version would change.</li>
 *     <li>{@link #JUDGEMENT_ERROR} last: the citations are right and the action is still outside the answer.</li>
 * </ol>
 * An answer no rule puts down to a cause, because none applies or the ones that might could not be computed, is
 * {@link #UNCLASSIFIED} until an administrator puts it down to one.
 */
public enum QualityCause {
    /** No answer, an answer that broke the contract and was replaced by the engine, or a call over the time limit. */
    FORMAT_AND_MODEL(QualityCauseFix.MODEL_SETTING),
    /** The model's own action was right and a rule of the engine changed it. */
    ENGINE_CHANGED(QualityCauseFix.RULE_SETTING),
    /** A fact of the prompt differs from the host's records of it (the evidence audit); decisions only. */
    INPUT_ERROR(QualityCauseFix.COLLECTOR_OR_RECORDS),
    /** A fact that decides the answer is on the prompt's list of unknown facts, or the context level is low. */
    INPUT_SHORTAGE(QualityCauseFix.INTEGRATION),
    /** A cited fact is not in the prompt, or its line does not say what the answer says. */
    GROUNDING_ERROR(QualityCauseFix.PROMPT_OR_MODEL),
    /** The same case gives different actions from run to run. */
    UNSTABLE(QualityCauseFix.PROMPT_OR_MODEL),
    /** The citations are right, and the action is outside the answer. */
    JUDGEMENT_ERROR(QualityCauseFix.PROMPT_VERSION),
    /** No rule puts the answer down to a cause. */
    UNCLASSIFIED(null);

    /** The causes the rules decide, in their order of precedence. */
    public static final List<QualityCause> RULED = List.of(FORMAT_AND_MODEL, ENGINE_CHANGED, INPUT_ERROR,
            INPUT_SHORTAGE, GROUNDING_ERROR, UNSTABLE, JUDGEMENT_ERROR);

    private final QualityCauseFix fix;

    QualityCause(QualityCauseFix fix) {
        this.fix = fix;
    }

    /** Where an answer put down to this cause is fixed; null for {@link #UNCLASSIFIED}. */
    public QualityCauseFix fix() {
        return fix;
    }

    /** Whether only a decision can be put down to this cause: a measured case's input is the one it was labelled on. */
    public boolean decisionsOnly() {
        return this == INPUT_ERROR;
    }

    /** The cause of the name, ignoring case and surrounding blanks, or null when the name is none. */
    public static QualityCause parse(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        String wanted = name.trim().toUpperCase(Locale.ROOT);
        for (QualityCause cause : values()) {
            if (cause.name().equals(wanted)) {
                return cause;
            }
        }
        return null;
    }
}
