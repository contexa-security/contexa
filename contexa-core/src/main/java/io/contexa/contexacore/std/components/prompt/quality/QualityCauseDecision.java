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
 * A decision an administrator rated inadequate, as the cause classification reads its record (quality plan 3.5, 3.6):
 * who set the action, what the model proposed and what the decision ended in, how the model call ended, the context
 * the prompt was drawn at, the citations, and what the evidence audit found of its facts.
 *
 * @param decisionSource       who set the action: {@code MODEL}, {@code ENGINE_CHANGED} or {@code MODEL_LESS}; null on
 *                             a record written before the decision source was kept
 * @param changeCause          what changed the model's action, or why no model set it; null for none
 * @param proposedAction       the action the model's answer proposed, or null
 * @param finalAction          the action the decision ended in, or null
 * @param modelDecisionPresent whether a decision of the model was there; null when not recorded
 * @param timedOut             whether the model call ran out of its time limit
 * @param technicalFallback    whether the engine set the action because the model call failed
 * @param parserFailure        whether the model's answer could not be read
 * @param modelUnavailable     whether the model could not be reached
 * @param contextLevel         the context coverage level the prompt was drawn at, or null
 * @param unknownFacts         the facts the prompt named unknown
 * @param citations            what the response check found of the citations of the answer that was kept
 * @param sourceTruth          what the evidence audit found of the facts compared with the host's own records
 * @param evaluationReason     the reason the administrator gave, or null
 */
public record QualityCauseDecision(String decisionSource, String changeCause, QualityAction proposedAction,
                                   QualityAction finalAction, Boolean modelDecisionPresent, boolean timedOut,
                                   boolean technicalFallback, boolean parserFailure, boolean modelUnavailable,
                                   String contextLevel, List<String> unknownFacts, QualityCauseCitations citations,
                                   SourceTruth sourceTruth, String evaluationReason) {

    /** The decision source of an action the model's answer set. */
    public static final String SOURCE_MODEL = "MODEL";
    /** The decision source of an action the engine changed over the model's answer. */
    public static final String SOURCE_ENGINE_CHANGED = "ENGINE_CHANGED";
    /** The decision source of an action the engine set without a usable answer of the model. */
    public static final String SOURCE_MODEL_LESS = "MODEL_LESS";

    /**
     * What the evidence audit found of the facts of the decision compared with the host's own records (the source truth
     * check of the sealed decision).
     *
     * @param state        whether the decision was sealed and its seal inspected with that check
     * @param matched      the facts that matched the host's records
     * @param mismatched   the facts the host's records state otherwise
     * @param unverifiable the facts that could not be compared
     */
    public record SourceTruth(State state, int matched, int mismatched, int unverifiable) {

        /** No seal: the decision was not sealed, or its seal is gone. */
        public static final SourceTruth NOT_SEALED = new SourceTruth(State.NOT_SEALED, 0, 0, 0);
        /** Sealed, and no evidence audit compared its facts with the host's records. */
        public static final SourceTruth NOT_INSPECTED = new SourceTruth(State.NOT_INSPECTED, 0, 0, 0);

        public enum State {
            NOT_SEALED,
            NOT_INSPECTED,
            INSPECTED
        }

        public SourceTruth {
            Objects.requireNonNull(state, "state");
        }

        public static SourceTruth inspected(int matched, int mismatched, int unverifiable) {
            return new SourceTruth(State.INSPECTED, Math.max(0, matched), Math.max(0, mismatched),
                    Math.max(0, unverifiable));
        }
    }

    public QualityCauseDecision {
        unknownFacts = unknownFacts == null ? List.of() : List.copyOf(unknownFacts);
        citations = citations != null ? citations : QualityCauseCitations.NOT_CHECKED;
        sourceTruth = sourceTruth != null ? sourceTruth : SourceTruth.NOT_SEALED;
    }
}
