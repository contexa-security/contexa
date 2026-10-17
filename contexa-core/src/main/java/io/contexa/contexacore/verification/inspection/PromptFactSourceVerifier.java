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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;

import java.util.List;
import java.util.Objects;

/**
 * W6-7 (P6-CHANGE-5): a host's own record of the facts a sealed prompt states. Given the sealed decision, the host
 * reads its sources again (its business records, its sign-in records) and says, for each fact it keeps, the piece of
 * the dictionary line the prompt must hold. The prompt inspector's source truth check compares them; without an
 * implementation the check records that no host source is integrated. A host whose records of a decision can be gone
 * says so through {@link #read} (N-SRC-2).
 */
public interface PromptFactSourceVerifier {

    /**
     * The facts the host keeps for the sealed decision; empty when it keeps none of them. A source that cannot be read
     * now throws {@link PromptInspectionUnavailableException}, so the package is inspected again later.
     */
    List<SourceFact> sourceFacts(PromptInspectionSubject subject);

    /**
     * N-SRC-2: what the host reads for the sealed decision, which the source truth check takes: the facts of
     * {@link #sourceFacts}, or that the host does not keep the records of the decision, as the run rows the showcase
     * removes when a run ends. The default gives the facts as kept, so a host whose records stay implements
     * {@link #sourceFacts} only; a host whose records can be gone overrides this, and the check then counts the facts
     * as not compared instead of counting nothing.
     */
    default SourceReading read(PromptInspectionSubject subject) {
        return SourceReading.kept(sourceFacts(subject));
    }

    /**
     * One fact of the host's source: the block and entry of the dictionary line that states it, the piece of the
     * line's value the source gives, a piece the value must not hold for the fact to match (the negated form of the
     * same words, as {@code not on call} for {@code on call}; null when none), and where the host read it.
     */
    record SourceFact(PromptBlock block, String entry, String fragment, String excluded, String sourceRef) {
    }

    /**
     * N-SRC-2: what the host read for the sealed decision. Its records kept: their facts, empty when it keeps none of
     * them. Its records not kept: no facts, and where the host looked ({@code notKeptRef}), which the check names.
     */
    record SourceReading(List<SourceFact> facts, String notKeptRef) {

        public SourceReading {
            facts = facts == null ? List.of() : List.copyOf(facts);
            if (notKeptRef != null && (notKeptRef.isBlank() || !facts.isEmpty())) {
                throw new IllegalArgumentException("records not kept name where the host looked and hold no facts");
            }
        }

        /** The facts of the records the host keeps; empty when it keeps none of them. */
        public static SourceReading kept(List<SourceFact> facts) {
            return new SourceReading(facts, null);
        }

        /** The host does not keep the records of the decision; {@code sourceRef} names where it looked. */
        public static SourceReading notKept(String sourceRef) {
            return new SourceReading(List.of(), Objects.requireNonNull(sourceRef, "sourceRef"));
        }

        /** Whether the host keeps the records of the decision. */
        public boolean recordsKept() {
            return notKeptRef == null;
        }
    }
}
