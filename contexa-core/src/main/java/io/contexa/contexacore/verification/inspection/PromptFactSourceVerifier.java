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

/**
 * W6-7 (P6-CHANGE-5): a host's own record of the facts a sealed prompt states. Given the sealed decision, the host
 * reads its sources again (its business records, its sign-in records) and says, for each fact it keeps, the piece of
 * the dictionary line the prompt must hold. The prompt inspector's source truth check compares them; without an
 * implementation the check records that no host source is integrated.
 */
public interface PromptFactSourceVerifier {

    /**
     * The facts the host keeps for the sealed decision; empty when it keeps none of them. A source that cannot be read
     * now throws {@link PromptInspectionUnavailableException}, so the package is inspected again later.
     */
    List<SourceFact> sourceFacts(PromptInspectionSubject subject);

    /**
     * One fact of the host's source: the block and entry of the dictionary line that states it, the piece of the
     * line's value the source gives, a piece the value must not hold for the fact to match (the negated form of the
     * same words, as {@code not on call} for {@code on call}; null when none), and where the host read it.
     */
    record SourceFact(PromptBlock block, String entry, String fragment, String excluded, String sourceRef) {
    }
}
