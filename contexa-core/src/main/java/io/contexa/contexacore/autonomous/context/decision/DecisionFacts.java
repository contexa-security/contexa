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
package io.contexa.contexacore.autonomous.context.decision;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The decision facts of one request (W2-5), in the order the prompt states them. Every reader of the facts (the
 * prompt, the sealed record, the response inspector, the verification) reads this one computation.
 *
 * @param facts      the known facts, each with its ID ({@code F1}, ...)
 * @param deviations the request compared with the usual behaviour, dimension by dimension
 * @param policy     whether the company's policies are satisfied at the request time
 * @param unknown     the names of the facts the engine could not establish, for the prompt's UNKNOWN block
 * @param unavailable of those, the ones whose source could not give them for this request, with why (dictionary 1.4
 *                    unavailable-now); the others have nothing that gives them (not integrated)
 */
public record DecisionFacts(List<DecisionFact> facts, List<Deviation> deviations, PolicySatisfaction policy,
                            List<String> unknown, Map<String, String> unavailable) {

    public static final DecisionFacts NONE = new DecisionFacts(List.of(), List.of(), PolicySatisfaction.UNKNOWN,
            List.of());

    public DecisionFacts {
        facts = facts == null ? List.of() : List.copyOf(facts);
        deviations = deviations == null ? List.of() : List.copyOf(deviations);
        policy = policy == null ? PolicySatisfaction.UNKNOWN : policy;
        unknown = unknown == null ? List.of() : List.copyOf(unknown);
        unavailable = unavailable == null ? Map.of() : Map.copyOf(unavailable);
    }

    /** Facts whose unknown ones are all not integrated. */
    public DecisionFacts(List<DecisionFact> facts, List<Deviation> deviations, PolicySatisfaction policy,
                         List<String> unknown) {
        this(facts, deviations, policy, unknown, Map.of());
    }

    /**
     * The facts with the IDs the prompt drew for them, by fact name (W3-13); a fact the prompt did not draw has none.
     */
    public DecisionFacts withPromptIds(Map<String, String> ids) {
        Map<String, String> drawn = ids == null ? Map.of() : ids;
        List<DecisionFact> identified = new ArrayList<>();
        for (DecisionFact fact : facts) {
            identified.add(new DecisionFact(drawn.get(fact.name()), fact.name(), fact.value(), fact.codes(),
                    fact.recordIds(), fact.source()));
        }
        return new DecisionFacts(identified, deviations, policy, unknown, unavailable);
    }

    /** The fact of that name, if the request has one. */
    public Optional<DecisionFact> fact(String name) {
        return facts.stream().filter(fact -> fact.name().equals(name)).findFirst();
    }

    /** The differences no record explains: the ones the minimum-action rules count. */
    public List<Deviation> unexplained() {
        return deviations.stream()
                .filter(deviation -> deviation.different()
                        && deviation.explanation() == Deviation.Explanation.UNEXPLAINED)
                .toList();
    }
}
