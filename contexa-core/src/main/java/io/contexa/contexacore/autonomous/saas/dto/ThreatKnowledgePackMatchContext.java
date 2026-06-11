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
package io.contexa.contexacore.autonomous.saas.dto;

import java.util.List;

public record ThreatKnowledgePackMatchContext(
        boolean applied,
        List<MatchedKnowledgeCase> matchedCases) {

    public ThreatKnowledgePackMatchContext {
        matchedCases = matchedCases == null ? List.of() : List.copyOf(matchedCases);
    }

    public static ThreatKnowledgePackMatchContext empty() {
        return new ThreatKnowledgePackMatchContext(false, List.of());
    }

    public boolean hasMatches() {
        return !matchedCases.isEmpty();
    }

    public record MatchedKnowledgeCase(
            ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase,
            List<String> matchedFacts) {

        public MatchedKnowledgeCase {
            matchedFacts = matchedFacts == null ? List.of() : List.copyOf(matchedFacts);
        }
    }
}