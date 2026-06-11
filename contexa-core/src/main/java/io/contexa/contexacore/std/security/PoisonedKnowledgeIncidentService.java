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
package io.contexa.contexacore.std.security;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class PoisonedKnowledgeIncidentService {

    public KnowledgeIncident buildIncident(
            ContextProvenanceRecord provenanceRecord,
            String quarantineState,
            List<String> facts) {
        String artifactId = provenanceRecord != null && StringUtils.hasText(provenanceRecord.artifactId())
                ? provenanceRecord.artifactId()
                : "unknown-artifact";
        List<String> incidentFacts = new ArrayList<>();
        if (facts != null) {
            incidentFacts.addAll(facts);
        }
        if (provenanceRecord != null && StringUtils.hasText(provenanceRecord.summary())) {
            incidentFacts.add(provenanceRecord.summary());
        }
        String summary = String.format(
                Locale.ROOT,
                "Artifact %s entered %s state during runtime context authorization.",
                artifactId,
                StringUtils.hasText(quarantineState) ? quarantineState : "UNKNOWN");
        return new KnowledgeIncident(artifactId, quarantineState, summary, List.copyOf(incidentFacts));
    }

    public record KnowledgeIncident(
            String artifactId,
            String quarantineState,
            String summary,
            List<String> facts) {

        public KnowledgeIncident {
            facts = facts == null ? List.of() : List.copyOf(facts);
        }
    }
}