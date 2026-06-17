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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.SecurityResponse;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class SecurityDecisionResponse extends AIResponse {

    private Double riskScore;
    private Double confidence;
    private String action;
    private String reasoning;
    private String mitre;

    public SecurityResponse toSecurityResponse() {
        return SecurityResponse.builder()
                .riskScore(riskScore)
                .confidence(confidence)
                .action(action)
                .reasoning(reasoning)
                .mitre(mitre)
                .build();
    }

    public static SecurityDecisionResponse fromSecurityResponse(SecurityResponse response) {
        SecurityDecisionResponse decisionResponse = new SecurityDecisionResponse();
        if (response == null) {
            return decisionResponse;
        }
        decisionResponse.setRiskScore(response.getRiskScore());
        decisionResponse.setConfidence(response.getConfidence());
        decisionResponse.setAction(response.getAction());
        decisionResponse.setReasoning(response.getReasoning());
        decisionResponse.setMitre(response.getMitre());
        return decisionResponse;
    }

    public static SecurityDecisionResponse fromLite(SecurityDecisionResponseLite response) {
        SecurityDecisionResponse decisionResponse = new SecurityDecisionResponse();
        if (response == null) {
            return decisionResponse;
        }
        decisionResponse.setRiskScore(response.getRiskScore());
        decisionResponse.setConfidence(response.getConfidence());
        decisionResponse.setAction(response.getAction());
        decisionResponse.setReasoning(response.getReasoning());
        decisionResponse.setMitre(response.getMitre());
        return decisionResponse;
    }
}
