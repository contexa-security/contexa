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
package io.contexa.contexacore.autonomous.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityResponseTest {

    @Test
    void fromJsonParsesCurrentContractWithoutEvidenceField() {
        String json = """
                {
                  "action": "BLOCK",
                  "reasoning": "Impossible travel and new device were observed.",
                  "riskScore": 0.91,
                  "confidence": 0.84,
                  "mitre": "TA0001"
                }
                """;

        SecurityResponse response = SecurityResponse.fromJson(json);

        assertThat(response).isNotNull();
        assertThat(response.getAction()).isEqualTo("BLOCK");
        assertThat(response.getReasoning()).contains("Impossible travel");
        assertThat(response.getRiskScore()).isEqualTo(0.91);
        assertThat(response.getConfidence()).isEqualTo(0.84);
        assertThat(response.getMitre()).isEqualTo("TA0001");
    }
}
