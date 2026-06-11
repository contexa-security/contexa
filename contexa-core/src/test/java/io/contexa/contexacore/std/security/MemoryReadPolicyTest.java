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

import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MemoryReadPolicyTest {

    private final MemoryReadPolicy policy = new MemoryReadPolicy();

    @Test
    void evaluateShouldAllowPromotedMemoryArtifact() {
        MemoryReadDecision decision = policy.evaluate(new Document(
                "Validated long-term memory.",
                Map.of("documentType", "memory_ltm", "promotionState", "PROMOTED")));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.decision()).isEqualTo("ALLOWED_MEMORY_PROMOTED");
    }

    @Test
    void evaluateShouldDenyUnpromotedMemoryArtifact() {
        MemoryReadDecision decision = policy.evaluate(new Document(
                "Unreviewed long-term memory.",
                Map.of("documentType", "memory_ltm")));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.decision()).isEqualTo("DENIED_MEMORY_PROMOTION");
    }
}