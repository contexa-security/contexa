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
package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.9: MODEL_COMPATIBILITY_MISSING, BUDGET_PROFILE_MISSING, TOKEN_COUNTING_POLICY_MISSING, CACHE_POLICY_MISSING and
 * COMPACTION_POLICY_MISSING are the product policy a version inherits and an organization cannot change: every prompt
 * the build ships declares it whole, and the start fails when one does not.
 */
class ProductPromptPolicyTest {

    @Test
    void everyShippedPromptDeclaresItsWholePolicy() {
        assertThatCode(ProductPromptPolicy::verify).doesNotThrowAnyException();
        ProductPromptPolicy.Policy decision = ProductPromptPolicy.of(SecurityDecisionPromptDocument.PROMPT).orElseThrow();

        assertThat(decision.gaps()).isEmpty();
        assertThat(decision.providerCompatibility()).isTrue();
        assertThat(decision.budgetProfiles()).isNotEmpty();
        assertThat(ProductPromptPolicy.of("cortex.unshipped")).isEmpty();
    }

    @Test
    void aProductThatDeclaresPartOfItsPolicyFailsTheStart() {
        ProductPromptPolicy.Policy partial = new ProductPromptPolicy.Policy("cortex.partial", List.of("LOCAL_ONLY"),
                false, List.of(), "MODEL_AWARE_TOKEN_COUNTING_V1", " ", null);

        assertThat(partial.gaps()).containsExactly("MODEL_COMPATIBILITY_MISSING", "BUDGET_PROFILE_MISSING",
                "CACHE_POLICY_MISSING", "COMPACTION_POLICY_MISSING");
        assertThatThrownBy(() -> ProductPromptPolicy.verify(partial)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cortex.partial").hasMessageContaining("CACHE_POLICY_MISSING");
        assertThat(new ProductPromptPolicy.Policy("cortex.none", List.of(), true, List.of("B"), null, "C", "D").gaps())
                .containsExactly("MODEL_COMPATIBILITY_MISSING", "TOKEN_COUNTING_POLICY_MISSING");
    }
}
