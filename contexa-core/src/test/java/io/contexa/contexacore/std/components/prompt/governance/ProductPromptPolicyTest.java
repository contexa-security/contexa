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
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.9: MODEL_COMPATIBILITY_MISSING, BUDGET_PROFILE_MISSING, TOKEN_COUNTING_POLICY_MISSING, CACHE_POLICY_MISSING and
 * COMPACTION_POLICY_MISSING are the product policy a version inherits and an organization cannot change: every prompt
 * the build ships declares it whole, the security decision and the prompts other than it (plan 3.11, K79), and the
 * start fails when one does not.
 */
class ProductPromptPolicyTest {

    private static final VersionedPrompts QUERIES = new VersionedPrompts(new ArrayList<>(QueryTransformPrompt.ALL));

    @Test
    void everyShippedPromptDeclaresItsWholePolicy() {
        assertThatCode(() -> ProductPromptPolicy.verify(QUERIES)).doesNotThrowAnyException();
        ProductPromptPolicy.Policy decision = ProductPromptPolicy.of(SecurityDecisionPromptDocument.PROMPT, null)
                .orElseThrow();

        assertThat(decision.gaps()).isEmpty();
        assertThat(decision.providerCompatibility()).isTrue();
        assertThat(decision.budgetProfiles()).isNotEmpty();
        assertThat(ProductPromptPolicy.of("cortex.unshipped", QUERIES)).isEmpty();
    }

    /** K79: a prompt other than the security decision has the policy its product declares, and none without it. */
    @Test
    void aPromptOtherThanTheSecurityDecisionHasThePolicyOfItsProduct() {
        for (QueryTransformPrompt query : QueryTransformPrompt.ALL) {
            ProductPromptPolicy.Policy policy = ProductPromptPolicy.of(query.prompt(), QUERIES).orElseThrow();

            assertThat(policy.gaps()).as(query.prompt()).isEmpty();
            assertThat(policy.modelProfiles()).as(query.prompt())
                    .containsExactly(PromptGovernanceSupport.PROVIDER_COMPATIBLE_MODEL_PROFILE);
            assertThat(ProductPromptPolicy.of(query.prompt(), null)).as("the build does not ship it").isEmpty();
        }
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

    /** K79: another prompt whose product declares no compatible model profile fails the start too. */
    @Test
    void anotherPromptWithoutACompatibleModelProfileFailsTheStart() {
        PromptGovernanceDescriptor undeclared = PromptGovernanceSupport.buildDefaultDescriptor("cortex.undeclared",
                ProductPromptPolicyTest.class);
        VersionedPrompts prompts = new VersionedPrompts(List.of(new VersionedPrompt() {
            @Override
            public String prompt() {
                return undeclared.promptKey();
            }

            @Override
            public List<ProductPromptRelease> productReleases() {
                return List.of();
            }

            @Override
            public AssembledPrompt product() {
                return null;
            }

            @Override
            public PromptGovernanceDescriptor registryDescriptor() {
                return undeclared;
            }

            @Override
            public Example example(AssembledPrompt version) {
                return new Example("", "");
            }
        }));

        assertThat(ProductPromptPolicy.of("cortex.undeclared", prompts).orElseThrow().gaps())
                .containsExactly("MODEL_COMPATIBILITY_MISSING");
        assertThatThrownBy(() -> ProductPromptPolicy.verify(prompts)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cortex.undeclared").hasMessageContaining("MODEL_COMPATIBILITY_MISSING");
    }
}
