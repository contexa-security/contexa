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

import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Plan 3.9: the product policy a version inherits from its Contexa base, which an organization's version cannot change:
 * the model profiles the prompt is compatible with, its budget profiles and the token counting, cache and compaction
 * policies that govern them. The release gate reads it for a version where it reads the compatibility and budget
 * ledgers for a bundle, so MODEL_COMPATIBILITY_MISSING, BUDGET_PROFILE_MISSING, TOKEN_COUNTING_POLICY_MISSING,
 * CACHE_POLICY_MISSING and COMPACTION_POLICY_MISSING are always met by a version; the gate does not start when the
 * product declares one of them not ({@link #verify()}).
 */
public final class ProductPromptPolicy {

    private static final String PROVIDER_COMPATIBILITY = "PROVIDER_COMPATIBILITY";

    /**
     * The policy of a prompt's product.
     *
     * @param modelProfiles          the model profiles the product declares
     * @param providerCompatibility  whether one of them declares the compatibility with the model providers
     * @param budgetProfiles         the budget profiles its prompts are drawn within
     */
    public record Policy(String promptKey, List<String> modelProfiles, boolean providerCompatibility,
                         List<String> budgetProfiles, String tokenCountingPolicy, String cachePolicy,
                         String compactionPolicy) {

        public Policy {
            modelProfiles = List.copyOf(modelProfiles);
            budgetProfiles = List.copyOf(budgetProfiles);
        }

        /** What the product does not declare, by the gate's blocker name; empty when the policy is whole. */
        public List<String> gaps() {
            List<String> gaps = new ArrayList<>();
            if (modelProfiles.isEmpty() || !providerCompatibility) {
                gaps.add("MODEL_COMPATIBILITY_MISSING");
            }
            if (budgetProfiles.isEmpty()) {
                gaps.add("BUDGET_PROFILE_MISSING");
            }
            if (!StringUtils.hasText(tokenCountingPolicy)) {
                gaps.add("TOKEN_COUNTING_POLICY_MISSING");
            }
            if (!StringUtils.hasText(cachePolicy)) {
                gaps.add("CACHE_POLICY_MISSING");
            }
            if (!StringUtils.hasText(compactionPolicy)) {
                gaps.add("COMPACTION_POLICY_MISSING");
            }
            return List.copyOf(gaps);
        }
    }

    private ProductPromptPolicy() {
    }

    /** The product policy of the prompt, from the descriptor of the product the build ships; empty for another prompt. */
    public static Optional<Policy> of(String promptKey) {
        return PromptGovernanceRegistryService.platformStandardDescriptors().stream()
                .filter(descriptor -> descriptor.promptKey().equals(promptKey))
                .findFirst()
                .map(ProductPromptPolicy::of);
    }

    static Policy of(PromptGovernanceDescriptor descriptor) {
        List<String> profiles = descriptor.supportedModelProfiles() != null
                ? descriptor.supportedModelProfiles().stream().filter(StringUtils::hasText).toList() : List.of();
        boolean provider = profiles.stream().anyMatch(profile -> PROVIDER_COMPATIBILITY.equals(
                PromptGovernanceModelCompatibilityRegistryService.resolveProfileCategory(profile)));
        return new Policy(descriptor.promptKey(), profiles, provider,
                Arrays.stream(PromptBudgetProfile.values()).map(PromptBudgetProfile::profileKey).toList(),
                PromptGovernanceModelCompatibilityRegistryService.TOKEN_COUNTING_POLICY_KEY,
                PromptGovernanceModelCompatibilityRegistryService.CACHE_POLICY_KEY,
                PromptGovernanceModelCompatibilityRegistryService.COMPACTION_POLICY_KEY);
    }

    /** Fails when the product of a prompt the build ships does not declare its whole policy. */
    public static void verify() {
        for (PromptGovernanceDescriptor descriptor : PromptGovernanceRegistryService.platformStandardDescriptors()) {
            verify(of(descriptor));
        }
    }

    static void verify(Policy policy) {
        List<String> gaps = policy.gaps();
        if (!gaps.isEmpty()) {
            throw new IllegalStateException("The product of " + policy.promptKey() + " does not declare the policy"
                    + " its versions inherit: " + gaps);
        }
    }
}
