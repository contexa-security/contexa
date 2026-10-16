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
package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptGovernanceDescriptorResolutionTest {

    /**
     * W4-7 (inventory 6, bundle 10): the open source static descriptor is the normal path and is recorded as STATIC;
     * FALLBACK is kept for a registry lookup that failed.
     */
    @Test
    void theStaticDescriptorIsTheNormalPathAndFallbackIsForAFailedLookup() {
        PromptGovernanceDescriptor descriptor = SecurityDecisionPromptBundles.V20.descriptor();
        PromptGovernanceResolutionContext context =
                new PromptGovernanceResolutionContext(null, null, null, null, null, null, null, Map.of());

        PromptGovernanceDescriptorResolution normal = PromptGovernanceDescriptorResolver.identity().resolve(descriptor, context);
        PromptGovernanceDescriptorResolution failed = PromptGovernanceDescriptorResolution.fallback(descriptor, context);

        assertThat(normal.descriptor()).isSameAs(descriptor);
        assertThat(normal.supplementalMetadata())
                .containsEntry("promptGovernanceCacheState", "STATIC")
                .containsEntry("governanceResolutionSource", "STATIC_PROMPT_DESCRIPTOR");
        assertThat(failed.supplementalMetadata()).containsEntry("promptGovernanceCacheState", "FALLBACK");
    }
}
