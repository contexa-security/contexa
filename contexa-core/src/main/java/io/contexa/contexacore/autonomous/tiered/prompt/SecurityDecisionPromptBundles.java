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

import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The security decision bundles this build runs (W3-16): the current bundle and one previous bundle (version management
 * decision 2). A bundle is its descriptor, whose version names its manifest, and the user prompt layout its code draws.
 * Older manifests of the catalog are records of bundles no code of this build renders, so they cannot be run.
 */
public final class SecurityDecisionPromptBundles {

    /** The user prompt a bundle draws. */
    public enum UserPromptLayout {
        /** The v19 sections. */
        V19_SECTIONS,
        /** The v20 dictionary blocks (W3-2), with the second-pass layout for Layer2 (W3-9). */
        V20_BLOCKS
    }

    /**
     * @param descriptor the bundle's descriptor; its prompt version is the bundle version
     * @param layout     the user prompt the bundle draws
     */
    public record Bundle(PromptGovernanceDescriptor descriptor, UserPromptLayout layout) {

        public Bundle {
            Objects.requireNonNull(descriptor, "descriptor");
            Objects.requireNonNull(layout, "layout");
        }

        public String version() {
            return descriptor.promptVersion();
        }
    }

    /** The build's default bundle: the one a request runs when no selector chooses another. */
    public static final Bundle DEFAULT = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE, UserPromptLayout.V19_SECTIONS);

    public static final Bundle V20 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V20_PROMPT_GOVERNANCE, UserPromptLayout.V20_BLOCKS);

    public static final List<Bundle> ALL = List.of(DEFAULT, V20);

    private SecurityDecisionPromptBundles() {
    }

    /** The bundle of the given version, when this build runs it. */
    public static Optional<Bundle> find(String bundleVersion) {
        if (bundleVersion == null) {
            return Optional.empty();
        }
        String version = bundleVersion.trim();
        return ALL.stream().filter(bundle -> bundle.version().equals(version)).findFirst();
    }
}
