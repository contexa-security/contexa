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
 * decision 2), and the v19 bundle the build runs by default while v21 is measured against v20 (V-1). A bundle is its
 * descriptor, whose version names its manifest, and the user prompt layout its code draws.
 * Older manifests of the catalog are records of bundles no code of this build renders, so they cannot be run.
 */
public final class SecurityDecisionPromptBundles {

    /** The user prompt a bundle draws. */
    public enum UserPromptLayout {
        /** The v19 sections. */
        V19_SECTIONS,
        /** The v20 dictionary blocks (W3-2), with the second-pass layout for Layer2 (W3-9). */
        V20_BLOCKS,
        /**
         * The v21 dictionary blocks: the v20 blocks with facts that state records, measurements and comparisons and no
         * conclusion of the core, read by a system text without decision rules (the model judges, V-1 to V-4).
         */
        V21_BLOCKS;

        /** Whether the layout draws the dictionary blocks (v20 and v21): its past records, second pass and output contract. */
        public boolean dictionaryBlocks() {
            return this == V20_BLOCKS || this == V21_BLOCKS;
        }
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

    /** The v21 bundle: the model judges from records and comparisons; no decision rule, floor or later enforcement. */
    public static final Bundle V21 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V21_PROMPT_GOVERNANCE, UserPromptLayout.V21_BLOCKS);

    public static final List<Bundle> ALL = List.of(DEFAULT, V20, V21);

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
