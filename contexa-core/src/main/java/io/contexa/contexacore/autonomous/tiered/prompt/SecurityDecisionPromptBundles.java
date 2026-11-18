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
 * The security decision bundle this build runs (plan 6-2): one, the product prompt of its release. What a decision's
 * prompt says and does beyond it is the version the decision runs (its parts and their effects), not another bundle:
 * the earlier bundles v19, v20 and v21 and the measured v1.0 variants are gone, and their functions are parts of the
 * product prompt document a version includes.
 */
public final class SecurityDecisionPromptBundles {

    /** The bundle: its descriptor, whose prompt version names its manifest. */
    public record Bundle(PromptGovernanceDescriptor descriptor) {

        public Bundle {
            Objects.requireNonNull(descriptor, "descriptor");
        }

        public String version() {
            return descriptor.promptVersion();
        }
    }

    /** v1.0, the product prompt and the build default. */
    public static final Bundle V1 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE);

    /** The build's default bundle: the one every request runs. */
    public static final Bundle DEFAULT = V1;

    public static final List<Bundle> ALL = List.of(V1);

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
