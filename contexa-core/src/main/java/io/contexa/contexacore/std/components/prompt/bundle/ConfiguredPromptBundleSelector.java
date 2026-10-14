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
package io.contexa.contexacore.std.components.prompt.bundle;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;

/**
 * The OSS default selector: the bundle named by {@code contexa.security.tiered.prompt-bundle.active}, the same for
 * every request. Without a name the build's default bundle runs.
 */
public final class ConfiguredPromptBundleSelector implements PromptBundleSelector {

    private final PromptBundleSelection selection;

    public ConfiguredPromptBundleSelector(String activeBundleVersion) {
        this.selection = activeBundleVersion == null || activeBundleVersion.isBlank()
                ? PromptBundleSelection.none()
                : new PromptBundleSelection(activeBundleVersion, PromptBundleSelectionSource.CONFIGURATION);
    }

    @Override
    public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
        return selection;
    }
}
