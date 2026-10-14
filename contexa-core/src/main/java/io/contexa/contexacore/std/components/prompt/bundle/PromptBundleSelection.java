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

import java.util.Objects;

/**
 * A selector's choice: the bundle version to run and what chose it. A choice without a version leaves the request to
 * the build's default bundle.
 *
 * @param bundleVersion the chosen bundle version, or null for no choice
 * @param source        what chose it
 */
public record PromptBundleSelection(String bundleVersion, PromptBundleSelectionSource source) {

    private static final PromptBundleSelection NONE = new PromptBundleSelection(null, PromptBundleSelectionSource.BUILD_DEFAULT);

    public PromptBundleSelection {
        bundleVersion = bundleVersion == null || bundleVersion.isBlank() ? null : bundleVersion.trim();
        source = Objects.requireNonNull(source, "source");
    }

    /** No choice: the build's default bundle runs. */
    public static PromptBundleSelection none() {
        return NONE;
    }
}
