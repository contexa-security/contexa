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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;

/**
 * Whether a release can run (plan 1-9, K1 and C9; plan 3.9). A version of the database ({@code v2.0}) runs when the
 * version table has it and it is not hidden; the release need not be in the build. A bundle of the build runs when the
 * catalog has its manifest: the catalog of the security decision may also hold the manifest of a bundle no code of
 * this build renders, which is a record only, and a request that names one runs the build's default bundle. A rollback
 * may therefore only target a release that runs, and the version screen tells the two apart. The catalog's other
 * prompts keep their rule: a manifest in the build is a bundle the build runs.
 */
public final class PromptBundleRunnability {

    private PromptBundleRunnability() {
    }

    /** Whether the release runs, a version read in the platform scope. */
    public static boolean runnable(PromptBundleCatalog catalog, String promptKey, String bundleVersion) {
        return runnable(catalog, PromptVersionCatalog.PLATFORM_SCOPE, promptKey, bundleVersion);
    }

    /**
     * Whether the release runs: a version of the scope that is in the version table and not hidden, or a bundle that
     * is in the catalog and that this build runs.
     */
    public static boolean runnable(PromptBundleCatalog catalog, String scope, String promptKey, String bundleVersion) {
        if (catalog == null || promptKey == null || bundleVersion == null) {
            return false;
        }
        if (PromptBundleCatalog.isVersionName(bundleVersion)) {
            return catalog.versions().runnable(scope != null && !scope.isBlank() ? scope.trim()
                    : PromptVersionCatalog.PLATFORM_SCOPE, promptKey, bundleVersion.trim());
        }
        if (catalog.find(promptKey, bundleVersion).isEmpty()) {
            return false;
        }
        if (SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE.promptKey().equals(promptKey)) {
            return SecurityDecisionPromptBundles.find(bundleVersion).isPresent();
        }
        return true;
    }
}
