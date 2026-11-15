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

/**
 * Whether this build can run a bundle of the catalog (plan 1-9, K1 and C9). The catalog of the security decision also
 * holds the manifests of earlier bundles that no code of this build renders; they are records only, and a request
 * that names one runs the build's default bundle. A rollback may therefore only target a bundle this build runs, and
 * the version screen tells the two apart. The catalog's other prompts keep their rule: a manifest in the build is a
 * bundle the build runs.
 */
public final class PromptBundleRunnability {

    private PromptBundleRunnability() {
    }

    /** Whether the bundle is in the catalog and this build runs it. */
    public static boolean runnable(PromptBundleCatalog catalog, String promptKey, String bundleVersion) {
        if (catalog == null || promptKey == null || bundleVersion == null
                || catalog.find(promptKey, bundleVersion).isEmpty()) {
            return false;
        }
        if (SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE.promptKey().equals(promptKey)) {
            return SecurityDecisionPromptBundles.find(bundleVersion).isPresent();
        }
        return true;
    }
}
