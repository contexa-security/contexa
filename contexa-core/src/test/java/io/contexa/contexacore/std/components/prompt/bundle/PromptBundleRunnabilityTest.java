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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.9: a version of the database (v2.0) runs when the version table of its scope has it and it is not hidden; it
 * need not be in the build and never reads a manifest. A bundle keeps its rule: its manifest is in the build, and a
 * security decision manifest no code of this build draws is a record only (K1).
 */
class PromptBundleRunnabilityTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;

    @Test
    void aVersionRunsWhenItsScopeHasItAndItIsNotHidden() {
        PromptBundleCatalog catalog = PromptBundleCatalog.shared().withVersions(versions(
                new PromptVersionCatalog.Entry("PLATFORM_GLOBAL", PROMPT, 1, "a", null, "CONTEXA", false),
                new PromptVersionCatalog.Entry("PLATFORM_GLOBAL", PROMPT, 2, "b", 1, "ORGANIZATION", true),
                new PromptVersionCatalog.Entry("TENANT_A", PROMPT, 3, "c", 1, "ORGANIZATION", false)));

        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, "v1.0")).isTrue();
        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, " 1 ")).isTrue();
        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, "v2.0")).as("hidden").isFalse();
        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, "v4.0")).as("missing").isFalse();
        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, "v3.0")).as("of another scope").isFalse();
        assertThat(PromptBundleRunnability.runnable(catalog, "TENANT_A", PROMPT, "v3.0")).isTrue();
        assertThat(PromptBundleRunnability.runnable(catalog, "cortex.other", "v1.0")).isFalse();
        assertThat(PromptBundleRunnability.runnable(PromptBundleCatalog.shared(), PROMPT, "v1.0"))
                .as("a catalog without the version tables has no version").isFalse();
    }

    @Test
    void aBundleKeepsTheRuleOfItsManifest() {
        PromptBundleCatalog catalog = PromptBundleCatalog.shared().withVersions(versions());

        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, SecurityDecisionPromptBundles.V1.version())).isTrue();
        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, "2026.10.24-v19.21")).isFalse();
        assertThat(PromptBundleRunnability.runnable(catalog, PROMPT, null)).isFalse();
        assertThat(PromptBundleRunnability.runnable(null, PROMPT, "v1.0")).isFalse();
        assertThat(PromptBundleCatalog.isVersionName("v2.0")).isTrue();
        assertThat(PromptBundleCatalog.isVersionName(SecurityDecisionPromptBundles.V1.version())).isFalse();
    }

    private static PromptVersionCatalog versions(PromptVersionCatalog.Entry... entries) {
        return new PromptVersionCatalog() {
            @Override
            public List<Entry> versions(String scope, String prompt) {
                return List.of(entries).stream().filter(entry -> entry.scope().equals(scope)
                        && entry.prompt().equals(prompt)).toList();
            }

            @Override
            public Optional<AssembledPrompt> assembled(String scope, String prompt, String name) {
                return Optional.empty();
            }

            @Override
            public Optional<String> deciding(String scope, String prompt) {
                return Optional.empty();
            }

            @Override
            public boolean trialFinished(String scope, String prompt, String name) {
                return false;
            }
        };
    }
}
