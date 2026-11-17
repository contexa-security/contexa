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
package io.contexa.contexacore.std.components.prompt.version;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The version a call of a prompt other than the security decision draws (plan 3.4, 3.11): the version the resolver
 * chooses for the prompt (the label of the screen, else the newest Contexa version), read from the store; the product
 * document of the build when there is no database, no such version or the database cannot be read. The selector and
 * the store are looked up at the first call, so a template can be made before them.
 */
public final class PromptVersionInUse {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionInUse.class);

    private final Supplier<PromptBundleSelector> selector;
    private final Supplier<PromptVersionStore> store;
    private final Set<String> reported = ConcurrentHashMap.newKeySet();

    /**
     * The version a call draws.
     *
     * @param version the version's parts
     * @param name    its name, {@code v2.0}; the product release when no store has a version
     * @param source  what chose it
     */
    public record Choice(AssembledPrompt version, String name, PromptBundleSelectionSource source) {

        public Choice {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(source, "source");
        }

        /** The descriptor of the call: the template's descriptor with the version and its content hash. */
        public PromptGovernanceDescriptor describe(PromptGovernanceDescriptor template) {
            return new PromptGovernanceDescriptor(template.promptKey(), template.templateKey(), name,
                    template.contractVersion(), template.releaseStatus(), template.owner(),
                    template.releaseApprovalReference(), template.evaluationBaselineReference(),
                    template.rollbackPromptVersion(), template.changeSummary() + " (content " + version.contentHash() + ")",
                    template.supportedModelProfiles(), template.templateClassName());
        }
    }

    /**
     * @param selector the resolver of the versions, none without the console's database
     * @param store    the store of the versions, none without the console's database
     */
    public PromptVersionInUse(Supplier<PromptBundleSelector> selector, Supplier<PromptVersionStore> store) {
        this.selector = selector != null ? selector : () -> null;
        this.store = store != null ? store : () -> null;
    }

    /** The product documents alone: every call draws the product version. */
    public static PromptVersionInUse productOnly() {
        return new PromptVersionInUse(() -> null, () -> null);
    }

    /**
     * The version a call of the prompt draws.
     *
     * @param prompt     the prompt key
     * @param product    the product version of the build
     * @param subjectKey the requester a canary share is drawn by; null when the call has none
     */
    public Choice choose(String prompt, AssembledPrompt product, String subjectKey) {
        Objects.requireNonNull(product, "product");
        try {
            PromptBundleSelector resolver = selector.get();
            PromptVersionStore versions = store.get();
            if (resolver != null && versions != null) {
                PromptBundleSelection selection = resolver.select(new PromptGovernanceResolutionContext(null, prompt,
                        prompt, null, null, null, null, Map.of()), subjectKey);
                if (selection != null && selection.bundleVersion() != null) {
                    Optional<AssembledPrompt> found = versions.find(prompt, selection.bundleVersion());
                    if (found.isPresent()) {
                        return new Choice(found.get(), selection.bundleVersion(), selection.source());
                    }
                }
            }
        }
        catch (RuntimeException failure) {
            if (reported.add(prompt)) {
                log.error("The version of the prompt {} cannot be read; its product document is drawn", prompt, failure);
            }
        }
        return new Choice(product, product.release(), PromptBundleSelectionSource.BUILD_DEFAULT);
    }
}
