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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Which version a decision runs (plan 3.4), in this order:
 * <ol>
 * <li>the label of the screen: the version the registry marks as used for decisions, or the canary a request falls
 * inside, of the request's scope, else of the platform (the registry's selection, with its cache and invalidation);</li>
 * <li>the setting {@code contexa.security.tiered.prompt-bundle.active}, read for every decision, when it names a
 * version ({@code v2.0}) that exists and is not hidden;</li>
 * <li>the newest version Contexa provided.</li>
 * </ol>
 * A setting that names no such version is logged once as a warning and passed over until the version exists; one that
 * names an earlier bundle is logged once as a warning whatever runs. A label or a setting that names an earlier bundle
 * is not a version: earlier bundles are gone. The resolver is the decision's selector in every installation with the
 * console's database; without the registry (prompt governance turned off) it reads the setting and the newest version.
 * A prompt other than the security decision (plan 3.11) runs its label, else its newest Contexa version: the setting
 * names a version of the security decision.
 */
public class PromptVersionResolver implements PromptBundleSelector {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionResolver.class);
    private static final long PRODUCT_CACHE_MILLIS = 60_000L;

    private final PromptBundleSelector registry;
    private final PromptVersionService versions;
    private final Supplier<String> configured;
    private final Clock clock;
    private final Set<String> warned = ConcurrentHashMap.newKeySet();
    private final Map<String, CachedVersion> latestProduct = new ConcurrentHashMap<>();
    private final Map<String, CachedVersion> existing = new ConcurrentHashMap<>();

    private record CachedVersion(Optional<String> version, long readAt) {
    }

    /**
     * @param registry   the registry's selection (labels and canaries); none when the console has no registry
     * @param versions   the versions of the database
     * @param configured the setting {@code prompt-bundle.active}, read for each decision
     */
    public PromptVersionResolver(PromptBundleSelector registry, PromptVersionService versions, Supplier<String> configured,
                                 Clock clock) {
        this.registry = registry != null ? registry : (context, subject) -> PromptBundleSelection.none();
        this.versions = Objects.requireNonNull(versions, "versions");
        this.configured = configured != null ? configured : () -> null;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
        String prompt = context != null ? context.promptKey() : null;
        if (prompt == null || prompt.isBlank()) {
            return PromptBundleSelection.none();
        }
        // The setting names a version of the security decision; another prompt runs its label, else its newest Contexa
        // version (plan 3.11).
        String configuredName = SecurityDecisionPromptDocument.PROMPT.equals(prompt) ? configured.get() : null;
        String setting = configuredName != null && !configuredName.isBlank() ? configuredName.trim() : null;
        if (setting != null && PromptVersionNames.number(setting).isEmpty() && warned.add(prompt + "|" + setting)) {
            // Plan 3.4: a setting that names an earlier bundle is said once, whatever runs.
            log.warn("contexa.security.tiered.prompt-bundle.active names {}, an earlier bundle of {}: earlier bundles"
                    + " are gone and a version is named v1.0, v2.0 and so on; the label of the screen, else the newest"
                    + " Contexa version runs", setting, prompt);
        }
        PromptBundleSelection labelled = selection(() -> registry.select(context, subjectKey));
        if (labelled != null && isVersion(prompt, labelled.bundleVersion())) {
            return new PromptBundleSelection(PromptVersionNames.name(number(labelled.bundleVersion())), labelled.source());
        }
        if (setting != null && PromptVersionNames.number(setting).isPresent()) {
            if (isVersion(prompt, setting)) {
                return new PromptBundleSelection(PromptVersionNames.name(number(setting)),
                        PromptBundleSelectionSource.CONFIGURATION);
            }
            if (warned.add(prompt + "|" + setting)) {
                log.warn("contexa.security.tiered.prompt-bundle.active names {}, which is not a version of {} that"
                        + " exists and is shown; the newest Contexa version runs until it is", setting, prompt);
            }
        }
        return latest(prompt)
                .map(version -> new PromptBundleSelection(version, PromptBundleSelectionSource.BUILD_DEFAULT))
                .orElseGet(PromptBundleSelection::none);
    }

    @Override
    public PromptBundleSelection shadow(PromptGovernanceResolutionContext context, String subjectKey) {
        String prompt = context != null ? context.promptKey() : null;
        PromptBundleSelection shadow = selection(() -> registry.shadow(context, subjectKey));
        if (prompt != null && shadow != null && isVersion(prompt, shadow.bundleVersion())) {
            return new PromptBundleSelection(PromptVersionNames.name(number(shadow.bundleVersion())), shadow.source());
        }
        return PromptBundleSelection.none();
    }

    private PromptBundleSelection selection(Supplier<PromptBundleSelection> select) {
        try {
            return select.get();
        }
        catch (RuntimeException failure) {
            if (warned.add("registry")) {
                log.error("The registry selection of the prompt version failed; the setting and the newest Contexa"
                        + " version are read", failure);
            }
            return null;
        }
    }

    /** Whether the name is a version of the prompt that exists and is not hidden (checked once a minute per name). */
    private boolean isVersion(String prompt, String name) {
        OptionalInt number = PromptVersionNames.number(name);
        if (number.isEmpty()) {
            return false;
        }
        String key = prompt + "|" + number.getAsInt();
        long now = clock.millis();
        CachedVersion cached = existing.get(key);
        if (cached == null || now - cached.readAt() > PRODUCT_CACHE_MILLIS) {
            Optional<String> found;
            try {
                found = versions.find(PromptVersionService.PLATFORM_SCOPE, prompt, number.getAsInt())
                        .filter(record -> !record.hidden()).map(PromptVersionRecord::name);
            }
            catch (RuntimeException failure) {
                found = cached != null ? cached.version() : Optional.empty();
            }
            cached = new CachedVersion(found, now);
            existing.put(key, cached);
        }
        return cached.version().isPresent();
    }

    private Optional<String> latest(String prompt) {
        long now = clock.millis();
        CachedVersion cached = latestProduct.get(prompt);
        if (cached == null || now - cached.readAt() > PRODUCT_CACHE_MILLIS) {
            Optional<String> found;
            try {
                found = versions.latestProduct(PromptVersionService.PLATFORM_SCOPE, prompt).map(PromptVersionRecord::name);
            }
            catch (RuntimeException failure) {
                // The database cannot be read: the last version read, else the product document of the build.
                found = cached != null ? cached.version() : Optional.empty();
            }
            cached = new CachedVersion(found, now);
            latestProduct.put(prompt, cached);
        }
        return cached.version();
    }

    private static int number(String name) {
        return PromptVersionNames.number(name).orElseThrow();
    }
}
