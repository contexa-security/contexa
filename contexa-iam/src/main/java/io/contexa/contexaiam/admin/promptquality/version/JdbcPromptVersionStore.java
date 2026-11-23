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

import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The versions the engine runs, from the database (plan 3.8, 2 and 7): a version name ({@code v2.0}) of the platform
 * scope, or of the scope asked for, assembled once and kept. A product version is found by its release as well, so an
 * event that names the release still runs it. When the database cannot be read the version is not found and the
 * engine runs the product document; the first failure is logged once.
 */
public class JdbcPromptVersionStore implements PromptVersionStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcPromptVersionStore.class);

    private final PromptVersionService versions;
    private final PromptVersionStore fallback;
    private final AtomicBoolean reported = new AtomicBoolean();

    /**
     * @param versions the versions of the database
     * @param fallback the product versions the build ships, found by their release
     */
    public JdbcPromptVersionStore(PromptVersionService versions, PromptVersionStore fallback) {
        this.versions = Objects.requireNonNull(versions, "versions");
        this.fallback = Objects.requireNonNull(fallback, "fallback");
    }

    @Override
    public Optional<AssembledPrompt> find(String prompt, String version) {
        return find(PromptVersionService.PLATFORM_SCOPE, prompt, version);
    }

    /**
     * Quality plan 3.2: a version name of the registry scope (a replay of a labelled case reads the version of its
     * measurement's scope); a product version by its release, as in every scope.
     */
    @Override
    public Optional<AssembledPrompt> find(String scope, String prompt, String version) {
        OptionalInt number = PromptVersionNames.number(version);
        if (number.isEmpty()) {
            return fallback.find(prompt, version);
        }
        String scopeName = scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
        try {
            return versions.assembled(scopeName, prompt, number.getAsInt());
        }
        catch (RuntimeException failure) {
            if (reported.compareAndSet(false, true)) {
                log.error("Prompt version {} of {} cannot be read from the database; the product document runs",
                        version, prompt, failure);
            }
            return Optional.empty();
        }
    }
}
