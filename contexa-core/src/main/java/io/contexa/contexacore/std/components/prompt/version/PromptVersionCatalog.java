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

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * The versions of the prompts the database keeps, as the release machinery reads them (plan 3.9): the release gate,
 * the rollback, the runnability of a release, the shadow run and the replay of a sealed decision read a version here,
 * where they read a manifest of the build for a bundle. The database implementation lives beside the registry; without
 * it there is no version, and every name reads as none.
 */
public interface PromptVersionCatalog {

    /** The scope of the platform, as the registry names it. */
    String PLATFORM_SCOPE = "PLATFORM_GLOBAL";
    /** The provider of the versions Contexa ships (the product documents). */
    String CONTEXA = "CONTEXA";

    /**
     * A version as the release machinery reads it.
     *
     * @param scope         the registry scope the version was saved in
     * @param number        its number ({@code 2} for {@code v2.0})
     * @param contentHash   the content hash of the prompt it draws
     * @param basedOnNumber the number of its base, null for a product version
     * @param provider      CONTEXA or ORGANIZATION
     * @param hidden        whether it is hidden from the lists (it still opens, but no longer decides)
     */
    record Entry(String scope, String prompt, int number, String contentHash, Integer basedOnNumber, String provider,
                 boolean hidden) {

        /** The name a screen shows and an event names: {@code v2.0}. */
        public String name() {
            return PromptVersionNames.name(number);
        }

        /** Whether Contexa provided the version. */
        public boolean contexa() {
            return CONTEXA.equals(provider);
        }
    }

    /** The versions of the prompt in the scope, newest first, the hidden ones included. */
    List<Entry> versions(String scope, String prompt);

    /**
     * The version the name stands for in the scope, hidden or not; empty when the name is no version name ({@code v2.0})
     * or no version of the prompt has its number.
     */
    default Optional<Entry> find(String scope, String prompt, String name) {
        OptionalInt number = PromptVersionNames.number(name);
        if (number.isEmpty() || prompt == null) {
            return Optional.empty();
        }
        return versions(scope, prompt).stream().filter(entry -> entry.number() == number.getAsInt()).findFirst();
    }

    /** Whether the name stands for a version of the prompt in the scope that is not hidden: a version that may decide. */
    default boolean runnable(String scope, String prompt, String name) {
        return find(scope, prompt, name).filter(entry -> !entry.hidden()).isPresent();
    }

    /** The versions of the prompt in the scope that may decide, newest first. */
    default List<Entry> shown(String scope, String prompt) {
        return versions(scope, prompt).stream().filter(entry -> !entry.hidden()).toList();
    }

    /** The assembled version the name stands for (its parts, as a decision draws them); empty when there is none. */
    Optional<AssembledPrompt> assembled(String scope, String prompt, String name);

    /**
     * The version the decisions of the scope run now (plan 3.4), apart from a canary: the label of the scope, else the
     * label of the platform, else the version the setting names, else the newest Contexa version. Empty when the
     * database has no version of the prompt.
     */
    Optional<String> deciding(String scope, String prompt);

    /**
     * Whether a trial decided recent sealed decisions again with the version and finished (plan 3.10 4): the evidence
     * of its content, as a version cannot change.
     */
    boolean trialFinished(String scope, String prompt, String name);

    /** No database: no version. */
    static PromptVersionCatalog none() {
        return None.INSTANCE;
    }

    /** The catalog of an application without the version tables. */
    final class None implements PromptVersionCatalog {

        private static final None INSTANCE = new None();

        private None() {
        }

        @Override
        public List<Entry> versions(String scope, String prompt) {
            return List.of();
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
    }
}
