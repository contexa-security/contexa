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

import java.util.Optional;

/**
 * Where the engine finds a version of a prompt by its name (plan 3.8, 2): the product versions the build ships, and
 * the versions a store keeps (plan 6-3). A version cannot change once made, so a store may keep what it found for good.
 */
public interface PromptVersionStore {

    /** The version of the prompt with the name; empty when the store has none. */
    Optional<AssembledPrompt> find(String prompt, String version);
}
