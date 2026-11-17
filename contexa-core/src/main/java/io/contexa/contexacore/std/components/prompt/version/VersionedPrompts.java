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

/**
 * The prompts other than the security decision that run from their versions (plan 3.11), in the order the version
 * screens list them after the security decision.
 */
public record VersionedPrompts(List<VersionedPrompt> prompts) {

    public VersionedPrompts {
        prompts = prompts == null ? List.of() : List.copyOf(prompts);
    }

    /** The prompt of the key; empty for the security decision and for a key no prompt has. */
    public Optional<VersionedPrompt> find(String prompt) {
        return prompts.stream().filter(item -> item.prompt().equals(prompt)).findFirst();
    }

    /** The store of the product versions of the prompts, named by their release. */
    public PromptVersionStore productStore() {
        return (prompt, version) -> find(prompt)
                .filter(item -> item.product().release().equals(version))
                .map(VersionedPrompt::product);
    }
}
