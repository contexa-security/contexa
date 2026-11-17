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

import java.util.List;

/**
 * A prompt other than the security decision that runs from its versions (plan 3.11): its key, the product documents
 * the build ships, the registry row its versions get, and its finished prompt drawn with a fixed example input, which
 * the version screen shows in place of a recent decision's.
 */
public interface VersionedPrompt {

    /** The prompt key, the template key it is called by. */
    String prompt();

    /** The product documents of the prompt, oldest first. */
    List<ProductPromptRelease> productReleases();

    /** The product version: the latest product document. */
    AssembledPrompt product();

    /** The governance descriptor of the prompt, which names the registry row of its versions. */
    PromptGovernanceDescriptor registryDescriptor();

    /** The finished prompt the version draws for the example input. */
    Example example(AssembledPrompt version);

    /**
     * The finished prompt of the example input.
     *
     * @param system the system prompt; empty when the prompt has none
     * @param user   the user prompt
     */
    record Example(String system, String user) {
    }
}
