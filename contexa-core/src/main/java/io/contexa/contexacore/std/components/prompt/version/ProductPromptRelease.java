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

import java.util.Objects;

/**
 * One product document a build ships (plan 3.3): the prompt it is for, the Contexa release and the document's text.
 * The releases of a prompt are listed oldest first; a first installation registers the newest, an upgrade the ones
 * newer than those it registered.
 *
 * @param prompt   the prompt, such as {@code cortex.security-decision}
 * @param release  the Contexa release, such as {@code 2026.11.16-v1.0}
 * @param document the text of the product document
 */
public record ProductPromptRelease(String prompt, String release, String document) {

    public ProductPromptRelease {
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(release, "release");
        Objects.requireNonNull(document, "document");
    }
}
