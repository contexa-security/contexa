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

import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;

/**
 * Chooses the prompt bundle a request runs (version management function 4). The prompt that asks keeps a bundle the
 * build cannot run from running: it then runs its default bundle and raises an alarm.
 */
@FunctionalInterface
public interface PromptBundleSelector {

    /**
     * @param context    the request's prompt key, template key, registry scope and resource
     * @param subjectKey a stable key of the requester (the user, else the session, else the event), which a canary
     *                   share is drawn by
     * @return the chosen bundle, or {@link PromptBundleSelection#none()} to leave it to the build default
     */
    PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey);
}
