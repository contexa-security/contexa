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

/**
 * What chose the bundle a prompt ran (the {@code promptBundleSelectionSource} of the execution record, version
 * management 6.3).
 */
public enum PromptBundleSelectionSource {
    /** Nothing chose a bundle, or the chosen bundle is not one the build runs: the build's default bundle ran. */
    BUILD_DEFAULT,
    /** The bundle named by {@code contexa.security.tiered.prompt-bundle.active}. */
    CONFIGURATION,
    /** The registry's active release of the request's scope. */
    REGISTRY,
    /** The registry's canary release, for a request inside the canary share of its scope. */
    CANARY,
    /**
     * W6-9 (P6-CHANGE-6): the registry's shadow release, run on sampled requests apart from the decision, sealed and
     * never enforced or learned.
     */
    SHADOW
}
