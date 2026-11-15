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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.properties.TieredStrategyProperties;

/**
 * Settings that choose the v19 bundle by its version. The tests of v19 behaviour (its sections, its similarity search
 * and the official checks that read the v19 sections) drew v19 as the build default; v1.0 is the build default since
 * plan 1-9, so they choose v19 and test the same behaviour.
 */
public final class V19BundleProperties {

    private V19BundleProperties() {
    }

    public static TieredStrategyProperties create() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V19.version());
        return properties;
    }
}
