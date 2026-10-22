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
package io.contexa.contexacore.std.llm.model;

import io.contexa.contexacore.config.TieredLLMProperties;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * Stops the start when a layer model set in {@code contexa.security.tiered.llm.layer1.model} or {@code layer2.model}
 * cannot be made: without it the layer's analysis would run on the primary chat model and only a selection record would
 * tell (docs/showcase/판정층-수정계획.md E-7).
 */
public class TieredLayerModelVerifier implements SmartInitializingSingleton {

    private final DynamicModelRegistry registry;
    private final TieredLLMProperties properties;

    public TieredLayerModelVerifier(DynamicModelRegistry registry, TieredLLMProperties properties) {
        this.registry = registry;
        this.properties = properties;
    }

    @Override
    public void afterSingletonsInstantiated() {
        verify("contexa.security.tiered.llm.layer1.model", properties.getModelNameForTier(1));
        verify("contexa.security.tiered.llm.layer2.model", properties.getModelNameForTier(2));
    }

    private void verify(String setting, String modelId) {
        if (modelId == null || modelId.isBlank()) {
            return;
        }
        try {
            registry.getModel(modelId);
        } catch (RuntimeException e) {
            throw new IllegalStateException(setting + " '" + modelId + "' cannot be used: no chat runtime binding has "
                    + "this model id and the primary chat model cannot be copied with it (" + e.getMessage()
                    + "). Bind a chat model with contexa.llm.bindings.chat, or use a provider whose chat model "
                    + "supports mutate().", e);
        }
    }
}
