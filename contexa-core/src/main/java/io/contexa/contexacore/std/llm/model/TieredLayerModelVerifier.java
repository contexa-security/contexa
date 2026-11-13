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
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Tells at the start, in one error line per layer, which layer model set in
 * {@code contexa.security.tiered.llm.layer1.model} or {@code layer2.model} cannot be made and which model runs in its
 * place: an application that ran keeps running whatever model is set (Q-22), and without this line only a selection
 * record would tell (docs/showcase/판정층-수정계획.md E-7).
 */
@Slf4j
public class TieredLayerModelVerifier implements SmartInitializingSingleton {

    private final DynamicModelRegistry registry;
    private final TieredLLMProperties properties;
    private final Supplier<ChatModel> primaryChatModel;
    private final BooleanSupplier layersAnalyse;

    /** @param primaryChatModel gives the model a layer falls back to, or null when there is none */
    public TieredLayerModelVerifier(DynamicModelRegistry registry, TieredLLMProperties properties,
                                    Supplier<ChatModel> primaryChatModel) {
        this(registry, properties, primaryChatModel, () -> true);
    }

    /**
     * @param layersAnalyse whether the zero trust mode sends requests to the layers (SHADOW, ENFORCE); OBSERVE and
     *                      DISABLED run no layer, so a layer model that cannot be made is no error there (mall D1, D2)
     */
    public TieredLayerModelVerifier(DynamicModelRegistry registry, TieredLLMProperties properties,
                                    Supplier<ChatModel> primaryChatModel, BooleanSupplier layersAnalyse) {
        this.registry = registry;
        this.properties = properties;
        this.primaryChatModel = primaryChatModel;
        this.layersAnalyse = layersAnalyse != null ? layersAnalyse : () -> true;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!layersAnalyse.getAsBoolean()) {
            return;
        }
        verify(1);
        verify(2);
    }

    private void verify(int layer) {
        String modelId = properties.getModelNameForTier(layer);
        if (modelId == null || modelId.isBlank() || usable(modelId)) {
            return;
        }
        log.error("[TieredLayerModel] contexa.security.tiered.llm.layer{}.model '{}' cannot be used, so layer {} runs on "
                        + "{}: no chat runtime binding has this model id and the primary chat model cannot be copied "
                        + "with it. Bind a chat model with contexa.llm.bindings.chat to run it.",
                layer, modelId, layer, replacement(layer));
    }

    /** The model the selection takes instead: the layer's backup model, else the primary chat model. */
    private String replacement(int layer) {
        String backup = properties.getBackupModelNameForTier(layer);
        if (backup != null && usable(backup)) {
            return "'" + backup + "'";
        }
        ChatModel primary = primary();
        if (primary == null) {
            return "no chat model";
        }
        ChatOptions defaults = primary.getDefaultOptions();
        return "'" + (defaults != null && defaults.getModel() != null ? defaults.getModel()
                : primary.getClass().getSimpleName()) + "'";
    }

    private boolean usable(String modelId) {
        try {
            return registry.getModel(modelId) != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private ChatModel primary() {
        try {
            return primaryChatModel != null ? primaryChatModel.get() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }
}
