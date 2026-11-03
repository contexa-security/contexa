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
package io.contexa.autoconfigure.core.llm;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingRules;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingRules.Findings;
import io.contexa.contexacore.std.llm.client.AnthropicThinkingRules.Settings;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Design 4.5-A: stops the start on Anthropic thinking settings that cannot work, and warns about those the model call
 * adjusts. The settings alone are checked (a budget below the Claude API's minimum, a value Spring AI 1.1 cannot send),
 * and with each layer's Claude model, when it is known, what its capability row says the model refuses. A layer's model
 * is the one {@code contexa.security.tiered.llm.layerN.model} names (resolved as the model call resolves it when the
 * registry is there), or else the primary chat model; a layer on another provider is checked on the settings alone. It
 * takes nothing at creation and reads the beans once every singleton exists, as the module's other beans here do.
 */
@Slf4j
public class AnthropicThinkingSettingsVerifier implements SmartInitializingSingleton, EnvironmentAware, BeanFactoryAware {

    private static final String TIERED_PREFIX = "contexa.security.tiered";
    private static final String PRIMARY_CHAT_MODEL = "contexaPrimaryChatModel";

    private Environment environment;
    private BeanFactory beanFactory;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (environment == null) {
            return;
        }
        TieredStrategyProperties tiered = Binder.get(environment)
                .bind(TIERED_PREFIX, Bindable.of(TieredStrategyProperties.class))
                .orElseGet(TieredStrategyProperties::new);
        List<String> refusals = new ArrayList<>();
        TieredStrategyProperties.Layer1 layer1 = tiered.getLayer1();
        TieredStrategyProperties.Layer2 layer2 = tiered.getLayer2();
        verify(1, new Settings(layer1.getAnthropicThinking(), layer1.getAnthropicEffort(),
                layer1.getAnthropicThinkingBudgetTokens(), layer1.getAnthropicThinkingAllowanceTokens()),
                layer1.getMaxOutputTokens(), refusals);
        verify(2, new Settings(layer2.getAnthropicThinking(), layer2.getAnthropicEffort(),
                layer2.getAnthropicThinkingBudgetTokens(), layer2.getAnthropicThinkingAllowanceTokens()),
                layer2.getMaxOutputTokens(), refusals);
        if (!refusals.isEmpty()) {
            throw new IllegalStateException("The Anthropic thinking settings cannot be used:\n - "
                    + String.join("\n - ", refusals));
        }
    }

    private void verify(int layer, Settings settings, int answerLimit, List<String> refusals) {
        Findings findings = AnthropicThinkingRules.check(TIERED_PREFIX + ".layer" + layer, settings, answerLimit,
                layerModel(layer));
        findings.warnings().forEach(warning -> log.warn("[AnthropicThinking] {}", warning));
        refusals.addAll(findings.refusals());
    }

    /** The Claude model the layer runs on, when known; null for another provider or when it cannot be told. */
    private String layerModel(int layer) {
        String configured = Binder.get(environment)
                .bind(TIERED_PREFIX + ".llm.layer" + layer + ".model", String.class)
                .map(String::trim)
                .orElse("");
        if (!configured.isEmpty()) {
            DynamicModelRegistry registry = beanFactory != null
                    ? beanFactory.getBeanProvider(DynamicModelRegistry.class).getIfAvailable() : null;
            if (registry != null) {
                try {
                    ChatModel model = registry.getModel(configured);
                    if (model != null) {
                        return claudeModelOf(model);
                    }
                } catch (RuntimeException ex) {
                    // The layer model verifier stops the start on a model that cannot be made; checked as configured.
                }
            }
            return configured;
        }
        ChatModel primary = primaryChatModel();
        return primary != null ? claudeModelOf(primary) : null;
    }

    private ChatModel primaryChatModel() {
        if (beanFactory == null || !beanFactory.containsBean(PRIMARY_CHAT_MODEL)) {
            return null;
        }
        try {
            return beanFactory.getBean(PRIMARY_CHAT_MODEL, ChatModel.class);
        } catch (BeansException ex) {
            return null;
        }
    }

    private static String claudeModelOf(ChatModel model) {
        return model.getDefaultOptions() instanceof AnthropicChatOptions options ? options.getModel() : null;
    }
}
