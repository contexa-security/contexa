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
package io.contexa.autoconfigure.core.llm.runtime;

import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class SpringLlmRuntimeCatalog implements LlmRuntimeCatalog {

    private final ConfigurableApplicationContext applicationContext;
    private final ConfigurableListableBeanFactory beanFactory;
    private final ContexaProperties contexaProperties;
    private final ContexaLlmBindingProperties bindingProperties;

    private volatile Snapshot snapshot;

    public SpringLlmRuntimeCatalog(
            ConfigurableApplicationContext applicationContext,
            ContexaProperties contexaProperties,
            ContexaLlmBindingProperties bindingProperties) {
        this.applicationContext = applicationContext;
        this.beanFactory = applicationContext.getBeanFactory();
        this.contexaProperties = contexaProperties;
        this.bindingProperties = bindingProperties;
    }

    @Override
    public List<LlmRuntimeBinding> getChatBindings() {
        return ensureSnapshot().chatBindings();
    }

    @Override
    public List<LlmRuntimeBinding> getEmbeddingBindings() {
        return ensureSnapshot().embeddingBindings();
    }

    @Override
    public Optional<LlmRuntimeBinding> findChatBinding(String selector) {
        return findBinding(getChatBindings(), selector);
    }

    @Override
    public Optional<LlmRuntimeBinding> findEmbeddingBinding(String selector) {
        return findBinding(getEmbeddingBindings(), selector);
    }

    @Override
    public ChatModel resolveChatModel(String selector) {
        LlmRuntimeBinding binding = findChatBinding(selector)
                .orElseThrow(() -> new IllegalStateException("No chat runtime binding found for selector: " + selector));
        return applicationContext.getBean(binding.getBeanName(), ChatModel.class);
    }

    @Override
    public EmbeddingModel resolveEmbeddingModel(String selector) {
        LlmRuntimeBinding binding = findEmbeddingBinding(selector)
                .orElseThrow(() -> new IllegalStateException("No embedding runtime binding found for selector: " + selector));
        return applicationContext.getBean(binding.getBeanName(), EmbeddingModel.class);
    }

    @Override
    public Optional<ChatModel> resolvePrimaryChatModel(String priorityConfig) {
        return resolvePrimary(getChatBindings(), priorityConfig, ChatModel.class);
    }

    @Override
    public Optional<EmbeddingModel> resolvePrimaryEmbeddingModel(String priorityConfig) {
        return resolvePrimary(getEmbeddingBindings(), priorityConfig, EmbeddingModel.class);
    }

    @Override
    public Optional<ChatModel> resolveSpringPrimaryChatModel() {
        return resolveSpringPrimary(getChatBindings(), ChatModel.class, "chat", "contexa.llm.selection.chat.mode");
    }

    @Override
    public Optional<EmbeddingModel> resolveSpringPrimaryEmbeddingModel() {
        return resolveSpringPrimary(getEmbeddingBindings(), EmbeddingModel.class, "embedding", "contexa.llm.selection.embedding.mode");
    }

    private Snapshot ensureSnapshot() {
        Snapshot current = snapshot;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (snapshot == null) {
                List<LlmRuntimeBinding> chatBindings = discoverBindings(ChatModel.class, LlmRuntimeType.CHAT, bindingProperties.getChat());
                List<LlmRuntimeBinding> embeddingBindings = discoverBindings(EmbeddingModel.class, LlmRuntimeType.EMBEDDING, bindingProperties.getEmbedding());
                validateUniqueSelectors(chatBindings, "chat");
                validateUniqueSelectors(embeddingBindings, "embedding");
                snapshot = new Snapshot(chatBindings, embeddingBindings);
            }
            return snapshot;
        }
    }

    private <T> Optional<T> resolvePrimary(List<LlmRuntimeBinding> bindings, String priorityConfig, Class<T> beanType) {
        RuntimeException firstFailure = null;
        for (String provider : parsePriority(priorityConfig)) {
            List<LlmRuntimeBinding> providerBindings = bindings.stream()
                    .filter(binding -> provider.equalsIgnoreCase(binding.getProvider()))
                    .sorted(bindingComparator())
                    .toList();
            for (LlmRuntimeBinding binding : providerBindings) {
                try {
                    return Optional.of(applicationContext.getBean(binding.getBeanName(), beanType));
                }
                catch (RuntimeException ex) {
                    if (firstFailure == null) {
                        firstFailure = ex;
                    }
                    log.warn("LLM runtime provider '{}' binding '{}' is not ready: {}",
                            provider, binding.getBeanName(), ex.getMessage());
                }
            }
        }

        for (LlmRuntimeBinding binding : bindings.stream().sorted(bindingComparator()).toList()) {
            try {
                return Optional.of(applicationContext.getBean(binding.getBeanName(), beanType));
            }
            catch (RuntimeException ex) {
                if (firstFailure == null) {
                    firstFailure = ex;
                }
                log.warn("LLM runtime binding '{}' is not ready: {}", binding.getBeanName(), ex.getMessage());
            }
        }

        if (firstFailure != null) {
            throw firstFailure;
        }
        return Optional.empty();
    }

    private <T> Optional<T> resolveSpringPrimary(
            List<LlmRuntimeBinding> bindings,
            Class<T> beanType,
            String runtimeType,
            String modeProperty) {
        if (bindings.isEmpty()) {
            return Optional.empty();
        }

        List<LlmRuntimeBinding> primaryBindings = bindings.stream()
                .filter(LlmRuntimeBinding::isPrimary)
                .sorted(bindingComparator())
                .toList();

        if (primaryBindings.size() > 1) {
            throw new IllegalStateException("Multiple " + runtimeType + " runtime bindings are marked primary: "
                    + describeBindings(primaryBindings)
                    + ". Keep only one @Primary Spring AI bean or switch to dynamic priority selection via "
                    + modeProperty + "=dynamic-priority.");
        }
        if (primaryBindings.size() == 1) {
            return Optional.of(applicationContext.getBean(primaryBindings.get(0).getBeanName(), beanType));
        }
        if (bindings.size() == 1) {
            return Optional.of(applicationContext.getBean(bindings.get(0).getBeanName(), beanType));
        }

        throw new IllegalStateException("Multiple " + runtimeType + " runtime bindings are available but none is marked primary: "
                + describeBindings(bindings)
                + ". Mark one Spring AI bean as @Primary or configure "
                + modeProperty + "=dynamic-priority with an explicit priority list.");
    }

    private String describeBindings(List<LlmRuntimeBinding> bindings) {
        return bindings.stream()
                .map(binding -> binding.getBeanName() + "[provider=" + binding.getProvider() + ", model=" + binding.getModelId() + "]")
                .collect(Collectors.joining(", "));
    }

    private List<LlmRuntimeBinding> discoverBindings(
            Class<?> beanType,
            LlmRuntimeType runtimeType,
            Map<String, ContexaLlmBindingProperties.Binding> configuredBindings) {
        List<LlmRuntimeBinding> bindings = new ArrayList<>();
        Set<String> matchedConfigKeys = new LinkedHashSet<>();

        String[] beanNames = beanFactory.getBeanNamesForType(beanType, true, false);
        Arrays.sort(beanNames);
        for (String beanName : beanNames) {
            if (shouldSkip(beanName)) {
                continue;
            }
            List<Map.Entry<String, ContexaLlmBindingProperties.Binding>> matchedBindings = configuredBindings.entrySet().stream()
                    .filter(entry -> entry.getValue() != null && entry.getValue().isEnabled())
                    .filter(entry -> matchesBinding(entry.getKey(), entry.getValue(), beanName))
                    .toList();

            if (matchedBindings.isEmpty()) {
                bindings.add(createBinding(beanName, beanType, runtimeType, beanName, null));
                continue;
            }

            for (Map.Entry<String, ContexaLlmBindingProperties.Binding> entry : matchedBindings) {
                bindings.add(createBinding(beanName, beanType, runtimeType, entry.getKey(), entry.getValue()));
                matchedConfigKeys.add(entry.getKey());
            }
        }

        for (Map.Entry<String, ContexaLlmBindingProperties.Binding> entry : configuredBindings.entrySet()) {
            if (matchedConfigKeys.contains(entry.getKey()) || entry.getValue() == null || !entry.getValue().isEnabled()) {
                continue;
            }
            if (!StringUtils.hasText(entry.getValue().getBeanName())) {
                continue;
            }
            if (!beanFactory.containsBean(entry.getValue().getBeanName())) {
                log.warn("Configured LLM binding '{}' references missing bean '{}'", entry.getKey(), entry.getValue().getBeanName());
                continue;
            }
            bindings.add(createBinding(entry.getValue().getBeanName(), beanType, runtimeType, entry.getKey(), entry.getValue()));
        }

        return bindings.stream()
                .sorted(bindingComparator())
                .toList();
    }

    private LlmRuntimeBinding createBinding(
            String beanName,
            Class<?> beanType,
            LlmRuntimeType runtimeType,
            String bindingKey,
            ContexaLlmBindingProperties.Binding configuredBinding) {
        String runtimeId = normalize(bindingKey != null ? bindingKey : beanName);
        String provider = normalize(configuredBinding != null ? configuredBinding.getProvider() : null);
        if (provider == null) {
            provider = inferProvider(beanName, beanFactory.getType(beanName, false));
        }
        String modelId = normalize(configuredBinding != null ? configuredBinding.getModelId() : null);
        if (modelId == null) {
            modelId = inferModelId(beanName, beanType, runtimeType, provider);
        }

        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(beanName);
        aliases.add(runtimeId);
        if (StringUtils.hasText(modelId)) {
            aliases.add(modelId);
        }
        if (configuredBinding != null && configuredBinding.getAliases() != null) {
            aliases.addAll(configuredBinding.getAliases());
        }

        return new LlmRuntimeBinding(
                runtimeId,
                beanName,
                provider,
                modelId,
                aliases,
                runtimeType,
                (configuredBinding != null && configuredBinding.isPrimary()) || isPrimaryBean(beanName),
                configuredBinding != null ? "configured" : "spring"
        );
    }

    private boolean matchesBinding(String key, ContexaLlmBindingProperties.Binding binding, String beanName) {
        if (key != null && key.equals(beanName)) {
            return true;
        }
        return StringUtils.hasText(binding.getBeanName()) && beanName.equals(binding.getBeanName().trim());
    }

    private boolean shouldSkip(String beanName) {
        return "primaryChatModel".equals(beanName)
                || "primaryEmbeddingModel".equals(beanName)
                || "embeddingModel".equals(beanName);
    }

    private boolean isPrimaryBean(String beanName) {
        if (!beanFactory.containsBeanDefinition(beanName)) {
            return false;
        }
        return beanFactory.getBeanDefinition(beanName).isPrimary();
    }

    private String inferProvider(String beanName, Class<?> beanType) {
        String source = ((beanType != null ? beanType.getName() : "") + ":" + beanName).toLowerCase();
        if (source.contains("ollama")) {
            return "ollama";
        }
        if (source.contains("anthropic") || source.contains("claude")) {
            return "anthropic";
        }
        if (source.contains("openai") || source.contains("azureopenai")) {
            return "openai";
        }
        if (source.contains("gemini") || source.contains("vertex")) {
            return "gemini";
        }
        if (source.contains("mistral")) {
            return "mistral";
        }
        if (source.contains("bedrock")) {
            return "bedrock";
        }
        if (source.contains("huggingface") || source.contains("hf")) {
            return "huggingface";
        }
        return "spring";
    }

    private String inferModelId(String beanName, Class<?> beanType, LlmRuntimeType runtimeType, String provider) {
        String configuredModelId = configuredProviderModelId(provider, runtimeType);
        if (configuredModelId != null) {
            return configuredModelId;
        }
        return beanName;
    }

    private String configuredProviderModelId(String provider, LlmRuntimeType runtimeType) {
        if (!StringUtils.hasText(provider) || runtimeType == null) {
            return null;
        }
        Environment environment = applicationContext.getEnvironment();
        if (environment == null) {
            return null;
        }

        String normalizedProvider = provider.trim().toLowerCase(Locale.ROOT);
        List<String> keys = switch (runtimeType) {
            case CHAT -> chatModelPropertyKeys(normalizedProvider);
            case EMBEDDING -> embeddingModelPropertyKeys(normalizedProvider);
        };
        for (String key : keys) {
            String value = normalize(environment.getProperty(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private List<String> chatModelPropertyKeys(String provider) {
        return switch (provider) {
            case "openai" -> List.of(
                    "spring.ai.openai.chat.options.model",
                    "spring.ai.azure.openai.chat.options.deployment-name",
                    "spring.ai.azure.openai.chat.options.model"
            );
            case "anthropic" -> List.of("spring.ai.anthropic.chat.options.model");
            case "ollama" -> List.of();
            default -> List.of();
        };
    }

    private List<String> embeddingModelPropertyKeys(String provider) {
        return switch (provider) {
            case "openai" -> List.of(
                    "spring.ai.openai.embedding.options.model",
                    "spring.ai.azure.openai.embedding.options.model"
            );
            case "ollama" -> List.of();
            default -> List.of();
        };
    }

    private void validateUniqueSelectors(List<LlmRuntimeBinding> bindings, String runtimeType) {
        Map<String, LlmRuntimeBinding> selectors = new LinkedHashMap<>();
        for (LlmRuntimeBinding binding : bindings) {
            for (String selector : selectorsOf(binding)) {
                LlmRuntimeBinding existing = selectors.putIfAbsent(selector, binding);
                if (existing != null && !sameBinding(existing, binding)) {
                    throw new IllegalStateException("Duplicate " + runtimeType + " runtime selector '" + selector + "' is mapped by multiple bindings: "
                            + describeBinding(existing) + ", " + describeBinding(binding)
                            + ". Keep bean names, runtime ids, model ids, and aliases unique.");
                }
            }
        }
    }

    private Set<String> selectorsOf(LlmRuntimeBinding binding) {
        Set<String> selectors = new LinkedHashSet<>();
        if (binding.getRuntimeId() != null) {
            selectors.add(binding.getRuntimeId());
        }
        if (binding.getBeanName() != null) {
            selectors.add(binding.getBeanName());
        }
        if (binding.getModelId() != null) {
            selectors.add(binding.getModelId());
        }
        selectors.addAll(binding.getAliases());
        return selectors;
    }

    private boolean sameBinding(LlmRuntimeBinding left, LlmRuntimeBinding right) {
        return Objects.equals(left.getBeanName(), right.getBeanName())
                && Objects.equals(left.getRuntimeId(), right.getRuntimeId())
                && Objects.equals(left.getModelId(), right.getModelId())
                && Objects.equals(left.getProvider(), right.getProvider());
    }

    private String describeBinding(LlmRuntimeBinding binding) {
        return binding.getBeanName() + "[runtimeId=" + binding.getRuntimeId()
                + ", provider=" + binding.getProvider()
                + ", model=" + binding.getModelId() + "]";
    }
    private Optional<LlmRuntimeBinding> findBinding(List<LlmRuntimeBinding> bindings, String selector) {
        if (!StringUtils.hasText(selector)) {
            return Optional.empty();
        }
        String normalized = selector.trim();
        return bindings.stream().filter(binding -> binding.matches(normalized)).findFirst();
    }

    private List<String> parsePriority(String priorityConfig) {
        if (!StringUtils.hasText(priorityConfig)) {
            return List.of();
        }
        return Arrays.stream(priorityConfig.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(String::toLowerCase)
                .distinct()
                .toList();
    }

    private Comparator<LlmRuntimeBinding> bindingComparator() {
        return Comparator.comparing(LlmRuntimeBinding::isPrimary).reversed()
                .thenComparing(binding -> binding.getProvider() == null ? "zzzz" : binding.getProvider())
                .thenComparing(binding -> binding.getRuntimeId() == null ? "zzzz" : binding.getRuntimeId());
    }

    private String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim();
    }

    private record Snapshot(List<LlmRuntimeBinding> chatBindings, List<LlmRuntimeBinding> embeddingBindings) {
    }
}
