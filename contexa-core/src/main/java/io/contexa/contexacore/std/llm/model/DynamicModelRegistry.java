package io.contexa.contexacore.std.llm.model;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.context.ApplicationContext;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime model registry backed by Spring AI runtime bindings.
 */
@Slf4j
public class DynamicModelRegistry {

    private final TieredLLMProperties tieredLLMProperties;
    private final LlmRuntimeCatalog runtimeCatalog;

    private final Map<String, ModelDescriptor> modelDescriptors = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    private final Map<String, String> aliases = new ConcurrentHashMap<>();

    public DynamicModelRegistry(ApplicationContext applicationContext, TieredLLMProperties tieredLLMProperties) {
        this(applicationContext, tieredLLMProperties, null);
    }

    public DynamicModelRegistry(
            ApplicationContext applicationContext,
            TieredLLMProperties tieredLLMProperties,
            LlmRuntimeCatalog runtimeCatalog) {
        this.tieredLLMProperties = tieredLLMProperties;
        this.runtimeCatalog = runtimeCatalog;
    }

    @PostConstruct
    public void initialize() {
        registerCatalogModels();
        loadModelsFromConfiguration();
    }

    private void registerCatalogModels() {
        if (runtimeCatalog == null) {
            return;
        }
        for (LlmRuntimeBinding binding : runtimeCatalog.getChatBindings()) {
            registerCatalogBinding(binding);
        }
    }

    private void registerCatalogBinding(LlmRuntimeBinding binding) {
        if (binding == null) {
            return;
        }
        String canonicalId = binding.canonicalId();
        if (canonicalId == null || canonicalId.isBlank()) {
            return;
        }

        ModelDescriptor existing = modelDescriptors.get(canonicalId);
        if (existing == null) {
            existing = ModelDescriptor.builder()
                    .modelId(canonicalId)
                    .displayName(canonicalId)
                    .provider(binding.getProvider())
                    .status(ModelDescriptor.ModelStatus.AVAILABLE)
                    .build();
            modelDescriptors.put(canonicalId, existing);
        }
        else {
            if (existing.getProvider() == null && binding.getProvider() != null) {
                existing.setProvider(binding.getProvider());
            }
            existing.setStatus(ModelDescriptor.ModelStatus.AVAILABLE);
        }

        registerAlias(binding.getBeanName(), canonicalId);
        registerAlias(binding.getRuntimeId(), canonicalId);
        registerAlias(binding.getModelId(), canonicalId);
        for (String alias : binding.getAliases()) {
            registerAlias(alias, canonicalId);
        }
    }

    private void loadModelsFromConfiguration() {
        registerModelFromConfig(1, tieredLLMProperties.getModelNameForTier(1));
        if (tieredLLMProperties.getLayer1().hasBackupModel()) {
            registerModelFromConfig(1, tieredLLMProperties.getLayer1().getBackup().getModel());
        }

        registerModelFromConfig(2, tieredLLMProperties.getModelNameForTier(2));
        if (tieredLLMProperties.getLayer2().hasBackupModel()) {
            registerModelFromConfig(2, tieredLLMProperties.getLayer2().getBackup().getModel());
        }
    }

    private void registerModelFromConfig(int tier, String modelName) {
        if (modelName == null || modelName.trim().isEmpty()) {
            return;
        }

        String canonicalId = resolveCanonicalModelId(modelName);
        LlmRuntimeBinding binding = findBinding(modelName, canonicalId);
        if (binding != null) {
            registerCatalogBinding(binding);
            canonicalId = binding.canonicalId();
        }

        ModelDescriptor existing = modelDescriptors.get(canonicalId);
        if (existing != null) {
            if (existing.getTier() == null || !existing.getTier().equals(tier)) {
                existing.setTier(tier);
            }
            registerAlias(modelName, canonicalId);
            return;
        }

        ModelDescriptor descriptor = ModelDescriptor.builder()
                .modelId(canonicalId)
                .displayName(canonicalId)
                .provider(binding != null ? binding.getProvider() : inferProviderFromModelName(canonicalId))
                .tier(tier)
                .status(ModelDescriptor.ModelStatus.AVAILABLE)
                .build();
        registerModel(descriptor);
        registerAlias(modelName, canonicalId);
    }

    private LlmRuntimeBinding findBinding(String selector, String canonicalId) {
        if (runtimeCatalog == null) {
            return null;
        }
        return runtimeCatalog.findChatBinding(selector)
                .or(() -> runtimeCatalog.findChatBinding(canonicalId))
                .orElse(null);
    }

    private String inferProviderFromModelName(String modelName) {
        String lowerName = modelName.toLowerCase();
        if (lowerName.contains("llama") || lowerName.contains("qwen")
                || lowerName.contains("gemma") || lowerName.contains("mistral")
                || lowerName.contains("phi") || lowerName.contains("exaone")
                || lowerName.contains("codellama") || lowerName.contains("deepseek")) {
            return "ollama";
        }
        if (lowerName.contains("claude")) {
            return "anthropic";
        }
        if (lowerName.contains("gpt") || lowerName.contains("o1") || lowerName.contains("davinci")) {
            return "openai";
        }
        if (lowerName.contains("gemini") || lowerName.contains("vertex")) {
            return "gemini";
        }
        if (lowerName.contains("bedrock")) {
            return "bedrock";
        }
        return "spring";
    }

    public void registerModel(ModelDescriptor descriptor) {
        if (descriptor == null || descriptor.getModelId() == null) {
            return;
        }
        ModelDescriptor existing = modelDescriptors.get(descriptor.getModelId());
        if (existing != null) {
            mergeDescriptors(existing, descriptor);
        }
        else {
            modelDescriptors.put(descriptor.getModelId(), descriptor);
        }
    }

    private void mergeDescriptors(ModelDescriptor existing, ModelDescriptor newDescriptor) {
        if (existing.getTier() == null && newDescriptor.getTier() != null) {
            existing.setTier(newDescriptor.getTier());
        }
        if (newDescriptor.getStatus() != null) {
            existing.setStatus(newDescriptor.getStatus());
        }
        if (existing.getCapabilities() == null && newDescriptor.getCapabilities() != null) {
            existing.setCapabilities(newDescriptor.getCapabilities());
        }
        if (existing.getOptions() == null && newDescriptor.getOptions() != null) {
            existing.setOptions(newDescriptor.getOptions());
        }
        if (existing.getProvider() == null && newDescriptor.getProvider() != null) {
            existing.setProvider(newDescriptor.getProvider());
        }
    }

    public ChatModel getModel(String modelId) {
        if (modelId == null) {
            throw new ModelSelectionException("Model ID is null");
        }
        if (runtimeCatalog == null) {
            throw new ModelSelectionException("No LLM runtime catalog configured", modelId);
        }

        String canonicalId = resolveCanonicalModelId(modelId);
        ChatModel cached = modelInstances.get(canonicalId);
        if (cached != null) {
            return cached;
        }

        LlmRuntimeBinding binding = findBinding(modelId, canonicalId);
        if (binding == null) {
            throw new ModelSelectionException("Model runtime binding not found: " + modelId, modelId);
        }

        ChatModel model = runtimeCatalog.resolveChatModel(binding.getRuntimeId() != null ? binding.getRuntimeId() : binding.canonicalId());
        registerCatalogBinding(binding);
        modelInstances.put(binding.canonicalId(), model);
        modelInstances.put(canonicalId, model);
        return model;
    }

    public Collection<ModelDescriptor> getAllModels() {
        return new ArrayList<>(modelDescriptors.values());
    }

    public ModelDescriptor getDescriptor(String modelId) {
        if (modelId == null || modelId.trim().isEmpty()) {
            return null;
        }
        return modelDescriptors.get(resolveCanonicalModelId(modelId));
    }

    public List<ModelDescriptor> getModelsByProvider(String provider) {
        if (provider == null || provider.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String normalizedProvider = provider.trim().toLowerCase();
        return modelDescriptors.values().stream()
                .filter(d -> normalizedProvider.equalsIgnoreCase(d.getProvider()))
                .filter(d -> d.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .toList();
    }

    public void updateModelStatus(String modelId, ModelDescriptor.ModelStatus status) {
        ModelDescriptor descriptor = modelDescriptors.get(resolveCanonicalModelId(modelId));
        if (descriptor != null) {
            descriptor.setStatus(status);
        }
    }

    public void refreshModels() {
        aliases.clear();
        modelDescriptors.clear();
        modelInstances.clear();
        registerCatalogModels();
        loadModelsFromConfiguration();
    }

    private String resolveCanonicalModelId(String selector) {
        if (selector == null) {
            return null;
        }
        String normalized = selector.trim();
        return aliases.getOrDefault(normalized, normalized);
    }

    private void registerAlias(String alias, String canonicalId) {
        if (alias == null || alias.isBlank() || canonicalId == null || canonicalId.isBlank()) {
            return;
        }
        aliases.putIfAbsent(alias.trim(), canonicalId.trim());
    }

    @PreDestroy
    public void shutdown() {
        aliases.clear();
        modelInstances.clear();
        modelDescriptors.clear();
    }
}