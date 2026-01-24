package io.contexa.contexacore.std.llm.model;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.context.ApplicationContext;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Dynamic model registry for managing LLM models across multiple providers.
 * Discovers Spring AI models and ModelProvider beans automatically.
 */
@Slf4j
@RequiredArgsConstructor
public class DynamicModelRegistry {

    private final ApplicationContext applicationContext;
    private final TieredLLMProperties tieredLLMProperties;

    private final Map<String, ModelProvider> providers = new ConcurrentHashMap<>();
    private final Map<String, ModelDescriptor> modelDescriptors = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();

    @PostConstruct
    public void initialize() {
        try {
            discoverAndRegisterProviders();
        } catch (Exception e) {
            log.warn("Failed to discover ModelProviders. LLM functionality may be limited: {}", e.getMessage());
        }

        try {
            discoverSpringAiModels();
        } catch (Exception e) {
            log.warn("Failed to discover Spring AI models. LLM functionality may be limited: {}", e.getMessage());
        }

        try {
            loadModelsFromConfiguration();
        } catch (Exception e) {
            log.warn("Failed to load models from configuration: {}", e.getMessage());
        }

        try {
            performHealthCheck();
        } catch (Exception e) {
            log.warn("Failed to perform model health check: {}", e.getMessage());
        }

        log.info("DynamicModelRegistry initialization complete. Registered models: {}, Providers: {}",
                modelDescriptors.size(), providers.size());
    }

    private void discoverSpringAiModels() {
        Map<String, ChatModel> chatModels = applicationContext.getBeansOfType(ChatModel.class);

        for (Map.Entry<String, ChatModel> entry : chatModels.entrySet()) {
            ChatModel chatModel = entry.getValue();
            String providerName = inferProviderFromModel(chatModel);

            // Check if provider already exists
            if (providers.containsKey(providerName)) {
                ModelProvider existingProvider = providers.get(providerName);
                // If existing provider has no models, use Spring AI model
                if (existingProvider.getAvailableModels().isEmpty()) {
                    registerSpringAiModel(providerName, chatModel);
                }
                continue;
            }

            // Register Spring AI model directly without AutoDiscoveredModelProvider
            registerSpringAiModel(providerName, chatModel);
        }
    }

    private void registerSpringAiModel(String providerName, ChatModel chatModel) {
        String modelId = extractModelIdFromChatModel(chatModel);

        ModelDescriptor descriptor = ModelDescriptor.builder()
                .modelId(modelId)
                .displayName(modelId)
                .provider(providerName)
                .status(ModelDescriptor.ModelStatus.AVAILABLE)
                .capabilities(ModelDescriptor.ModelCapabilities.builder()
                        .streaming(true)
                        .supportsSystemMessage(true)
                        .build())
                .build();

        registerModel(descriptor);
        modelInstances.put(modelId, chatModel);
    }

    private String extractModelIdFromChatModel(ChatModel chatModel) {
        ChatOptions options = chatModel.getDefaultOptions();
        if (options != null && options.getModel() != null) {
            return options.getModel();
        }
        return chatModel.getClass().getSimpleName();
    }

    private String inferProviderFromModel(ChatModel model) {
        String className = model.getClass().getSimpleName().toLowerCase();

        if (className.contains("ollama"))
            return "ollama";
        if (className.contains("anthropic"))
            return "anthropic";
        if (className.contains("openai"))
            return "openai";
        if (className.contains("gemini") || className.contains("vertex"))
            return "gemini";
        if (className.contains("mistral"))
            return "mistral";
        if (className.contains("azure"))
            return "azure";
        if (className.contains("bedrock"))
            return "bedrock";
        if (className.contains("huggingface") || className.contains("hf"))
            return "huggingface";

        // Unknown provider
        log.warn("Unknown ChatModel type: {}. Registering as 'unknown' provider.", className);
        return "unknown-" + className;
    }

    private void discoverAndRegisterProviders() {
        Map<String, ModelProvider> providerBeans = applicationContext.getBeansOfType(ModelProvider.class);

        for (Map.Entry<String, ModelProvider> entry : providerBeans.entrySet()) {
            ModelProvider provider = entry.getValue();
            String providerName = provider.getProviderName();

            providers.put(providerName, provider);

            try {
                provider.initialize(Collections.emptyMap());

                List<ModelDescriptor> models = provider.getAvailableModels();
                for (ModelDescriptor model : models) {
                    registerModel(model);
                }
            } catch (Exception e) {
                log.error("ModelProvider initialization failed: {}", providerName, e);
            }
        }
    }

    private void loadModelsFromConfiguration() {
        registerModelFromConfig(1, tieredLLMProperties.getLayer1().getModel());
        if (tieredLLMProperties.getLayer1().hasBackupModel()) {
            registerModelFromConfig(1, tieredLLMProperties.getLayer1().getBackup().getModel());
        }

        registerModelFromConfig(2, tieredLLMProperties.getLayer2().getModel());
        if (tieredLLMProperties.getLayer2().hasBackupModel()) {
            registerModelFromConfig(2, tieredLLMProperties.getLayer2().getBackup().getModel());
        }
    }

    private void registerModelFromConfig(int tier, String modelName) {
        if (modelName == null || modelName.trim().isEmpty()) {
            return;
        }

        if (modelDescriptors.containsKey(modelName)) {
            ModelDescriptor existing = modelDescriptors.get(modelName);
            // Configuration tier always takes precedence over provider-defined tier
            if (existing.getTier() == null || !existing.getTier().equals(tier)) {
                log.debug("Updating model {} tier from {} to {} (configuration takes precedence)",
                        modelName, existing.getTier(), tier);
                existing.setTier(tier);
            }
            return;
        }

        // Create simple descriptor from model name
        String provider = inferProviderFromModelName(modelName);
        ModelDescriptor descriptor = ModelDescriptor.builder()
                .modelId(modelName)
                .displayName(modelName)
                .provider(provider)
                .tier(tier)
                .status(ModelDescriptor.ModelStatus.AVAILABLE)
                .build();

        registerModel(descriptor);
    }

    private String inferProviderFromModelName(String modelName) {
        String lowerName = modelName.toLowerCase();

        // Ollama models
        if (lowerName.contains("llama") || lowerName.contains("qwen") ||
            lowerName.contains("gemma") || lowerName.contains("mistral") ||
            lowerName.contains("phi") || lowerName.contains("exaone") ||
            lowerName.contains("codellama") || lowerName.contains("deepseek")) {
            return "ollama";
        }

        // Anthropic models
        if (lowerName.contains("claude")) {
            return "anthropic";
        }

        // OpenAI models
        if (lowerName.contains("gpt") || lowerName.contains("o1") || lowerName.contains("davinci")) {
            return "openai";
        }

        // Default to unknown
        return "unknown";
    }

    private void performHealthCheck() {
        for (Map.Entry<String, ModelProvider> entry : providers.entrySet()) {
            String providerName = entry.getKey();
            ModelProvider provider = entry.getValue();

            if (!provider.isReady()) {
                log.warn("ModelProvider {} is not ready", providerName);
                continue;
            }

            for (ModelDescriptor model : provider.getAvailableModels()) {
                try {
                    ModelProvider.HealthStatus health = provider.checkHealth(model.getModelId());
                    if (!health.isHealthy()) {
                        log.warn("Model {} unhealthy: {}", model.getModelId(), health.getMessage());
                        model.setStatus(ModelDescriptor.ModelStatus.UNAVAILABLE);
                    }
                } catch (Exception e) {
                    log.error("Model {} health check failed", model.getModelId(), e);
                }
            }
        }
    }

    public void registerModel(ModelDescriptor descriptor) {
        if (descriptor == null || descriptor.getModelId() == null) {
            return;
        }

        ModelDescriptor existing = modelDescriptors.get(descriptor.getModelId());
        if (existing != null) {
            // Merge new descriptor with existing one, preserving important fields
            mergeDescriptors(existing, descriptor);
            log.debug("Merged model descriptor: {}", descriptor.getModelId());
        } else {
            modelDescriptors.put(descriptor.getModelId(), descriptor);
        }
    }

    private void mergeDescriptors(ModelDescriptor existing, ModelDescriptor newDescriptor) {
        // Preserve tier if already set (configuration takes precedence)
        if (existing.getTier() == null && newDescriptor.getTier() != null) {
            existing.setTier(newDescriptor.getTier());
        }

        // Update status if new descriptor has more recent info
        if (newDescriptor.getStatus() != null) {
            existing.setStatus(newDescriptor.getStatus());
        }

        // Update capabilities if existing has none
        if (existing.getCapabilities() == null && newDescriptor.getCapabilities() != null) {
            existing.setCapabilities(newDescriptor.getCapabilities());
        }

        // Update options if existing has none
        if (existing.getOptions() == null && newDescriptor.getOptions() != null) {
            existing.setOptions(newDescriptor.getOptions());
        }
    }

    public ChatModel getModel(String modelId) {
        if (modelId == null) {
            throw new ModelSelectionException("Model ID is null");
        }

        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
        }

        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor == null) {
            // Try to find provider dynamically
            ModelProvider provider = findProviderForModel(modelId);
            if (provider != null) {
                descriptor = ModelDescriptor.builder()
                        .modelId(modelId)
                        .displayName(modelId)
                        .provider(provider.getProviderName())
                        .status(ModelDescriptor.ModelStatus.AVAILABLE)
                        .build();
                registerModel(descriptor);
            } else {
                throw new ModelSelectionException("Model not found: " + modelId, modelId);
            }
        }

        String providerName = descriptor.getProvider();
        ModelProvider provider = providers.get(providerName);

        if (provider == null) {
            provider = findProviderForModel(modelId);
            if (provider != null) {
                descriptor.setProvider(provider.getProviderName());
                log.debug("Dynamically resolved provider for model {}: {}", modelId, provider.getProviderName());
            }
        }

        if (provider == null) {
            throw new ModelSelectionException(
                    "No provider supports model: " + modelId, modelId);
        }

        try {
            ChatModel model = provider.createModel(descriptor);
            modelInstances.put(modelId, model);
            return model;
        } catch (Exception e) {
            throw new ModelSelectionException(
                    "Model creation failed: " + modelId + " - " + e.getMessage(), modelId, e);
        }
    }

    private ModelProvider findProviderForModel(String modelId) {
        // Sort by priority (ascending) and filter ready providers that support the model
        List<ModelProvider> sortedProviders = providers.values().stream()
                .filter(ModelProvider::isReady)
                .filter(p -> p.supportsModel(modelId))
                .sorted(Comparator.comparingInt(ModelProvider::getPriority))
                .toList();

        // Try each provider in priority order
        for (ModelProvider provider : sortedProviders) {
            try {
                ModelDescriptor tempDesc = ModelDescriptor.builder()
                        .modelId(modelId)
                        .provider(provider.getProviderName())
                        .build();
                ChatModel model = provider.createModel(tempDesc);
                if (model != null) {
                    return provider;
                }
            } catch (Exception e) {
                log.debug("Provider {} cannot create model {}: {}",
                        provider.getProviderName(), modelId, e.getMessage());
            }
        }
        return null;
    }

    public Collection<ModelDescriptor> getAllModels() {
        return new ArrayList<>(modelDescriptors.values());
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
        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor != null) {
            descriptor.setStatus(status);
        }
    }

    public void refreshModels() {
        for (ModelProvider provider : providers.values()) {
            try {
                provider.refreshModels();

                for (ModelDescriptor model : provider.getAvailableModels()) {
                    if (!modelDescriptors.containsKey(model.getModelId())) {
                        registerModel(model);
                    }
                }
            } catch (Exception e) {
                log.error("Model refresh failed: {}", provider.getProviderName(), e);
            }
        }
    }

    @PreDestroy
    public void shutdown() {
        for (ModelProvider provider : providers.values()) {
            try {
                provider.shutdown();
            } catch (Exception e) {
                log.error("ModelProvider shutdown failed: {}", provider.getProviderName(), e);
            }
        }

        modelInstances.clear();
        modelDescriptors.clear();
        providers.clear();
    }
}
