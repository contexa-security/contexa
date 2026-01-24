package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexacore.std.llm.model.ModelProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Base abstract class for ModelProvider implementations.
 * Uses Template Method pattern for common logic.
 */
@Slf4j
public abstract class BaseModelProvider implements ModelProvider {

    protected String baseUrl;
    protected RestTemplate restTemplate;
    protected final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    protected final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    protected boolean ready = false;

    // ========== Abstract Methods ==========

    @Override
    public abstract String getProviderName();

    @Override
    public abstract String getDescription();

    @Override
    public abstract ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config);

    @Override
    public abstract HealthStatus checkHealth(String modelId);

    @Override
    public abstract boolean supportsModelType(String modelType);

    @Override
    public abstract int getPriority();

    /**
     * Provider-specific initialization logic (Template Method hook)
     */
    protected abstract void doInitialize(Map<String, Object> config);

    /**
     * Get the base URL for this provider
     */
    protected abstract String getProviderBaseUrl();

    /**
     * Check if this provider is enabled
     */
    protected abstract boolean isProviderEnabled();

    /**
     * Provider-specific additional metrics (Optional)
     */
    protected Map<String, Object> getAdditionalMetrics() {
        return Collections.emptyMap();
    }

    // ========== Common Implementation ==========

    @Override
    public void initialize(Map<String, Object> config) {
        try {
            if (!isProviderEnabled()) {
                log.warn("{} is disabled or not configured", getProviderName());
                ready = false;
                return;
            }

            this.baseUrl = getProviderBaseUrl();
            this.restTemplate = new RestTemplate();
            doInitialize(config);
            ready = true;
        } catch (Exception e) {
            log.error("{}ModelProvider initialization failed", getProviderName(), e);
            ready = false;
        }
    }

    @Override
    public void shutdown() {
        modelInstances.clear();
        modelCache.clear();
        ready = false;
    }

    @Override
    public boolean isReady() {
        return ready;
    }

    @Override
    public void refreshModels() {
        // Default implementation: no-op. Override in subclass if needed
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("cachedModels", modelCache.size());
        metrics.put("activeInstances", modelInstances.size());
        metrics.put("ready", ready);
        metrics.put("baseUrl", baseUrl);
        metrics.putAll(getAdditionalMetrics());
        return metrics;
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        return new ArrayList<>(modelCache.values());
    }

    @Override
    public ModelDescriptor getModelDescriptor(String modelId) {
        return modelCache.get(modelId);
    }

    @Override
    public boolean supportsModel(String modelId) {
        if (modelCache.containsKey(modelId)) {
            return true;
        }
        // If provider is ready, it can attempt to create the model dynamically
        return isReady();
    }

    /**
     * Get cached ChatModel instance
     */
    protected ChatModel getCachedModel(String modelId) {
        return modelInstances.get(modelId);
    }

    /**
     * Cache ChatModel instance
     */
    protected void cacheModel(String modelId, ChatModel model) {
        modelInstances.put(modelId, model);
    }

    /**
     * Check if model is cached
     */
    protected boolean hasCachedModel(String modelId) {
        return modelInstances.containsKey(modelId);
    }

    /**
     * Model status (can be overridden by subclasses)
     */
    protected ModelDescriptor.ModelStatus getModelStatus() {
        return ModelDescriptor.ModelStatus.AVAILABLE;
    }
}
