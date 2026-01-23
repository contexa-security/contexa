package io.contexa.contexacore.std.llm.service;

import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexacore.std.llm.model.ModelProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ModelDiscoveryService {

    private final ApplicationContext applicationContext;
    private final DynamicModelRegistry modelRegistry;

    private final Map<String, ModelDiscoveryStatus> discoveryStatus = new ConcurrentHashMap<>();

    private final Map<String, ModelHealthStatus> healthStatus = new ConcurrentHashMap<>();

    private final AtomicInteger totalDiscoveryAttempts = new AtomicInteger(0);
    private final AtomicInteger successfulDiscoveries = new AtomicInteger(0);
    private final AtomicInteger failedDiscoveries = new AtomicInteger(0);

    public static class ModelDiscoveryStatus {
        private final String modelId;
        private final String provider;
        private final Date discoveredAt;
        private Date lastSeenAt;
        private boolean available;
        private String lastError;

        public ModelDiscoveryStatus(String modelId, String provider) {
            this.modelId = modelId;
            this.provider = provider;
            this.discoveredAt = new Date();
            this.lastSeenAt = new Date();
            this.available = true;
        }

        public void updateStatus(boolean available, String error) {
            this.lastSeenAt = new Date();
            this.available = available;
            this.lastError = error;
        }

        public String getModelId() { return modelId; }
        public String getProvider() { return provider; }
        public Date getDiscoveredAt() { return discoveredAt; }
        public Date getLastSeenAt() { return lastSeenAt; }
        public boolean isAvailable() { return available; }
        public String getLastError() { return lastError; }
    }

    public static class ModelHealthStatus {
        private final String modelId;
        private boolean healthy;
        private String message;
        private Date lastCheckTime;
        private int consecutiveFailures;
        private long averageResponseTime;
        private final List<Long> recentResponseTimes = new LinkedList<>();

        public ModelHealthStatus(String modelId) {
            this.modelId = modelId;
            this.healthy = true;
            this.lastCheckTime = new Date();
            this.consecutiveFailures = 0;
            this.averageResponseTime = 0;
        }

        public void recordHealthCheck(boolean success, String message, long responseTime) {
            this.healthy = success;
            this.message = message;
            this.lastCheckTime = new Date();

            if (success) {
                this.consecutiveFailures = 0;
                recordResponseTime(responseTime);
            } else {
                this.consecutiveFailures++;
            }
        }

        private void recordResponseTime(long responseTime) {
            recentResponseTimes.add(responseTime);
            if (recentResponseTimes.size() > 10) {
                recentResponseTimes.remove(0);
            }
            this.averageResponseTime = (long) recentResponseTimes.stream()
                .mapToLong(Long::longValue)
                .average()
                .orElse(0);
        }

        public String getModelId() { return modelId; }
        public boolean isHealthy() { return healthy; }
        public String getMessage() { return message; }
        public Date getLastCheckTime() { return lastCheckTime; }
        public int getConsecutiveFailures() { return consecutiveFailures; }
        public long getAverageResponseTime() { return averageResponseTime; }
    }

    @PostConstruct
    public void initializeDiscovery() {
                discoverAllModels();
            }

    public void scheduledDiscovery() {
                discoverAllModels();
    }

    public void scheduledHealthCheck() {
                performHealthCheckForAllModels();
    }

    public void discoverAllModels() {
        totalDiscoveryAttempts.incrementAndGet();

        Map<String, ModelProvider> providers = applicationContext.getBeansOfType(ModelProvider.class);
        
        int newModelsCount = 0;
        int updatedModelsCount = 0;

        for (ModelProvider provider : providers.values()) {
            try {
                if (!provider.isReady()) {
                                        continue;
                }

                provider.refreshModels();

                List<ModelDescriptor> models = provider.getAvailableModels();

                for (ModelDescriptor model : models) {
                    String modelId = model.getModelId();

                    if (!discoveryStatus.containsKey(modelId)) {
                        
                        ModelDiscoveryStatus status = new ModelDiscoveryStatus(modelId, provider.getProviderName());
                        discoveryStatus.put(modelId, status);

                        modelRegistry.registerModel(model);

                        newModelsCount++;
                                            } else {
                        
                        ModelDiscoveryStatus status = discoveryStatus.get(modelId);
                        status.updateStatus(true, null);
                        updatedModelsCount++;
                    }
                }

                successfulDiscoveries.incrementAndGet();
            } catch (Exception e) {
                failedDiscoveries.incrementAndGet();
                log.error("Failed to discover models from provider {}", provider.getProviderName(), e);
            }
        }

        checkForStaleModels();

            }

    public List<ModelDescriptor> discoverModelsFromProvider(String providerName) {
        Map<String, ModelProvider> providers = applicationContext.getBeansOfType(ModelProvider.class);

        for (ModelProvider provider : providers.values()) {
            if (provider.getProviderName().equals(providerName)) {
                try {
                    provider.refreshModels();
                    List<ModelDescriptor> models = provider.getAvailableModels();

                    for (ModelDescriptor model : models) {
                        String modelId = model.getModelId();
                        if (!discoveryStatus.containsKey(modelId)) {
                            ModelDiscoveryStatus status = new ModelDiscoveryStatus(modelId, providerName);
                            discoveryStatus.put(modelId, status);
                            modelRegistry.registerModel(model);
                        }
                    }

                    return models;
                } catch (Exception e) {
                    log.error("Failed to discover models from provider {}", providerName, e);
                    return Collections.emptyList();
                }
            }
        }

        log.warn("Provider {} not found", providerName);
        return Collections.emptyList();
    }

    public void performHealthCheckForAllModels() {
        Map<String, ModelProvider> providers = applicationContext.getBeansOfType(ModelProvider.class);

        for (Map.Entry<String, ModelDiscoveryStatus> entry : discoveryStatus.entrySet()) {
            String modelId = entry.getKey();
            ModelDiscoveryStatus status = entry.getValue();

            if (!status.isAvailable()) {
                continue; 
            }

            for (ModelProvider provider : providers.values()) {
                if (provider.getProviderName().equals(status.getProvider())) {
                    performHealthCheck(modelId, provider);
                    break;
                }
            }
        }
    }

    private void performHealthCheck(String modelId, ModelProvider provider) {
        long startTime = System.currentTimeMillis();

        try {
            ModelProvider.HealthStatus health = provider.checkHealth(modelId);
            long responseTime = System.currentTimeMillis() - startTime;

            ModelHealthStatus modelHealth = healthStatus.computeIfAbsent(modelId,
                k -> new ModelHealthStatus(modelId));

            modelHealth.recordHealthCheck(health.isHealthy(), health.getMessage(), responseTime);

            if (!health.isHealthy()) {
                log.warn("Health check failed for model {}: {}", modelId, health.getMessage());

                if (modelHealth.getConsecutiveFailures() >= 3) {
                    log.error("Model {} disabled due to consecutive failures", modelId);
                    modelRegistry.updateModelStatus(modelId, ModelDescriptor.ModelStatus.UNAVAILABLE);

                    ModelDiscoveryStatus discoveryStatus = this.discoveryStatus.get(modelId);
                    if (discoveryStatus != null) {
                        discoveryStatus.updateStatus(false, "Health check failed repeatedly");
                    }
                }
            } else {
                            }
        } catch (Exception e) {
            log.error("Error during health check for model {}", modelId, e);

            ModelHealthStatus modelHealth = healthStatus.computeIfAbsent(modelId,
                k -> new ModelHealthStatus(modelId));
            modelHealth.recordHealthCheck(false, e.getMessage(), 0);
        }
    }

    private void checkForStaleModels() {
        Date cutoffTime = new Date(System.currentTimeMillis() - 3600000); 

        for (Map.Entry<String, ModelDiscoveryStatus> entry : discoveryStatus.entrySet()) {
            ModelDiscoveryStatus status = entry.getValue();

            if (status.isAvailable() && status.getLastSeenAt().before(cutoffTime)) {
                log.warn("Model {} marked stale and disabled (last seen: {})",
                        status.getModelId(), status.getLastSeenAt());

                status.updateStatus(false, "Not seen for over 1 hour");
                modelRegistry.updateModelStatus(status.getModelId(),
                    ModelDescriptor.ModelStatus.UNAVAILABLE);
            }
        }
    }

    public int getActiveModelsCount() {
        return (int) discoveryStatus.values().stream()
            .filter(ModelDiscoveryStatus::isAvailable)
            .count();
    }

    public Map<String, Integer> getModelCountByProvider() {
        return discoveryStatus.values().stream()
            .filter(ModelDiscoveryStatus::isAvailable)
            .collect(Collectors.groupingBy(
                ModelDiscoveryStatus::getProvider,
                Collectors.collectingAndThen(Collectors.counting(), Long::intValue)
            ));
    }

    public ModelDiscoveryStatus getDiscoveryStatus(String modelId) {
        return discoveryStatus.get(modelId);
    }

    public ModelHealthStatus getHealthStatus(String modelId) {
        return healthStatus.get(modelId);
    }

    public List<String> getAllDiscoveredModels() {
        return new ArrayList<>(discoveryStatus.keySet());
    }

    public List<String> getActiveModels() {
        return discoveryStatus.entrySet().stream()
            .filter(e -> e.getValue().isAvailable())
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalDiscoveryAttempts", totalDiscoveryAttempts.get());
        stats.put("successfulDiscoveries", successfulDiscoveries.get());
        stats.put("failedDiscoveries", failedDiscoveries.get());
        stats.put("totalModels", discoveryStatus.size());
        stats.put("activeModels", getActiveModelsCount());
        stats.put("modelsByProvider", getModelCountByProvider());

        long healthyModels = healthStatus.values().stream()
            .filter(ModelHealthStatus::isHealthy)
            .count();
        stats.put("healthyModels", healthyModels);
        stats.put("unhealthyModels", healthStatus.size() - healthyModels);

        double avgResponseTime = healthStatus.values().stream()
            .mapToLong(ModelHealthStatus::getAverageResponseTime)
            .average()
            .orElse(0);
        stats.put("averageResponseTime", avgResponseTime);

        return stats;
    }

    public void forceRediscovery() {
                discoveryStatus.clear();
        healthStatus.clear();
        modelRegistry.refreshModels();
        discoverAllModels();
    }
}