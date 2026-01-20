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
        log.info("모델 발견 서비스 초기화 시작");
        discoverAllModels();
        log.info("모델 발견 서비스 초기화 완료 - 발견된 모델: {} 개", discoveryStatus.size());
    }

    

    public void scheduledDiscovery() {
        log.debug("주기적 모델 발견 시작");
        discoverAllModels();
    }

    

    public void scheduledHealthCheck() {
        log.debug("주기적 모델 헬스 체크 시작");
        performHealthCheckForAllModels();
    }

    
    public void discoverAllModels() {
        totalDiscoveryAttempts.incrementAndGet();

        Map<String, ModelProvider> providers = applicationContext.getBeansOfType(ModelProvider.class);
        log.info("모델 발견 시작 - {} 개의 제공자 스캔", providers.size());

        int newModelsCount = 0;
        int updatedModelsCount = 0;

        for (ModelProvider provider : providers.values()) {
            try {
                if (!provider.isReady()) {
                    log.debug("제공자 {} 가 준비되지 않음", provider.getProviderName());
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
                        log.info("새로운 모델 발견: {} (제공자: {})", modelId, provider.getProviderName());
                    } else {
                        
                        ModelDiscoveryStatus status = discoveryStatus.get(modelId);
                        status.updateStatus(true, null);
                        updatedModelsCount++;
                    }
                }

                successfulDiscoveries.incrementAndGet();
            } catch (Exception e) {
                failedDiscoveries.incrementAndGet();
                log.error("제공자 {} 에서 모델 발견 실패", provider.getProviderName(), e);
            }
        }

        
        checkForStaleModels();

        log.info("모델 발견 완료 - 새로운 모델: {}, 업데이트된 모델: {}, 총 활성 모델: {}",
                newModelsCount, updatedModelsCount, getActiveModelsCount());
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
                    log.error("제공자 {} 에서 모델 발견 실패", providerName, e);
                    return Collections.emptyList();
                }
            }
        }

        log.warn("제공자 {} 를 찾을 수 없음", providerName);
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
                log.warn("모델 {} 헬스 체크 실패: {}", modelId, health.getMessage());

                
                if (modelHealth.getConsecutiveFailures() >= 3) {
                    log.error("모델 {} 연속 실패로 비활성화", modelId);
                    modelRegistry.updateModelStatus(modelId, ModelDescriptor.ModelStatus.UNAVAILABLE);

                    ModelDiscoveryStatus discoveryStatus = this.discoveryStatus.get(modelId);
                    if (discoveryStatus != null) {
                        discoveryStatus.updateStatus(false, "Health check failed repeatedly");
                    }
                }
            } else {
                log.debug("모델 {} 헬스 체크 성공 (응답시간: {}ms)", modelId, responseTime);
            }
        } catch (Exception e) {
            log.error("모델 {} 헬스 체크 중 오류", modelId, e);

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
                log.warn("모델 {} 가 오래되어 비활성화됨 (마지막 확인: {})",
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
        log.info("강제 모델 재발견 시작");
        discoveryStatus.clear();
        healthStatus.clear();
        modelRegistry.refreshModels();
        discoverAllModels();
    }
}