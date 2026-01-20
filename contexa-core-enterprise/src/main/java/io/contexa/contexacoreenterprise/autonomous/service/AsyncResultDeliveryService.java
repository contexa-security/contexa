package io.contexa.contexacoreenterprise.autonomous.service;

import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class AsyncResultDeliveryService {
    
    
    private final ToolExecutionContextRepository executionRepository;
    private final RedisEventPublisher eventPublisher;
    private final UnifiedNotificationService notificationService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SimpMessagingTemplate messagingTemplate;
    private final ObjectMapper objectMapper;
    
    
    @Value("${result.delivery.retry.max-attempts:3}")
    private int maxRetryAttempts;
    
    @Value("${result.delivery.retry.delay-seconds:5}")
    private int retryDelaySeconds;
    
    @Value("${result.delivery.ttl-hours:24}")
    private int resultTtlHours;
    
    @Value("${result.delivery.batch.size:50}")
    private int batchSize;
    
    @Value("${result.delivery.batch.interval-ms:1000}")
    private int batchIntervalMs;
    
    @Value("${result.delivery.websocket.enabled:true}")
    private boolean websocketEnabled;
    
    @Value("${result.delivery.notification.enabled:true}")
    private boolean notificationEnabled;
    
    @Value("${result.delivery.event.enabled:true}")
    private boolean eventPublishingEnabled;
    
    
    private final List<PendingResult> resultQueue = Collections.synchronizedList(new ArrayList<>());
    
    
    private final Map<String, DeliveryStatus> deliveryStatuses = new ConcurrentHashMap<>();
    
    
    private final AtomicLong totalDelivered = new AtomicLong(0);
    private final AtomicLong failedDeliveries = new AtomicLong(0);
    private final Map<DeliveryChannel, AtomicLong> channelMetrics = new ConcurrentHashMap<>();
    
    
    private final Map<String, CachedResult> resultCache = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initialize() {
        log.info("비동기 결과 전달 서비스 초기화 시작");
        
        
        startBatchProcessor();
        
        
        startCacheCleaner();
        
        
        startRetryScheduler();
        
        log.info("비동기 결과 전달 서비스 초기화 완료");
    }
    
    
    public Mono<DeliveryResult> deliverSoarResult(String requestId, SoarResponse response) {
        log.info("SOAR 결과 전달 시작 - Request ID: {}, Recommendations: {}", 
            requestId, response.getRecommendations().size());
        
        return Mono.fromCallable(() -> {
            
            DeliveryStatus status = new DeliveryStatus(requestId);
            deliveryStatuses.put(requestId, status);
            
            return saveToDatabase(requestId, response)
                .flatMap(saved -> {
                    if (saved) {
                        status.markDatabaseDelivered();
                    } else {
                        status.markDatabaseFailed();
                    }
                    
                    
                    List<Mono<Boolean>> deliveries = new ArrayList<>();
                    
                    
                    if (eventPublishingEnabled) {
                        deliveries.add(publishToRedis(requestId, response)
                            .doOnSuccess(success -> {
                                if (success) status.markEventDelivered();
                                else status.markEventFailed();
                            }));
                    }
                    
                    
                    if (websocketEnabled) {
                        deliveries.add(pushToWebSocket(requestId, response)
                            .doOnSuccess(success -> {
                                if (success) status.markWebSocketDelivered();
                                else status.markWebSocketFailed();
                            }));
                    }
                    
                    
                    if (notificationEnabled) {
                        deliveries.add(sendNotification(requestId, response)
                            .doOnSuccess(success -> {
                                if (success) status.markNotificationDelivered();
                                else status.markNotificationFailed();
                            }));
                    }
                    
                    
                    return Flux.merge(deliveries)
                        .collectList()
                        .map(results -> {
                            status.setCompleted(true);
                            
                            
                            cacheResult(requestId, response);
                            
                            
                            updateMetrics(status);
                            
                            return createDeliveryResult(requestId, status, response);
                        });
                })
                .onErrorResume(error -> {
                    log.error("결과 전달 실패 - Request ID: {}", requestId, error);
                    status.setError(error.getMessage());
                    failedDeliveries.incrementAndGet();
                    
                    
                    queueForRetry(requestId, response);
                    
                    return Mono.just(createDeliveryResult(requestId, status, response));
                });
        })
        .flatMap(mono -> mono)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    public Mono<DeliveryResult> deliverToolExecutionResult(String executionId, Object result, boolean success) {
        log.info("도구 실행 결과 전달 - Execution ID: {}, Success: {}", executionId, success);
        
        Map<String, Object> resultData = new HashMap<>();
        resultData.put("executionId", executionId);
        resultData.put("result", result);
        resultData.put("success", success);
        resultData.put("timestamp", LocalDateTime.now());
        
        
        SoarResponse response = new SoarResponse(executionId, 
            success ? AIResponse.ExecutionStatus.SUCCESS : AIResponse.ExecutionStatus.FAILURE);
        response.setSessionId(executionId);
        response.setRecommendations(Collections.singletonList(
            success ? "도구 실행 성공" : "도구 실행 실패"
        ));
        response.setThreatLevel(success ? 
            io.contexa.contexacore.domain.SoarContext.ThreatLevel.LOW : 
            io.contexa.contexacore.domain.SoarContext.ThreatLevel.MEDIUM);
        response.setMetadata(resultData);
        
        return deliverSoarResult(executionId, response);
    }
    
    
    public Mono<List<DeliveryResult>> deliverBatchResults(Map<String, SoarResponse> results) {
        log.info("배치 결과 전달 시작 - {} 건", results.size());
        
        return Flux.fromIterable(results.entrySet())
            .flatMap(entry -> deliverSoarResult(entry.getKey(), entry.getValue()))
            .collectList();
    }
    
    
    public Mono<SoarResponse> getResult(String requestId) {
        
        CachedResult cached = resultCache.get(requestId);
        if (cached != null && !cached.isExpired()) {
            return Mono.just(cached.getResponse());
        }
        
        
        return Mono.fromCallable(() -> {
            Optional<ToolExecutionContext> context = executionRepository.findByRequestId(requestId);
            if (context.isPresent()) {
                String result = context.get().getExecutionResult();
                if (result != null && !result.isEmpty()) {
                    
                    try {
                        SoarResponse response = objectMapper.readValue(result, SoarResponse.class);
                        cacheResult(requestId, response);
                        return response;
                    } catch (Exception e) {
                        log.error("결과 파싱 실패: {}", requestId, e);
                    }
                }
            }
            return null;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    public Mono<DeliveryStatus> getDeliveryStatus(String requestId) {
        return Mono.justOrEmpty(deliveryStatuses.get(requestId));
    }
    
    
    private Mono<Boolean> saveToDatabase(String requestId, SoarResponse response) {
        return Mono.fromCallable(() -> {
            try {
                
                ToolExecutionContext context = executionRepository.findByRequestId(requestId)
                    .orElse(new ToolExecutionContext());
                
                context.setRequestId(requestId);
                context.setExecutionResult(objectMapper.writeValueAsString(response));
                context.setStatus("EXECUTED");
                context.setExecutionEndTime(LocalDateTime.now());
                
                executionRepository.save(context);
                
                log.debug("DB 저장 성공 - Request ID: {}", requestId);
                return true;
            } catch (Exception e) {
                log.error("DB 저장 실패 - Request ID: {}", requestId, e);
                return false;
            }
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private Mono<Boolean> publishToRedis(String requestId, SoarResponse response) {
        return Mono.fromCallable(() -> {
            try {
                Map<String, Object> event = new HashMap<>();
                event.put("requestId", requestId);
                event.put("type", "SOAR_RESULT");
                event.put("recommendations", response.getRecommendations());
                event.put("riskLevel", response.getThreatLevel());
                event.put("timestamp", LocalDateTime.now());
                
                eventPublisher.publishEvent("soar-results", event);
                
                
                String key = "soar:result:" + requestId;
                redisTemplate.opsForValue().set(key, response, resultTtlHours, TimeUnit.HOURS);
                
                log.debug("Redis 이벤트 발행 성공 - Request ID: {}", requestId);
                channelMetrics.computeIfAbsent(DeliveryChannel.REDIS, k -> new AtomicLong()).incrementAndGet();
                return true;
            } catch (Exception e) {
                log.error("Redis 이벤트 발행 실패 - Request ID: {}", requestId, e);
                return false;
            }
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private Mono<Boolean> pushToWebSocket(String requestId, SoarResponse response) {
        return Mono.fromCallable(() -> {
            try {
                Map<String, Object> message = new HashMap<>();
                message.put("type", "SOAR_RESULT");
                message.put("requestId", requestId);
                message.put("response", response);
                message.put("timestamp", LocalDateTime.now());
                
                
                String destination = "/queue/soar-results/" + requestId;
                messagingTemplate.convertAndSend(destination, (Object)message);
                
                
                messagingTemplate.convertAndSend("/topic/soar-results", (Object)message);
                
                log.debug("WebSocket 푸시 성공 - Request ID: {}", requestId);
                channelMetrics.computeIfAbsent(DeliveryChannel.WEBSOCKET, k -> new AtomicLong()).incrementAndGet();
                return true;
            } catch (Exception e) {
                log.error("WebSocket 푸시 실패 - Request ID: {}", requestId, e);
                return false;
            }
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private Mono<Boolean> sendNotification(String requestId, SoarResponse response) {
        return notificationService.sendCompletionNotification(requestId, response)
            .map(result -> {
                if (result.isSuccess()) {
                    log.debug("알림 발송 성공 - Request ID: {}", requestId);
                    channelMetrics.computeIfAbsent(DeliveryChannel.NOTIFICATION, k -> new AtomicLong()).incrementAndGet();
                    return true;
                } else {
                    log.warn("알림 발송 실패 - Request ID: {}", requestId);
                    return false;
                }
            })
            .onErrorReturn(false);
    }
    
    
    private void cacheResult(String requestId, SoarResponse response) {
        CachedResult cached = new CachedResult(response, LocalDateTime.now().plusHours(1));
        resultCache.put(requestId, cached);
        
        
        if (resultCache.size() > 1000) {
            
            resultCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
        }
    }
    
    
    private void queueForRetry(String requestId, SoarResponse response) {
        PendingResult pending = new PendingResult(requestId, response, 0, LocalDateTime.now());
        resultQueue.add(pending);
    }
    
    
    private void startBatchProcessor() {
        Schedulers.parallel().schedulePeriodically(() -> {
            if (!resultQueue.isEmpty()) {
                List<PendingResult> batch;
                synchronized (resultQueue) {
                    batch = resultQueue.stream()
                        .limit(batchSize)
                        .collect(Collectors.toList());
                    resultQueue.removeAll(batch);
                }
                
                processBatch(batch);
            }
        }, batchIntervalMs, batchIntervalMs, TimeUnit.MILLISECONDS);
    }
    
    
    private void processBatch(List<PendingResult> batch) {
        log.debug("배치 결과 전달 처리 - {} 건", batch.size());
        
        Flux.fromIterable(batch)
            .flatMap(pending -> deliverSoarResult(pending.getRequestId(), pending.getResponse()))
            .subscribe(
                result -> log.debug("배치 전달 완료: {}", result.getRequestId()),
                error -> log.error("배치 전달 실패", error)
            );
    }
    
    
    private void startRetryScheduler() {
        Schedulers.parallel().schedulePeriodically(() -> {
            
            deliveryStatuses.entrySet().stream()
                .filter(entry -> !entry.getValue().isCompleted() && 
                        entry.getValue().getRetryCount() < maxRetryAttempts)
                .forEach(entry -> {
                    String requestId = entry.getKey();
                    DeliveryStatus status = entry.getValue();
                    
                    
                    String key = "soar:result:" + requestId;
                    SoarResponse response = (SoarResponse) redisTemplate.opsForValue().get(key);
                    
                    if (response != null) {
                        status.incrementRetry();
                        deliverSoarResult(requestId, response)
                            .subscribe(
                                result -> log.info("재시도 성공: {}", requestId),
                                error -> log.error("재시도 실패: {}", requestId, error)
                            );
                    }
                });
        }, retryDelaySeconds, retryDelaySeconds * 2, TimeUnit.SECONDS);
    }
    
    
    private void startCacheCleaner() {
        Schedulers.parallel().schedulePeriodically(() -> {
            
            int removed = 0;
            for (Iterator<Map.Entry<String, CachedResult>> it = resultCache.entrySet().iterator(); it.hasNext();) {
                Map.Entry<String, CachedResult> entry = it.next();
                if (entry.getValue().isExpired()) {
                    it.remove();
                    removed++;
                }
            }
            
            if (removed > 0) {
                log.debug("캐시 정리 완료 - {} 개 엔트리 제거", removed);
            }
            
            
            LocalDateTime cutoff = LocalDateTime.now().minusHours(resultTtlHours);
            deliveryStatuses.entrySet().removeIf(entry -> 
                entry.getValue().getCreatedAt().isBefore(cutoff)
            );
            
        }, 3600, 3600, TimeUnit.SECONDS);  
    }
    
    
    private DeliveryResult createDeliveryResult(String requestId, DeliveryStatus status, SoarResponse response) {
        return DeliveryResult.builder()
            .requestId(requestId)
            .success(status.isAllChannelsDelivered())
            .deliveredChannels(status.getDeliveredChannels())
            .failedChannels(status.getFailedChannels())
            .timestamp(LocalDateTime.now())
            .response(response)
            .build();
    }
    
    
    private void updateMetrics(DeliveryStatus status) {
        if (status.isAllChannelsDelivered()) {
            totalDelivered.incrementAndGet();
        } else if (status.hasFailures()) {
            failedDeliveries.incrementAndGet();
        }
    }
    
    
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("totalDelivered", totalDelivered.get());
        metrics.put("failedDeliveries", failedDeliveries.get());
        
        Map<String, Long> channelStats = new HashMap<>();
        channelMetrics.forEach((channel, count) -> 
            channelStats.put(channel.name(), count.get())
        );
        metrics.put("channelStats", channelStats);
        
        metrics.put("queueSize", resultQueue.size());
        metrics.put("cacheSize", resultCache.size());
        metrics.put("activeDeliveries", deliveryStatuses.size());
        
        return metrics;
    }
    
    
    
    
    public enum DeliveryChannel {
        DATABASE, REDIS, WEBSOCKET, NOTIFICATION
    }
    
    
    @lombok.Data
    public static class DeliveryStatus {
        private final String requestId;
        private final LocalDateTime createdAt;
        private boolean completed;
        private int retryCount;
        private String error;
        
        private boolean databaseDelivered;
        private boolean eventDelivered;
        private boolean webSocketDelivered;
        private boolean notificationDelivered;
        
        public DeliveryStatus(String requestId) {
            this.requestId = requestId;
            this.createdAt = LocalDateTime.now();
        }
        
        public void incrementRetry() {
            retryCount++;
        }
        
        public void markDatabaseDelivered() {
            databaseDelivered = true;
        }
        
        public void markDatabaseFailed() {
            databaseDelivered = false;
        }
        
        public void markEventDelivered() {
            eventDelivered = true;
        }
        
        public void markEventFailed() {
            eventDelivered = false;
        }
        
        public void markWebSocketDelivered() {
            webSocketDelivered = true;
        }
        
        public void markWebSocketFailed() {
            webSocketDelivered = false;
        }
        
        public void markNotificationDelivered() {
            notificationDelivered = true;
        }
        
        public void markNotificationFailed() {
            notificationDelivered = false;
        }
        
        public boolean isAllChannelsDelivered() {
            return databaseDelivered && eventDelivered && 
                   webSocketDelivered && notificationDelivered;
        }
        
        public boolean hasFailures() {
            return !databaseDelivered || !eventDelivered || 
                   !webSocketDelivered || !notificationDelivered;
        }
        
        public List<DeliveryChannel> getDeliveredChannels() {
            List<DeliveryChannel> channels = new ArrayList<>();
            if (databaseDelivered) channels.add(DeliveryChannel.DATABASE);
            if (eventDelivered) channels.add(DeliveryChannel.REDIS);
            if (webSocketDelivered) channels.add(DeliveryChannel.WEBSOCKET);
            if (notificationDelivered) channels.add(DeliveryChannel.NOTIFICATION);
            return channels;
        }
        
        public List<DeliveryChannel> getFailedChannels() {
            List<DeliveryChannel> channels = new ArrayList<>();
            if (!databaseDelivered) channels.add(DeliveryChannel.DATABASE);
            if (!eventDelivered) channels.add(DeliveryChannel.REDIS);
            if (!webSocketDelivered) channels.add(DeliveryChannel.WEBSOCKET);
            if (!notificationDelivered) channels.add(DeliveryChannel.NOTIFICATION);
            return channels;
        }
    }
    
    
    @lombok.Data
    @lombok.Builder
    public static class DeliveryResult {
        private String requestId;
        private boolean success;
        private List<DeliveryChannel> deliveredChannels;
        private List<DeliveryChannel> failedChannels;
        private LocalDateTime timestamp;
        private SoarResponse response;
    }
    
    
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class PendingResult {
        private String requestId;
        private SoarResponse response;
        private int retryCount;
        private LocalDateTime queuedAt;
    }
    
    
    @lombok.AllArgsConstructor
    private static class CachedResult {
        private final SoarResponse response;
        private final LocalDateTime expiryTime;
        
        public SoarResponse getResponse() {
            return response;
        }
        
        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiryTime);
        }
    }
}