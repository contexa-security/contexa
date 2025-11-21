package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import org.redisson.api.*;
import org.springframework.data.redis.connection.MessageListener;
import org.redisson.client.codec.StringCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.PatternTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.LocalDateTime;
import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Redis 기반 보안 이벤트 수집기
 * 
 * Redis Pub/Sub과 Streams를 사용하여 실시간 보안 이벤트를 수집하고 처리합니다.
 * 분산 환경에서 이벤트 동기화와 캐싱을 제공합니다.
 */
public class RedisSecurityEventCollector {
    
    private static final Logger logger = LoggerFactory.getLogger(RedisSecurityEventCollector.class);
    
    @Value("${security.plane.redis.channel.security-events:security:events}")
    private String securityEventsChannel;
    
    @Value("${security.plane.redis.channel.threat-alerts:security:threats}")
    private String threatAlertsChannel;
    
    @Value("${security.plane.redis.channel.incidents:security:incidents}")
    private String incidentsChannel;
    
    @Value("${security.plane.redis.stream.events:security-events-stream}")
    private String eventsStreamKey;
    
    @Value("${security.plane.redis.cache.ttl-minutes:60}")
    private int cacheTtlMinutes;
    
    @Value("${security.plane.redis.batch-size:50}")
    private int batchSize;
    
    private final RedissonClient redissonClient;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final RedisMessageListenerContainer messageListenerContainer;
    
    private final List<SecurityEventListener> listeners;
    private final Map<String, SecurityEvent> eventCache;
    private final AtomicLong eventCount;
    private final AtomicLong errorCount;

    private RTopic securityEventsTopic;
    private RMapCache<String, String> distributedCache;
    private RAtomicLong globalEventCounter;
    private RRateLimiter rateLimiter;
    private RBloomFilter<String> deduplicationFilter;
    
    private volatile boolean running;
    private String consumerId;
    private String consumerGroup;
    
    public RedisSecurityEventCollector(
        RedissonClient redissonClient,
        StringRedisTemplate redisTemplate,
        ObjectMapper objectMapper,
        RedisMessageListenerContainer messageListenerContainer
    ) {
        this.redissonClient = redissonClient;
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.messageListenerContainer = messageListenerContainer;
        this.listeners = new CopyOnWriteArrayList<>();
        this.eventCache = new ConcurrentHashMap<>();
        this.eventCount = new AtomicLong(0);
        this.errorCount = new AtomicLong(0);
        this.running = true;
        this.consumerId = "security-plane-" + UUID.randomUUID().toString().substring(0, 8);
        this.consumerGroup = "security-plane-consumers";
    }
    
    @PostConstruct
    public void initialize() {
        logger.info("Initializing Redis Security Event Collector");
        logger.info("Consumer ID: {}, Consumer Group: {}", consumerId, consumerGroup);
        
        // Initialize Redis components
        initializeRedisComponents();
        
        // Setup Pub/Sub listeners
        setupPubSubListeners();

        logger.info("Redis Security Event Collector initialized successfully");
    }
    
    @PreDestroy
    public void shutdown() {
        logger.info("Shutting down Redis Security Event Collector");
        running = false;

        // Clean up Redis resources
        if (securityEventsTopic != null) {
            securityEventsTopic.removeAllListeners();
        }

        logger.info("Redis Security Event Collector shut down");
    }
    
    private void initializeRedisComponents() {
        // Initialize distributed cache with TTL
        distributedCache = redissonClient.getMapCache(ZeroTrustRedisKeys.eventsCache(), StringCodec.INSTANCE);

        // Initialize global event counter
        globalEventCounter = redissonClient.getAtomicLong(ZeroTrustRedisKeys.eventsCounter());

        // Initialize rate limiter (1000 events per second)
        rateLimiter = redissonClient.getRateLimiter(ZeroTrustRedisKeys.eventsLimiter());
        rateLimiter.trySetRate(RateType.OVERALL, 1000, 1, RateIntervalUnit.SECONDS);

        // Initialize deduplication filter
        deduplicationFilter = redissonClient.getBloomFilter(ZeroTrustRedisKeys.eventsDedup());
        deduplicationFilter.tryInit(1000000, 0.01); // 1M expected events, 1% false positive
    }
    
    private void setupPubSubListeners() {
        // Security events topic
        securityEventsTopic = redissonClient.getTopic(securityEventsChannel, StringCodec.INSTANCE);
        securityEventsTopic.addListener(String.class, (channel, msg) -> {
            long startTime = System.currentTimeMillis();
            logger.debug("[RedisCollector] RECEIVED event from channel '{}' - thread: {}",
                channel, Thread.currentThread().getName());

            try {
                // 메시지가 배열인지 단일 객체인지 확인
                if (msg.trim().startsWith("[")) {
                   JsonNode rootNode = objectMapper.readTree(msg);

                    if (rootNode.isArray() && rootNode.size() == 2 && rootNode.get(0).isTextual()) {
                        // 타입 정보 포함 형식 - 두 번째 요소만 파싱
                        SecurityEvent event = objectMapper.treeToValue(rootNode.get(1), SecurityEvent.class);

                        logger.debug("[RedisCollector] Parsed event from typed array - eventId: {}, type: {}",
                            event.getEventId(), event.getEventType());

                        event.setSource(SecurityEvent.EventSource.REDIS);
                        event.addMetadata("redis.channel", channel.toString());
                        processEvent(event);

                        long count = eventCount.incrementAndGet();
                        long duration = System.currentTimeMillis() - startTime;

                        logger.debug("[RedisCollector] PROCESSED typed array event - eventId: {}, totalCount: {}, duration: {}ms",
                            event.getEventId(), count, duration);

                    } else {
                        // 일반 배열 형태의 메시지 처리
                        List<SecurityEvent> events = objectMapper.readValue(msg,
                            objectMapper.getTypeFactory().constructCollectionType(List.class, SecurityEvent.class));

                        logger.debug("[RedisCollector] Parsed {} events from array", events.size());

                        for (SecurityEvent event : events) {
                            event.setSource(SecurityEvent.EventSource.REDIS);
                            event.addMetadata("redis.channel", channel.toString());
                            processEvent(event);
                        }

                        long count = eventCount.addAndGet(events.size());
                        long duration = System.currentTimeMillis() - startTime;

                        logger.debug("[RedisCollector] PROCESSED {} events successfully - totalCount: {}, duration: {}ms",
                            events.size(), count, duration);
                    }

                } else {
                    // 단일 객체 처리
                    SecurityEvent event = objectMapper.readValue(msg, SecurityEvent.class);

                    logger.debug("[RedisCollector] Parsed event - eventId: {}, type: {}, userId: {}",
                        event.getEventId(), event.getEventType(), event.getUserId());

                    event.setSource(SecurityEvent.EventSource.REDIS);
                    event.addMetadata("redis.channel", channel.toString());

                    logger.debug("[RedisCollector] Processing event - eventId: {}", event.getEventId());
                    processEvent(event);

                    long count = eventCount.incrementAndGet();
                    long duration = System.currentTimeMillis() - startTime;

                    logger.debug("[RedisCollector] PROCESSED event successfully - eventId: {}, totalCount: {}, duration: {}ms",
                        event.getEventId(), count, duration);
                }

            } catch (Exception e) {
                long errorCnt = errorCount.incrementAndGet();
                logger.error("[RedisCollector] ERROR processing event - channel: {}, errorCount: {}, error: {}, message: {}",
                    channel, errorCnt, e.getMessage(), msg.length() > 200 ? msg.substring(0, 200) + "..." : msg, e);
            }
        });
        
        // Threat alerts channel - use Spring Data Redis MessageListener
        MessageListener threatListener = (message, pattern) -> {
            try {
                String body = new String(message.getBody());
                logger.debug("Received threat alert: {}", body);
                
                SecurityEvent event = parseThreatAlert(body);
                processEvent(event);
            } catch (Exception e) {
                logger.error("Error processing threat alert: {}", e.getMessage());
                errorCount.incrementAndGet();
            }
        };
        messageListenerContainer.addMessageListener(
            threatListener,
            new ChannelTopic(threatAlertsChannel)
        );
        
        // Incident notifications channel - use Spring Data Redis MessageListener
        MessageListener incidentListener = (message, pattern) -> {
            try {
                String body = new String(message.getBody());
                logger.debug("Received incident: {}", body);
                
                SecurityEvent event = parseIncident(body);
                event.addMetadata("redis.channel", incidentsChannel);
                processEvent(event);
            } catch (Exception e) {
                logger.error("Error processing incident: {}", e.getMessage());
                errorCount.incrementAndGet();
            }
        };
        messageListenerContainer.addMessageListener(
            incidentListener,
            new PatternTopic(incidentsChannel + ":*")
        );
    }
    
    
    public void collectEvent(SecurityEvent event) {
        if (!running) {
            logger.warn("Collector is shutting down, ignoring event");
            return;
        }
        
        // Apply rate limiting
        if (!rateLimiter.tryAcquire()) {
            logger.warn("Rate limit exceeded, dropping event: {}", event.getEventId());
            return;
        }
        
        // Check for duplicates
        if (!deduplicationFilter.add(event.getEventId())) {
            logger.debug("Duplicate event detected: {}", event.getEventId());
            return;
        }
        
        processEvent(event);
    }
    
    public List<SecurityEvent> collectEvents(int maxEvents) {
        List<SecurityEvent> events = new ArrayList<>();
        
        // First try local cache
        eventCache.values().stream()
            .sorted(Comparator.comparing(SecurityEvent::getTimestamp).reversed())
            .limit(maxEvents)
            .forEach(events::add);
        
        // If not enough, fetch from distributed cache
        if (events.size() < maxEvents) {
            distributedCache.values().stream()
                .limit(maxEvents - events.size())
                .forEach(json -> {
                    try {
                        SecurityEvent event = objectMapper.readValue(json, SecurityEvent.class);
                        events.add(event);
                    } catch (Exception e) {
                        logger.error("Error deserializing cached event: {}", e.getMessage());
                    }
                });
        }
        
        return events;
    }
    
    public void registerListener(SecurityEventListener listener) {
        listeners.add(listener);
        logger.info("Registered security event listener: {}", listener.getListenerName());
    }
    
    public void unregisterListener(SecurityEventListener listener) {
        listeners.remove(listener);
        logger.info("Unregistered security event listener: {}", listener.getListenerName());
    }
    
    private void processEvent(SecurityEvent event) {
        // Update counters
        eventCount.incrementAndGet();
        globalEventCounter.incrementAndGet();
        
        // Add to local cache
        eventCache.put(event.getEventId(), event);
        
        // Notify listeners
        notifyListeners(event);
    }
    
    private void processBatchEvents(List<SecurityEvent> events) {
        // Add to cache
        events.forEach(event -> eventCache.put(event.getEventId(), event));
        
        // Notify listeners
        for (SecurityEventListener listener : listeners) {
            try {
                listener.onBatchEvents(events);
            } catch (Exception e) {
                logger.error("Error in batch event listener {}: {}", 
                    listener.getListenerName(), e.getMessage());
            }
        }
    }
    
    private void notifyListeners(SecurityEvent event) {
        for (SecurityEventListener listener : listeners) {
            try {
                if (listener.canHandle(event.getEventType()) && 
                    listener.canHandle(event.getSource())) {
                    listener.onSecurityEvent(event);
                    
                    // Route to specialized handlers
                    routeToSpecializedHandler(listener, event);
                }
            } catch (Exception e) {
                listener.onError(event, e);
            }
        }
    }
    
    private void routeToSpecializedHandler(SecurityEventListener listener, SecurityEvent event) {
        switch (event.getEventType()) {
            case INTRUSION_ATTEMPT:
            case NETWORK_SCAN:
                listener.onNetworkEvent(event);
                break;
            case AUTH_FAILURE:
            case PRIVILEGE_ESCALATION:
                listener.onAuthenticationEvent(event);
                break;
            case MALWARE_DETECTED:
                listener.onMalwareEvent(event);
                break;
            case ANOMALY_DETECTED:
                listener.onAnomalyEvent(event);
                break;
            case POLICY_VIOLATION:
                listener.onPolicyViolationEvent(event);
                break;
        }
        
        // High-risk events
        if (event.getSeverity() == SecurityEvent.Severity.CRITICAL ||
            event.getSeverity() == SecurityEvent.Severity.HIGH) {
            listener.onHighRiskEvent(event);
        }
    }
    
    private SecurityEvent parseThreatAlert(String json) throws Exception {
        Map<String, Object> data = objectMapper.readValue(json, Map.class);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.THREAT_DETECTED)
            .source(SecurityEvent.EventSource.THREAT_INTEL)
            .severity(SecurityEvent.Severity.HIGH)
            .timestamp(LocalDateTime.now())
            .description((String) data.get("description"))
            .sourceIp((String) data.get("source_ip"))
            .build();
    }
    
    private SecurityEvent parseIncident(String json) throws Exception {
        Map<String, Object> data = objectMapper.readValue(json, Map.class);
        
        return SecurityEvent.builder()
            .eventId((String) data.get("incident_id"))
            .eventType(SecurityEvent.EventType.INCIDENT_CREATED)
            .source(SecurityEvent.EventSource.SIEM)
            .severity(parseSeverity((String) data.get("severity")))
            .timestamp(LocalDateTime.now())
            .description((String) data.get("description"))
            .build();
    }
    
    
    private SecurityEvent.Severity parseSeverity(String severity) {
        if (severity == null) return SecurityEvent.Severity.MEDIUM;
        
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> SecurityEvent.Severity.CRITICAL;
            case "HIGH" -> SecurityEvent.Severity.HIGH;
            case "MEDIUM" -> SecurityEvent.Severity.MEDIUM;
            case "LOW" -> SecurityEvent.Severity.LOW;
            case "INFO" -> SecurityEvent.Severity.INFO;
            default -> SecurityEvent.Severity.MEDIUM;
        };
    }
    
    /**
     * 통계 조회
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("consumer_id", consumerId);
        stats.put("local_events", eventCount.get());
        stats.put("global_events", globalEventCounter.get());
        stats.put("error_count", errorCount.get());
        stats.put("cache_size", eventCache.size());
        stats.put("distributed_cache_size", distributedCache.size());
        stats.put("listener_count", listeners.size());
        stats.put("rate_limit", rateLimiter.getConfig().getRate());
        return stats;
    }
}