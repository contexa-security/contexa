package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.RedisSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.processor.EventNormalizer;
import io.contexa.contexacore.autonomous.processor.EventDeduplicator;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 보안 모니터링 서비스 구현
 *
 * Observer 패턴을 사용하여 보안 이벤트를 실시간으로 모니터링하고
 * 위협을 평가하여 인시던트를 생성합니다.
 */
@Service
public class SecurityMonitoringService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityMonitoringService.class);

    private final KafkaSecurityEventCollector kafkaCollector;
    private final RedisSecurityEventCollector redisCollector;
    private final SecurityIncidentRepository securityIncidentRepository;
    private final List<ThreatEvaluationStrategy> evaluationStrategies;
    private final List<SecurityEventListener> eventListeners;
    private final EventNormalizer eventNormalizer;
    private final EventDeduplicator eventDeduplicator;
    private final SecurityEventEnricher eventEnricher;
    private final Map<String, MonitoringSession> activeSessions;
    private final Map<String, SecurityIncident> activeIncidents;
    private final BlockingQueue<SecurityEvent> eventQueue;
    private final ExecutorService executorService;
    private final ScheduledExecutorService scheduler;
    private final int workerThreads;
    private volatile boolean running;
    private final AtomicLong eventCounter;
    private final AtomicLong incidentCounter;
    private final Cache<String, Long> eventDeduplicationCache;
    private final int dedupWindowMinutes;

    public SecurityMonitoringService(
            KafkaSecurityEventCollector kafkaCollector,
            RedisSecurityEventCollector redisCollector,
            SecurityIncidentRepository securityIncidentRepository,
            ThreatIndicatorRepository indicatorRepository,
            List<ThreatEvaluationStrategy> evaluationStrategies,
            EventNormalizer eventNormalizer,
            EventDeduplicator eventDeduplicator,
            SecurityEventEnricher eventEnricher,
            @Value("${security.plane.monitor.queue-size:10000}") int queueSize,
            @Value("${security.plane.monitor.worker-threads:5}") int workerThreads,
            @Value("${security.plane.monitor.correlation-window-minutes:10}") int correlationWindowMinutes,
            @Value("${security.plane.monitor.threat-threshold:0.7}") double threatThreshold,
            @Value("${security.plane.monitor.auto-incident-creation:true}") boolean autoIncidentCreation,
            @Value("${security.plane.monitor.dedup-window-minutes:5}") int dedupWindowMinutes) {
        this.kafkaCollector = kafkaCollector;
        this.redisCollector = redisCollector;
        this.securityIncidentRepository = securityIncidentRepository;
        this.evaluationStrategies = evaluationStrategies;
        this.eventNormalizer = eventNormalizer;
        this.eventDeduplicator = eventDeduplicator;
        this.eventEnricher = eventEnricher;
        this.workerThreads = workerThreads;
        this.eventListeners = new CopyOnWriteArrayList<>();
        this.activeSessions = new ConcurrentHashMap<>();
        this.activeIncidents = new ConcurrentHashMap<>();
        this.eventQueue = new LinkedBlockingQueue<>(queueSize);
        this.executorService = Executors.newFixedThreadPool(workerThreads);
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.running = true;
        this.eventCounter = new AtomicLong(0);
        this.incidentCounter = new AtomicLong(0);
        this.dedupWindowMinutes = dedupWindowMinutes;

        // 중복 제거를 위한 캐시 초기화 (TTL 설정)
        this.eventDeduplicationCache = CacheBuilder.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(dedupWindowMinutes, TimeUnit.MINUTES)
                .build();
    }

    // eventId 기반 중복 필터 (1시간 TTL)
    private final ConcurrentHashMap<String, Long> processedEvents = new ConcurrentHashMap<>();
    private static final long DEDUP_TTL_MS = 3600_000; // 1시간

    @PostConstruct
    public void initialize() {
        logger.info("Initializing Security Monitoring Service");

        // Kafka만 사용하여 이중 수집 방지
        kafkaCollector.registerListener(new CollectorEventListener());
        // Redis Collector 등록 제거 - Kafka 단일 채널 사용으로 이중 수집 방지
        logger.info("Redis Collector registration skipped - using Kafka single channel to prevent duplicate collection");

        loadActiveIncidents();

        // 중복 필터 정리 스케줄러 (1시간마다)
        scheduler.scheduleAtFixedRate(this::cleanupDedupFilter, 1, 1, TimeUnit.HOURS);
    }

    /**
     * 중복 필터 정리 (만료된 항목 제거)
     */
    private void cleanupDedupFilter() {
        long now = System.currentTimeMillis();
        int removed = 0;
        for (Map.Entry<String, Long> entry : processedEvents.entrySet()) {
            if (now - entry.getValue() > DEDUP_TTL_MS) {
                processedEvents.remove(entry.getKey());
                removed++;
            }
        }
        if (removed > 0) {
            logger.debug("Cleaned up {} expired entries from dedup filter", removed);
        }
    }

    @PreDestroy
    public void shutdown() {
        logger.info("Shutting down Security Monitoring Service");
        running = false;

        executorService.shutdown();
        scheduler.shutdown();

        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }

        logger.info("Security Monitoring Service shut down");
    }

    /**
     * SecurityPlaneAgent를 위한 모니터링 시작
     * - 에이전트별 독립적인 모니터링 세션 생성
     * - 커렉터 구성 및 필터링 설정
     */
    public void startMonitoring(String sessionId, Map<String, Object> config) {
        logger.info("Starting monitoring session {}", sessionId);

        // 이미 활성 세션이 있는지 확인
        if (activeSessions.containsKey(sessionId)) {
            logger.warn("Monitoring session already exists for: {}", sessionId);
            return;
        }

        MonitoringSession session = new MonitoringSession(sessionId, config);
        activeSessions.put(sessionId, session);

        logger.info("Monitoring session {} started for agent {}", sessionId, config.get("agentId"));
    }

    /**
     * SecurityPlaneAgent를 위한 모니터링 중지
     * - 커렉터 비활성화
     * - 세션 정리
     */
    public void stopMonitoring(String sessionId) {
        logger.info("Stopping monitoring session {}", sessionId);

        MonitoringSession session = activeSessions.remove(sessionId);
        if (session != null) {
            session.stop();

            // 세션 종료 시 로깅
            if (activeSessions.isEmpty()) {
                logger.info("All monitoring sessions stopped");
            }

            logger.info("Monitoring session {} stopped", sessionId);
        } else {
            logger.warn("No active monitoring session found for: {}", sessionId);
        }
    }

    /**
     * 큐에서 이벤트를 가져오는 메서드 (중복 처리 방지)
     */
    public List<SecurityEvent> pollEventsFromQueue(int limit, long timeoutMs) {
        List<SecurityEvent> processedEvents = new ArrayList<>();
        long endTime = System.currentTimeMillis() + timeoutMs;

        while (processedEvents.size() < limit && System.currentTimeMillis() < endTime) {
            try {
                long remainingTime = endTime - System.currentTimeMillis();
                if (remainingTime <= 0) break;

                SecurityEvent rawEvent = eventQueue.poll(Math.min(remainingTime, 100), TimeUnit.MILLISECONDS);
                if (rawEvent != null) {
                    SecurityEvent processed = preprocessEvent(rawEvent);
                    if (processed != null) {
                        processedEvents.add(processed);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        return processedEvents;
    }

    private SecurityEvent preprocessEvent(SecurityEvent event) {
        try {
            SecurityEvent normalizedEvent = eventNormalizer.process(event);
            if (normalizedEvent == null) {
                logger.debug("Event filtered during normalization");
                return null;
            }

            SecurityEvent deduplicatedEvent = eventDeduplicator.process(normalizedEvent);
            if (deduplicatedEvent == null) {
                logger.debug("Duplicate event filtered: {}", normalizedEvent.getEventId());
                return null;
            }

            eventEnricher.enrichEvent(deduplicatedEvent, "processingTimestamp", LocalDateTime.now());
            eventEnricher.enrichEvent(deduplicatedEvent, "monitoringServiceProcessed", true);

            eventCounter.incrementAndGet();

            return deduplicatedEvent;
        } catch (Exception e) {
            logger.error("Error preprocessing event", e);
            return null;
        }
    }

    public Map<String, Object> getMonitoringStatistics() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("total_events", eventCounter.get());
        stats.put("total_incidents", incidentCounter.get());
        stats.put("active_sessions", activeSessions.size());
        stats.put("active_incidents", activeIncidents.size());
        stats.put("queue_size", eventQueue.size());
        stats.put("event_listeners", eventListeners.size());
        stats.put("evaluation_strategies", evaluationStrategies.size());

        // Add collector statistics
        stats.put("kafka_stats", kafkaCollector.getStatistics());
        stats.put("redis_stats", redisCollector.getStatistics());

        return stats;
    }

    private void eventProcessingWorker() {
        while (running) {
            try {
                SecurityEvent event = eventQueue.poll(1, TimeUnit.SECONDS);
                if (event != null) {
                    processEvent(event);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error processing event", e);
            }
        }
    }

    private void processEvent(SecurityEvent event) {
        try {
            // 1. 이벤트 정규화 (EventNormalizer 사용)
            SecurityEvent normalizedEvent = eventNormalizer.process(event);
            if (normalizedEvent == null) {
                logger.debug("Event filtered during normalization");
                return;
            }
            
            // 2. 이벤트 중복 제거 (EventDeduplicator 사용)
            SecurityEvent deduplicatedEvent = eventDeduplicator.process(normalizedEvent);
            if (deduplicatedEvent == null) {
                logger.debug("Duplicate event filtered: {}", normalizedEvent.getEventId());
                return;
            }
            
            // 3. 이벤트 보강 (SecurityEventEnricher 사용)
            eventEnricher.enrichEvent(deduplicatedEvent, "processingTimestamp", LocalDateTime.now());
            eventEnricher.enrichEvent(deduplicatedEvent, "monitoringServiceProcessed", true);

            // 4. 이벤트 카운터 증가
            eventCounter.incrementAndGet();

            // 5. 추가 처리 로직 (기존 로직 유지 가능)
            logger.trace("Event processed successfully: eventId={}, type={}",
                        deduplicatedEvent.getEventId(), deduplicatedEvent.getEventType());

        } catch (Exception e) {
            logger.error("Error processing event", e);
        }
    }

    /**
     * 이벤트 중복 체크 - 이벤트 ID와 해시 기반 중복 제거
     * @deprecated EventDeduplicator로 대체됨
     */
    @Deprecated
    private boolean isDuplicateEvent(SecurityEvent event) {
        // 이벤트 ID가 있으면 ID로 체크
        if (event.getEventId() != null && !event.getEventId().isEmpty()) {
            Long existingTimestamp = eventDeduplicationCache.getIfPresent(event.getEventId());
            if (existingTimestamp != null) {
                logger.debug("Duplicate event detected by ID: {}", event.getEventId());
                return true;
            }
            eventDeduplicationCache.put(event.getEventId(), System.currentTimeMillis());
        }

        // 이벤트 내용 해시로 중복 체크
        String eventHash = calculateEventHash(event);
        if (eventHash != null) {
            Long existingTimestamp = eventDeduplicationCache.getIfPresent(eventHash);
            if (existingTimestamp != null) {
                // 같은 내용의 이벤트가 짧은 시간 내에 반복되면 중복
                long timeDiff = System.currentTimeMillis() - existingTimestamp;
                if (timeDiff < TimeUnit.MINUTES.toMillis(dedupWindowMinutes)) {
                    logger.debug("Duplicate event detected by hash: {} ({}ms apart)",
                            eventHash, timeDiff);
                    return true;
                }
            }
            eventDeduplicationCache.put(eventHash, System.currentTimeMillis());
        }

        return false;
    }

    /**
     * 이벤트 해시 계산 - 주요 필드를 기반으로 고유 해시 생성
     * @deprecated EventDeduplicator로 대체됨
     */
    @Deprecated
    private String calculateEventHash(SecurityEvent event) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");

            // 주요 필드를 기반으로 해시 생성
            StringBuilder sb = new StringBuilder();
            sb.append(event.getEventType());
            sb.append("|");
            sb.append(event.getSourceIp() != null ? event.getSourceIp() : "null");
            sb.append("|");
            sb.append(event.getUserId() != null ? event.getUserId() : "null");
            sb.append("|");
            sb.append(event.getTargetIp() != null ? event.getTargetIp() : "null");
            sb.append("|");
            sb.append(event.getSeverity());

            // 시간은 분 단위로만 포함 (초 단위 반복 방지)
            if (event.getTimestamp() != null) {
                sb.append("|");
                sb.append(event.getTimestamp().getMinute());
            }

            byte[] hashBytes = md.digest(sb.toString().getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);

        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to calculate event hash", e);
            return null;
        }
    }

    private void loadActiveIncidents() {
        List<SecurityIncident> incidents = securityIncidentRepository.findActiveIncidents();
        for (SecurityIncident incident : incidents) {
            activeIncidents.put(incident.getIncidentId(), incident);
        }
        logger.info("Loaded {} active incidents", activeIncidents.size());
    }

    /**
     * Event listener for collectors
     */
    private class CollectorEventListener implements SecurityEventListener {
        @Override
        public void onSecurityEvent(SecurityEvent event) {
            String eventId = event.getEventId();

            // eventId 기반 중복 체크
            Long timestamp = processedEvents.get(eventId);
            if (timestamp != null && (System.currentTimeMillis() - timestamp) < DEDUP_TTL_MS) {
                logger.debug("[MonitoringService] Duplicate event ignored - eventId: {}, age: {}ms",
                    eventId, System.currentTimeMillis() - timestamp);
                return;
            }

            logger.info("[MonitoringService] Received event from collector - eventId: {}, type: {}, queueSize: {}",
                eventId, event.getEventType(), eventQueue.size());

            try {
                boolean offered = eventQueue.offer(event, 100, TimeUnit.MILLISECONDS);
                if (offered) {
                    // 이벤트 처리 성공 시 중복 필터에 등록
                    processedEvents.put(eventId, System.currentTimeMillis());

                    logger.info("[MonitoringService] Event queued successfully - eventId: {}, newQueueSize: {}",
                        eventId, eventQueue.size());
                } else {
                    // 큐 추가 실패 시 예외 발생 - 상위 호출자에게 전파되어 ACK 방지
                    String errorMsg = String.format(
                        "Failed to queue event (timeout or queue full) - eventId: %s, queueSize: %d, queueCapacity: %d",
                        event.getEventId(), eventQueue.size(), eventQueue.remainingCapacity());
                    logger.error("[MonitoringService] {}", errorMsg);
                    throw new RuntimeException(errorMsg);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("[MonitoringService] Interrupted while queuing event - eventId: {}",
                    event.getEventId(), e);
                // 인터럽트 예외를 RuntimeException으로 래핑하여 재발생
                throw new RuntimeException("Interrupted while queuing event: " + event.getEventId(), e);
            }
        }

        @Override
        public String getListenerName() {
            return "MonitoringServiceListener";
        }
    }

    /**
     * Monitoring session
     */
    private static class MonitoringSession {
        private final String id;
        private final Map<String, Object> config;
        private final LocalDateTime startTime;
        private volatile boolean active;

        public MonitoringSession(String id, Map<String, Object> config) {
            this.id = id;
            this.config = config;
            this.startTime = LocalDateTime.now();
            this.active = true;
        }

        public void stop() {
            active = false;
        }

        public String getId() {
            return id;
        }

        public Map<String, Object> getConfig() {
            return config;
        }

        public boolean isActive() {
            return active;
        }
    }
}