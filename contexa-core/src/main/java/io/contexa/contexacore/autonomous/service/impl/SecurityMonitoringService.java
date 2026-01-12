package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.RedisSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.BatchSecurityEventListener;
import io.contexa.contexacore.autonomous.processor.EventNormalizer;
import io.contexa.contexacore.autonomous.processor.EventDeduplicator;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 보안 모니터링 서비스 구현
 *
 * AI Native v5.0.0: 비동기 구조 최적화
 * - BlockingQueue 제거 -> Kafka Batch Listener로 대체
 * - 콜백 기반 배치 처리 (SecurityEventBatchProcessor)
 * - 이벤트 전처리 후 Agent로 직접 전달
 */
public class SecurityMonitoringService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityMonitoringService.class);

    /**
     * 배치 이벤트 처리 콜백 인터페이스
     * SecurityPlaneAgent가 구현하여 배치 이벤트를 수신
     */
    @FunctionalInterface
    public interface SecurityEventBatchProcessor {
        void processBatch(List<SecurityEvent> events);
    }

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
    private final ScheduledExecutorService scheduler;
    private volatile boolean running;
    private final AtomicLong eventCounter;
    private final AtomicLong incidentCounter;

    // AI Native v5.0.0: 콜백 기반 배치 처리
    private volatile SecurityEventBatchProcessor batchProcessor;

    public SecurityMonitoringService(
            KafkaSecurityEventCollector kafkaCollector,
            RedisSecurityEventCollector redisCollector,
            SecurityIncidentRepository securityIncidentRepository,
            ThreatIndicatorRepository indicatorRepository,
            List<ThreatEvaluationStrategy> evaluationStrategies,
            EventNormalizer eventNormalizer,
            EventDeduplicator eventDeduplicator,
            SecurityEventEnricher eventEnricher,
            @Value("${security.plane.monitor.worker-threads:5}") int workerThreads,
            @Value("${security.plane.monitor.correlation-window-minutes:10}") int correlationWindowMinutes,
            @Value("${security.plane.monitor.threat-threshold:0.7}") double threatThreshold,
            @Value("${security.plane.monitor.auto-incident-creation:true}") boolean autoIncidentCreation) {
        this.kafkaCollector = kafkaCollector;
        this.redisCollector = redisCollector;
        this.securityIncidentRepository = securityIncidentRepository;
        this.evaluationStrategies = evaluationStrategies;
        this.eventNormalizer = eventNormalizer;
        this.eventDeduplicator = eventDeduplicator;
        this.eventEnricher = eventEnricher;
        this.eventListeners = new CopyOnWriteArrayList<>();
        this.activeSessions = new ConcurrentHashMap<>();
        this.activeIncidents = new ConcurrentHashMap<>();
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.running = true;
        this.eventCounter = new AtomicLong(0);
        this.incidentCounter = new AtomicLong(0);
    }

    /**
     * 배치 프로세서 설정 (SecurityPlaneAgent가 호출)
     * @param processor 배치 이벤트를 처리할 콜백
     */
    public void setBatchProcessor(SecurityEventBatchProcessor processor) {
        this.batchProcessor = processor;
        logger.info("[SecurityMonitoringService] Batch processor registered");
    }

    @PostConstruct
    public void initialize() {
        logger.info("Initializing Security Monitoring Service (AI Native v5.0.0)");

        // AI Native v5.0.0: DirectBatchListener 등록 (Kafka Batch 이벤트 직접 수신)
        kafkaCollector.registerListener(new DirectBatchListener());
        logger.info("DirectBatchListener registered - using Kafka batch mode for event processing");

        loadActiveIncidents();
    }

    @PreDestroy
    public void shutdown() {
        logger.info("Shutting down Security Monitoring Service");
        running = false;

        scheduler.shutdown();

        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
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
     * 이벤트 전처리 (정규화, 중복 제거, 보강)
     * @param event 원시 이벤트
     * @return 전처리된 이벤트 (필터링된 경우 null)
     */
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
        stats.put("event_listeners", eventListeners.size());
        stats.put("evaluation_strategies", evaluationStrategies.size());
        stats.put("batch_processor_registered", batchProcessor != null);

        // Add collector statistics
        stats.put("kafka_stats", kafkaCollector.getStatistics());
        stats.put("redis_stats", redisCollector.getStatistics());

        return stats;
    }

    private void loadActiveIncidents() {
        List<SecurityIncident> incidents = securityIncidentRepository.findActiveIncidents();
        for (SecurityIncident incident : incidents) {
            activeIncidents.put(incident.getIncidentId(), incident);
        }
        logger.info("Loaded {} active incidents", activeIncidents.size());
    }

    /**
     * AI Native v5.0.0: Kafka 배치 이벤트를 직접 수신하여 Agent로 전달
     * - BlockingQueue 제거 -> 콜백 기반 직접 전달
     * - 전처리 (정규화, 중복 제거, 보강) 후 배치 프로세서 호출
     */
    private class DirectBatchListener implements BatchSecurityEventListener {

        @Override
        public void onBatchEvents(List<SecurityEvent> events) {
            if (events == null || events.isEmpty()) {
                return;
            }

            logger.debug("[DirectBatchListener] Received batch of {} events", events.size());

            // 전처리 후 유효한 이벤트만 필터링
            List<SecurityEvent> processedList = events.stream()
                    .map(DirectBatchListener.this::preprocessEventSafe)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            if (processedList.isEmpty()) {
                logger.debug("[DirectBatchListener] All events filtered during preprocessing");
                return;
            }

            // 배치 프로세서(SecurityPlaneAgent)로 직접 전달
            if (batchProcessor != null) {
                try {
                    batchProcessor.processBatch(processedList);
                    logger.debug("[DirectBatchListener] Batch of {} events forwarded to processor",
                            processedList.size());
                } catch (Exception e) {
                    logger.error("[DirectBatchListener] Failed to process batch", e);
                    throw new RuntimeException("Batch processing failed", e);
                }
            } else {
                logger.warn("[DirectBatchListener] No batch processor registered, {} events dropped",
                        processedList.size());
            }
        }

        @Override
        public void onSecurityEvent(SecurityEvent event) {
            // 단일 이벤트는 배치로 래핑하여 처리
            onBatchEvents(List.of(event));
        }

        @Override
        public String getListenerName() {
            return "DirectBatchListener";
        }

        /**
         * 이벤트 전처리 (예외 안전)
         */
        private SecurityEvent preprocessEventSafe(SecurityEvent event) {
            try {
                return preprocessEvent(event);
            } catch (Exception e) {
                logger.error("[DirectBatchListener] Error preprocessing event: {}",
                        event.getEventId(), e);
                return null;
            }
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