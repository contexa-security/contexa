package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
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


public class SecurityMonitoringService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityMonitoringService.class);

    
    @FunctionalInterface
    public interface SecurityEventBatchProcessor {
        void processBatch(List<SecurityEvent> events);
    }

    private final KafkaSecurityEventCollector kafkaCollector;
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

    
    private volatile SecurityEventBatchProcessor batchProcessor;

    public SecurityMonitoringService(
            KafkaSecurityEventCollector kafkaCollector,
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

    
    public void setBatchProcessor(SecurityEventBatchProcessor processor) {
        this.batchProcessor = processor;
        logger.info("[SecurityMonitoringService] Batch processor registered");
    }

    @PostConstruct
    public void initialize() {
        logger.info("Initializing Security Monitoring Service (AI Native v5.0.0)");

        
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

    
    public void startMonitoring(String sessionId, Map<String, Object> config) {
        logger.info("Starting monitoring session {}", sessionId);

        
        if (activeSessions.containsKey(sessionId)) {
            logger.warn("Monitoring session already exists for: {}", sessionId);
            return;
        }

        MonitoringSession session = new MonitoringSession(sessionId, config);
        activeSessions.put(sessionId, session);

        logger.info("Monitoring session {} started for agent {}", sessionId, config.get("agentId"));
    }

    
    public void stopMonitoring(String sessionId) {
        logger.info("Stopping monitoring session {}", sessionId);

        MonitoringSession session = activeSessions.remove(sessionId);
        if (session != null) {
            session.stop();

            
            if (activeSessions.isEmpty()) {
                logger.info("All monitoring sessions stopped");
            }

            logger.info("Monitoring session {} stopped", sessionId);
        } else {
            logger.warn("No active monitoring session found for: {}", sessionId);
        }
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

        
        stats.put("kafka_stats", kafkaCollector.getStatistics());

        return stats;
    }

    private void loadActiveIncidents() {
        List<SecurityIncident> incidents = securityIncidentRepository.findActiveIncidents();
        for (SecurityIncident incident : incidents) {
            activeIncidents.put(incident.getIncidentId(), incident);
        }
        logger.info("Loaded {} active incidents", activeIncidents.size());
    }

    
    private class DirectBatchListener implements BatchSecurityEventListener {

        @Override
        public void onBatchEvents(List<SecurityEvent> events) {
            if (events == null || events.isEmpty()) {
                return;
            }

            logger.debug("[DirectBatchListener] Received batch of {} events", events.size());

            
            List<SecurityEvent> processedList = events.stream()
                    .map(DirectBatchListener.this::preprocessEventSafe)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

            if (processedList.isEmpty()) {
                logger.debug("[DirectBatchListener] All events filtered during preprocessing");
                return;
            }

            
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
            
            onBatchEvents(List.of(event));
        }

        @Override
        public String getListenerName() {
            return "DirectBatchListener";
        }

        
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