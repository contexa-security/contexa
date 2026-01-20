package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.repository.BehaviorRealtimeCacheRepository;
import io.contexa.contexacommon.entity.behavior.BehaviorRealtimeCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
public class RealTimeBehaviorMonitor {

    private final BehaviorRealtimeCacheRepository realtimeCacheRepository;
    private final SimpMessagingTemplate brokerTemplate;
    private final Set<String> monitoringUsers = ConcurrentHashMap.newKeySet();

    
    private final Sinks.Many<Map<String, Object>> behaviorEventSink =
            Sinks.many().multicast().onBackpressureBuffer();

    public RealTimeBehaviorMonitor(BehaviorRealtimeCacheRepository realtimeCacheRepository,
                                   @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.realtimeCacheRepository = realtimeCacheRepository;
        this.brokerTemplate = brokerTemplate;
    }

    
    public void startMonitoring(String userId) {
        monitoringUsers.add(userId);
        log.info("사용자 모니터링 시작: {}", userId);

        
        BehaviorRealtimeCache cache = realtimeCacheRepository.findById(userId)
                .orElseGet(() -> createInitialCache(userId));

        cache.setLastActivityTimestamp(LocalDateTime.now());
        realtimeCacheRepository.save(cache);
    }

    
    public void stopMonitoring(String userId) {
        monitoringUsers.remove(userId);
        log.info("사용자 모니터링 중지: {}", userId);
    }

    
    public Flux<String> streamAllUserBehaviors() {
        return behaviorEventSink.asFlux()
                .map(this::convertEventToJson)
                .onErrorContinue((error, obj) ->
                        log.error("스트리밍 오류: {}", error.getMessage()));
    }

    
    public void publishBehaviorEvent(String userId, String activity, String ip, double riskScore) {
        Map<String, Object> event = new HashMap<>();
        event.put("userId", userId);
        event.put("activity", activity);
        event.put("remoteIp", ip);
        event.put("riskScore", riskScore);
        event.put("timestamp", LocalDateTime.now().toString());
        event.put("riskLevel", determineRiskLevel(riskScore));

        
        updateRealtimeCache(userId, activity, ip, riskScore);

        
        behaviorEventSink.tryEmitNext(event);

        
        brokerTemplate.convertAndSend("/topic/behavior-events", event);

        
        if (monitoringUsers.contains(userId)) {
            Map<String, Object> detailedEvent = new HashMap<>(event);
            detailedEvent.put("anomalies", detectRealTimeAnomalies(userId, activity, ip));
            brokerTemplate.convertAndSend("/topic/user/" + userId, detailedEvent);
        }
    }

    
    private void updateRealtimeCache(String userId, String activity, String ip, double riskScore) {
        BehaviorRealtimeCache cache = realtimeCacheRepository.findById(userId)
                .orElseGet(() -> createInitialCache(userId));

        
        List<Map<String, Object>> recentActivities = cache.getRecentActivitiesList();
        if (recentActivities == null) {
            recentActivities = new ArrayList<>();
        }

        Map<String, Object> newActivity = new HashMap<>();
        newActivity.put("timestamp", LocalDateTime.now().toString());
        newActivity.put("activity", activity);
        newActivity.put("ip", ip);
        newActivity.put("riskScore", riskScore);

        recentActivities.add(0, newActivity);

        
        if (recentActivities.size() > 10) {
            recentActivities = recentActivities.subList(0, 10);
        }

        cache.setRecentActivities(convertToJson(recentActivities));
        cache.setLastActivityTimestamp(LocalDateTime.now());
        cache.setCurrentRiskScore((float) riskScore);

        
        if (riskScore > 50) {
            List<String> riskFactors = new ArrayList<>();
            if (riskScore > 70) riskFactors.add("HIGH_RISK_SCORE");
            if (!ip.equals(cache.getSessionIp())) riskFactors.add("IP_CHANGE");
            cache.setRiskFactors(convertToJson(riskFactors));
        }

        
        cache.setExpiresAt(LocalDateTime.now().plusHours(1));

        realtimeCacheRepository.save(cache);
    }

    
    private List<String> detectRealTimeAnomalies(String userId, String activity, String ip) {
        List<String> anomalies = new ArrayList<>();

        BehaviorRealtimeCache cache = realtimeCacheRepository.findById(userId).orElse(null);
        if (cache == null) return anomalies;

        
        if (cache.getSessionIp() != null && !cache.getSessionIp().equals(ip)) {
            anomalies.add("IP 주소 변경 감지");
        }

        
        if (cache.getRecentActivitiesList() != null && cache.getRecentActivitiesList().size() >= 5) {
            LocalDateTime fiveMinutesAgo = LocalDateTime.now().minusMinutes(5);
            long recentCount = cache.getRecentActivitiesList().stream()
                    .filter(act -> {
                        String timestamp = (String) ((Map<?, ?>) act).get("timestamp");
                        return LocalDateTime.parse(timestamp).isAfter(fiveMinutesAgo);
                    })
                    .count();

            if (recentCount >= 10) {
                anomalies.add("비정상적으로 빠른 활동 속도");
            }
        }

        
        if (activity.toLowerCase().contains("delete") || activity.toLowerCase().contains("admin")) {
            anomalies.add("민감한 작업 수행");
        }

        return anomalies;
    }

    
    private BehaviorRealtimeCache createInitialCache(String userId) {
        BehaviorRealtimeCache cache = new BehaviorRealtimeCache();
        cache.setUserId(userId);
        cache.setRecentActivities("[]");
        cache.setCurrentRiskScore(0.0f);
        cache.setRiskFactors("[]");
        cache.setExpiresAt(LocalDateTime.now().plusHours(1));
        return cache;
    }

    
    private String determineRiskLevel(double riskScore) {
        if (riskScore >= 80) return "CRITICAL";
        else if (riskScore >= 60) return "HIGH";
        else if (riskScore >= 40) return "MEDIUM";
        else return "LOW";
    }

    
    private String convertEventToJson(Map<String, Object> event) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .writeValueAsString(event);
        } catch (Exception e) {
            log.error("JSON 변환 오류", e);
            return "{}";
        }
    }

    
    private String convertToJson(Object obj) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .writeValueAsString(obj);
        } catch (Exception e) {
            log.error("JSON 변환 오류", e);
            return "[]";
        }
    }

    

    public void cleanupExpiredCache() {
        log.info("만료된 실시간 캐시 정리 시작");
        int deleted = realtimeCacheRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        log.info("만료된 캐시 {}개 삭제됨", deleted);
    }

    
    public Set<String> getMonitoringUsers() {
        return new HashSet<>(monitoringUsers);
    }

    
    public float getCurrentRiskScore(String userId) {
        return realtimeCacheRepository.findById(userId)
                .map(BehaviorRealtimeCache::getCurrentRiskScore)
                .orElse(0.0f);
    }

    
    public double getAverageRiskScore() {
        List<BehaviorRealtimeCache> allCaches = realtimeCacheRepository.findAll();
        if (allCaches.isEmpty()) return 0.0;

        return allCaches.stream()
                .mapToDouble(BehaviorRealtimeCache::getCurrentRiskScore)
                .average()
                .orElse(0.0);
    }

    
    public List<String> getHighRiskUsers() {
        return realtimeCacheRepository.findByCurrentRiskScoreGreaterThan(70.0f)
                .stream()
                .map(BehaviorRealtimeCache::getUserId)
                .collect(Collectors.toList());
    }
}
