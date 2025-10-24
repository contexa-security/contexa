package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.repository.BehaviorRealtimeCacheRepository;
import io.contexa.contexacommon.entity.behavior.BehaviorRealtimeCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 실시간 사용자 행동 모니터링 서비스
 */
@Slf4j
@Service
public class RealTimeBehaviorMonitor {

    private final BehaviorRealtimeCacheRepository realtimeCacheRepository;
    private final SimpMessagingTemplate brokerTemplate;
    private final Set<String> monitoringUsers = ConcurrentHashMap.newKeySet();

    // 실시간 이벤트 스트림
    private final Sinks.Many<Map<String, Object>> behaviorEventSink =
            Sinks.many().multicast().onBackpressureBuffer();

    public RealTimeBehaviorMonitor(BehaviorRealtimeCacheRepository realtimeCacheRepository,
                                   @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.realtimeCacheRepository = realtimeCacheRepository;
        this.brokerTemplate = brokerTemplate;
    }

    /**
     * 특정 사용자 모니터링 시작
     */
    public void startMonitoring(String userId) {
        monitoringUsers.add(userId);
        log.info("사용자 모니터링 시작: {}", userId);

        // 초기 캐시 생성
        BehaviorRealtimeCache cache = realtimeCacheRepository.findById(userId)
                .orElseGet(() -> createInitialCache(userId));

        cache.setLastActivityTimestamp(LocalDateTime.now());
        realtimeCacheRepository.save(cache);
    }

    /**
     * 특정 사용자 모니터링 중지
     */
    public void stopMonitoring(String userId) {
        monitoringUsers.remove(userId);
        log.info("사용자 모니터링 중지: {}", userId);
    }

    /**
     * 전체 사용자 행동 스트림
     */
    public Flux<String> streamAllUserBehaviors() {
        return behaviorEventSink.asFlux()
                .map(this::convertEventToJson)
                .onErrorContinue((error, obj) ->
                        log.error("스트리밍 오류: {}", error.getMessage()));
    }

    /**
     * 행동 이벤트 발생
     */
    public void publishBehaviorEvent(String userId, String activity, String ip, double riskScore) {
        Map<String, Object> event = new HashMap<>();
        event.put("userId", userId);
        event.put("activity", activity);
        event.put("remoteIp", ip);
        event.put("riskScore", riskScore);
        event.put("timestamp", LocalDateTime.now().toString());
        event.put("riskLevel", determineRiskLevel(riskScore));

        // 실시간 캐시 업데이트
        updateRealtimeCache(userId, activity, ip, riskScore);

        // 이벤트 발행
        behaviorEventSink.tryEmitNext(event);

        // WebSocket 으로도 전송 (옵션)
        brokerTemplate.convertAndSend("/topic/behavior-events", event);

        // 모니터링 중인 사용자면 상세 정보 전송
        if (monitoringUsers.contains(userId)) {
            Map<String, Object> detailedEvent = new HashMap<>(event);
            detailedEvent.put("anomalies", detectRealTimeAnomalies(userId, activity, ip));
            brokerTemplate.convertAndSend("/topic/user/" + userId, detailedEvent);
        }
    }

    /**
     * 실시간 캐시 업데이트
     */
    private void updateRealtimeCache(String userId, String activity, String ip, double riskScore) {
        BehaviorRealtimeCache cache = realtimeCacheRepository.findById(userId)
                .orElseGet(() -> createInitialCache(userId));

        // 최근 활동 업데이트
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

        // 최대 10개만 유지
        if (recentActivities.size() > 10) {
            recentActivities = recentActivities.subList(0, 10);
        }

        cache.setRecentActivities(convertToJson(recentActivities));
        cache.setLastActivityTimestamp(LocalDateTime.now());
        cache.setCurrentRiskScore((float) riskScore);

        // 위험 요인 업데이트
        if (riskScore > 50) {
            List<String> riskFactors = new ArrayList<>();
            if (riskScore > 70) riskFactors.add("HIGH_RISK_SCORE");
            if (!ip.equals(cache.getSessionIp())) riskFactors.add("IP_CHANGE");
            cache.setRiskFactors(convertToJson(riskFactors));
        }

        // TTL 설정 (1시간)
        cache.setExpiresAt(LocalDateTime.now().plusHours(1));

        realtimeCacheRepository.save(cache);
    }

    /**
     * 실시간 이상 징후 감지
     */
    private List<String> detectRealTimeAnomalies(String userId, String activity, String ip) {
        List<String> anomalies = new ArrayList<>();

        BehaviorRealtimeCache cache = realtimeCacheRepository.findById(userId).orElse(null);
        if (cache == null) return anomalies;

        // IP 변경 감지
        if (cache.getSessionIp() != null && !cache.getSessionIp().equals(ip)) {
            anomalies.add("IP 주소 변경 감지");
        }

        // 짧은 시간 내 과도한 활동
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

        // 위험한 활동 패턴
        if (activity.toLowerCase().contains("delete") || activity.toLowerCase().contains("admin")) {
            anomalies.add("민감한 작업 수행");
        }

        return anomalies;
    }

    /**
     * 초기 캐시 생성
     */
    private BehaviorRealtimeCache createInitialCache(String userId) {
        BehaviorRealtimeCache cache = new BehaviorRealtimeCache();
        cache.setUserId(userId);
        cache.setRecentActivities("[]");
        cache.setCurrentRiskScore(0.0f);
        cache.setRiskFactors("[]");
        cache.setExpiresAt(LocalDateTime.now().plusHours(1));
        return cache;
    }

    /**
     * 위험 수준 결정
     */
    private String determineRiskLevel(double riskScore) {
        if (riskScore >= 80) return "CRITICAL";
        else if (riskScore >= 60) return "HIGH";
        else if (riskScore >= 40) return "MEDIUM";
        else return "LOW";
    }

    /**
     * 이벤트를 JSON 문자열로 변환
     */
    private String convertEventToJson(Map<String, Object> event) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .writeValueAsString(event);
        } catch (Exception e) {
            log.error("JSON 변환 오류", e);
            return "{}";
        }
    }

    /**
     * 객체를 JSON 문자열로 변환
     */
    private String convertToJson(Object obj) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .writeValueAsString(obj);
        } catch (Exception e) {
            log.error("JSON 변환 오류", e);
            return "[]";
        }
    }

    /**
     * 만료된 캐시 정리 (매시간 실행)
     */
//    @Scheduled(fixedDelay = 3600000) // 1시간마다
    public void cleanupExpiredCache() {
        log.info("만료된 실시간 캐시 정리 시작");
        int deleted = realtimeCacheRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        log.info("만료된 캐시 {}개 삭제됨", deleted);
    }

    /**
     * 현재 모니터링 중인 사용자 목록
     */
    public Set<String> getMonitoringUsers() {
        return new HashSet<>(monitoringUsers);
    }

    /**
     * 사용자의 현재 위험도 조회
     */
    public float getCurrentRiskScore(String userId) {
        return realtimeCacheRepository.findById(userId)
                .map(BehaviorRealtimeCache::getCurrentRiskScore)
                .orElse(0.0f);
    }

    /**
     * 전체 사용자의 평균 위험도
     */
    public double getAverageRiskScore() {
        List<BehaviorRealtimeCache> allCaches = realtimeCacheRepository.findAll();
        if (allCaches.isEmpty()) return 0.0;

        return allCaches.stream()
                .mapToDouble(BehaviorRealtimeCache::getCurrentRiskScore)
                .average()
                .orElse(0.0);
    }

    /**
     * 고위험 사용자 목록 (위험도 70 이상)
     */
    public List<String> getHighRiskUsers() {
        return realtimeCacheRepository.findByCurrentRiskScoreGreaterThan(70.0f)
                .stream()
                .map(BehaviorRealtimeCache::getUserId)
                .collect(Collectors.toList());
    }
}
