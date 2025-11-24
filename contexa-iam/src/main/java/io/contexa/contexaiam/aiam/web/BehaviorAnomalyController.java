package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 행동 이상 탐지 API 컨트롤러
 *
 * 공격 시뮬레이션의 행동 이상 패턴을 수신하고
 * 즉시 보안 이벤트를 발행하여 자율보안체제가 실시간 탐지할 수 있도록 합니다.
 */
@Slf4j
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class BehaviorAnomalyController {

    private final KafkaSecurityEventPublisher eventPublisher;
    private final SoarIncidentRepository incidentRepository;
    private final AttackEventHelper attackEventHelper;

    /**
     * 행동 이상 탐지 API
     * 각 이상 행동마다 즉시 이벤트 발행
     */
    @PostMapping("/behavior/anomaly")
    public ResponseEntity<?> detectBehaviorAnomaly(@RequestBody Map<String, Object> request) {
        String username = (String) request.get("user");
        String action = (String) request.get("action");
        String description = (String) request.get("description");

        log.warn("행동 이상 탐지: user={}, action={}, description={}",
            username, action, description);

        // 즉시 보안 이벤트 발행 - 자율보안체제가 실시간 탐지
        AttackResult attackEvent = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.BEHAVIORAL_ANOMALY)
            .username(username)
            .targetResource("behavior:" + action)
            .timestamp(LocalDateTime.now())
            .successful(false) // 아직 성공 여부 미정
            .detected(false) // 탐지 여부는 보안 시스템이 결정
            .riskScore(calculateRiskScore(action))
            .details(request)
            .build();

        // ThreatDetectionEvent 생성 및 발행
        ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
            .threatId(attackEvent.getAttackId())
            .threatType("BEHAVIORAL_ANOMALY")
            .threatLevel(mapRiskScoreToThreatLevel(attackEvent.getRiskScore()))
            .detectionSource("behavior:" + action)
            .confidenceScore(attackEvent.getRiskScore())
            .affectedResources(new String[]{"behavior:" + action})
            .recommendedActions(new String[]{"Monitor user activity", "Review access patterns"})
            .metadata(request)
            .build();

        eventPublisher.publishThreatDetection(threatEvent);

        // SOAR 인시던트 생성 (위험도가 높은 경우)
        if (attackEvent.getRiskScore() > 0.7) {
            createSoarIncident(username, action, description);
        }

        // 응답 - 실제로는 보안 시스템의 결정을 기다려야 함
        Map<String, Object> response = new HashMap<>();
        response.put("status", "RECEIVED");
        response.put("eventId", attackEvent.getAttackId());
        response.put("riskScore", attackEvent.getRiskScore());
        response.put("timestamp", LocalDateTime.now());

        return ResponseEntity.ok(response);
    }

    /**
     * 사용자 프로필 접근 API
     */
    @GetMapping("/user/profile")
    public ResponseEntity<?> getUserProfile(@RequestHeader Map<String, String> headers) {
        String authToken = headers.get("authorization");
        log.info("프로필 접근 시도: token={}", authToken != null ? "present" : "missing");

        // 프로필 접근 이벤트 발행
        if (authToken != null) {
            String username = extractUsernameFromToken(authToken);
            publishAccessEvent(username, "/user/profile", "PROFILE_ACCESS");
        }

        Map<String, Object> profile = new HashMap<>();
        profile.put("id", "user-" + UUID.randomUUID().toString().substring(0, 8));
        profile.put("username", "testuser");
        profile.put("email", "test@example.com");
        profile.put("lastLogin", LocalDateTime.now().minusDays(1));

        return ResponseEntity.ok(profile);
    }

    /**
     * 금융 데이터 접근 API
     */
    @GetMapping("/user/financial")
    public ResponseEntity<?> getFinancialData(@RequestHeader Map<String, String> headers) {
        String authToken = headers.get("authorization");
        log.warn("민감 데이터(금융) 접근 시도!");

        if (authToken != null) {
            String username = extractUsernameFromToken(authToken);

            // 민감 데이터 접근은 높은 위험도 이벤트
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.DATA_EXFILTRATION)
                .username(username)
                .targetResource("/user/financial")
                .timestamp(LocalDateTime.now())
                .riskScore(0.9) // 높은 위험도
                .build();

            ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
                .threatId(event.getAttackId())
                .threatType("DATA_EXFILTRATION")
                .threatLevel(ThreatDetectionEvent.ThreatLevel.HIGH)
                .detectionSource("/user/financial")
                .confidenceScore(0.9)
                .affectedResources(new String[]{"/user/financial"})
                .recommendedActions(new String[]{"Block access", "Alert security team"})
                .build();

            eventPublisher.publishThreatDetection(threatEvent);

            // 즉시 SOAR 인시던트 생성
            createSoarIncident(username, "FINANCIAL_ACCESS", "민감 금융 데이터 접근 시도");
        }

        return ResponseEntity.status(403).body(Map.of(
            "error", "Access Denied",
            "message", "Financial data access requires additional verification"
        ));
    }

    /**
     * 다른 사용자 프로필 접근 (IDOR 시도)
     */
    @GetMapping("/user/{userId}/profile")
    public ResponseEntity<?> getOtherUserProfile(
            @PathVariable String userId,
            @RequestHeader Map<String, String> headers) {

        String authToken = headers.get("authorization");
        log.error("IDOR 공격 시도 탐지! targetUserId={}", userId);

        if (authToken != null) {
            String username = extractUsernameFromToken(authToken);

            // IDOR는 매우 높은 위험도
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.IDOR)
                .username(username)
                .targetResource("/user/" + userId + "/profile")
                .timestamp(LocalDateTime.now())
                .successful(false)
                .detected(true) // 즉시 탐지
                .blocked(true) // 즉시 차단
                .riskScore(0.95)
                .build();

            ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
                .threatId(event.getAttackId())
                .threatType("IDOR")
                .threatLevel(ThreatDetectionEvent.ThreatLevel.CRITICAL)
                .detectionSource("/user/" + userId + "/profile")
                .confidenceScore(0.95)
                .affectedResources(new String[]{"/user/" + userId + "/profile"})
                .recommendedActions(new String[]{"Block immediately", "Ban user", "Security investigation"})
                .metadata(Map.of("targetUserId", userId, "attackingUser", username))
                .build();

            eventPublisher.publishThreatDetection(threatEvent);

            // 즉시 인시던트 생성
            createSoarIncident(username, "IDOR_ATTACK", "IDOR 공격 시도 - 타 사용자 정보 접근");
        }

        return ResponseEntity.status(403).body(Map.of(
            "error", "Forbidden",
            "message", "Access denied - security violation logged"
        ));
    }

    /**
     * 대량 데이터 다운로드 시도
     */
    @PostMapping("/data/export")
    public ResponseEntity<?> exportBulkData(@RequestBody Map<String, Object> request) {
        String username = (String) request.get("username");
        Integer recordCount = (Integer) request.get("recordCount");
        String dataType = (String) request.get("dataType");

        log.warn("대량 데이터 익스포트 시도: user={}, records={}, type={}",
            username, recordCount, dataType);

        // 대량 다운로드는 데이터 유출 위험
        if (recordCount != null && recordCount > 1000) {
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.DATA_EXFILTRATION)
                .username(username)
                .targetResource("/data/export")
                .timestamp(LocalDateTime.now())
                .riskScore(Math.min(1.0, 0.5 + (recordCount / 10000.0)))
                .details(Map.of(
                    "recordCount", recordCount,
                    "dataType", dataType
                ))
                .build();

            ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
                .threatId(event.getAttackId())
                .threatType("DATA_EXFILTRATION")
                .threatLevel(mapRiskScoreToThreatLevel(event.getRiskScore()))
                .detectionSource("/data/export")
                .confidenceScore(event.getRiskScore())
                .affectedResources(new String[]{"/data/export"})
                .recommendedActions(new String[]{"Monitor export", "Rate limit", "Review permissions"})
                .metadata(Map.of("recordCount", recordCount, "dataType", dataType))
                .build();

            eventPublisher.publishThreatDetection(threatEvent);

            if (recordCount > 5000) {
                createSoarIncident(username, "DATA_EXFILTRATION",
                    "대량 데이터 유출 시도: " + recordCount + "건");
            }
        }

        return ResponseEntity.ok(Map.of(
            "status", "PROCESSING",
            "message", "Export request received and logged"
        ));
    }

    // Helper methods

    private double calculateRiskScore(String action) {
        if (action == null) return 0.5;

        // 행동별 위험도 평가
        return switch (action.toUpperCase()) {
            case "BULK_DOWNLOAD", "DATABASE_DUMP" -> 0.95;
            case "PRIVILEGE_CHANGE", "ADMIN_ACCESS" -> 0.9;
            case "LATERAL_MOVEMENT", "NETWORK_SCAN" -> 0.85;
            case "UNUSUAL_TIME_ACCESS" -> 0.7;
            case "GRADUAL_DOWNLOAD" -> 0.6;
            default -> 0.5;
        };
    }

    private void createSoarIncident(String username, String action, String description) {
        try {
            SoarIncident incident = new SoarIncident();
            incident.setTitle("행동 이상 탐지: " + action);
            incident.setStatus(SoarIncidentStatus.NEW);
            incident.addHistoryLog(String.format(
                "사용자 %s의 이상 행동 탐지: %s - %s",
                username, action, description
            ));

            incidentRepository.save(incident);
            log.info("SOAR 인시던트 생성: {}", incident.getId());
        } catch (Exception e) {
            log.error("SOAR 인시던트 생성 실패", e);
        }
    }

    private void publishAccessEvent(String username, String resource, String action) {
        AttackResult event = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.UNKNOWN)
            .username(username)
            .targetResource(resource)
            .timestamp(LocalDateTime.now())
            .riskScore(0.3) // 일반 접근은 낮은 위험도
            .build();

        // 일반 접근은 LOW 레벨 이벤트로 발행
        ThreatDetectionEvent threatEvent = ThreatDetectionEvent.builder()
            .threatId(event.getAttackId())
            .threatType("ACCESS_MONITORING")
            .threatLevel(ThreatDetectionEvent.ThreatLevel.LOW)
            .detectionSource(resource)
            .confidenceScore(0.3)
            .affectedResources(new String[]{resource})
            .build();

        eventPublisher.publishThreatDetection(threatEvent);
    }

    private ThreatDetectionEvent.ThreatLevel mapRiskScoreToThreatLevel(double riskScore) {
        if (riskScore >= 0.9) return ThreatDetectionEvent.ThreatLevel.CRITICAL;
        if (riskScore >= 0.7) return ThreatDetectionEvent.ThreatLevel.HIGH;
        if (riskScore >= 0.5) return ThreatDetectionEvent.ThreatLevel.MEDIUM;
        if (riskScore >= 0.3) return ThreatDetectionEvent.ThreatLevel.LOW;
        return ThreatDetectionEvent.ThreatLevel.INFO;
    }

    private String extractUsernameFromToken(String authToken) {
        // 실제로는 JWT 파싱 필요
        if (authToken != null && authToken.startsWith("Bearer ")) {
            return "user-" + authToken.substring(7, Math.min(15, authToken.length()));
        }
        return "anonymous";
    }
}