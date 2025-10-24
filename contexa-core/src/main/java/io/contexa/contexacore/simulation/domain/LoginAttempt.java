package io.contexa.contexacore.simulation.domain;

import lombok.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * 로그인 시도 도메인 모델
 * 
 * 인증 시도에 대한 모든 정보를 포함합니다.
 * 성공/실패 여부, 시도 위치, 시간, 장치 정보 등을 추적합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {
    
    // 기본 정보
    private String attemptId;
    private String username;
    private String password; // 실제로는 해시값만 저장
    private LocalDateTime timestamp;
    private boolean successful;
    
    // 위치 정보
    private String sourceIp;
    private String country;
    private String city;
    private Double latitude;
    private Double longitude;
    
    // 장치 정보
    private String deviceFingerprint;
    private String userAgent;
    private String browserName;
    private String osName;
    private String deviceType; // mobile, desktop, tablet
    
    // 세션 정보
    private String sessionId;
    private String previousSessionId;
    private Long sessionDuration;

    // 응답 정보
    private Long responseTimeMs;
    private Integer responseCode;
    private boolean blocked;
    
    // 실패 정보
    private String failureReason;
    private Integer failureCount;
    private Long timeSinceLastAttempt;
    
    // 행동 분석
    private Double typingSpeed; // 키스트로크 다이나믹스
    private Double mouseMovementPattern;
    private Integer passwordLength;
    private Boolean pastedPassword;
    
    // MFA 정보
    private Boolean mfaRequired;
    private String mfaMethod; // sms, totp, push, email
    private Boolean mfaSuccessful;
    private Integer mfaAttempts;
    
    // 위험 평가
    private Double riskScore;
    private String riskLevel; // LOW, MEDIUM, HIGH, CRITICAL
    private String threatCategory; // bruteforce, credential_stuffing, account_takeover
    
    // 컨텍스트 데이터
    @Builder.Default
    private Map<String, Object> contextData = new HashMap<>();
    
    // 메타데이터
    private String attackId; // 관련 공격 ID
    private String campaignId; // 캠페인 ID
    private Boolean isAnomaly;
    private String anomalyType;
    
    /**
     * 로그인 성공 여부 확인
     */
    public boolean isSuccess() {
        return successful;
    }

    /**
     * 로그인 성공 여부 설정
     */
    public void setSuccess(boolean success) {
        this.successful = success;
    }

    /**
     * 로그인 시도가 의심스러운지 판단
     */
    public boolean isSuspicious() {
        return !successful && failureCount > 3 ||
               riskScore != null && riskScore > 0.7 ||
               "HIGH".equals(riskLevel) || "CRITICAL".equals(riskLevel) ||
               isAnomaly != null && isAnomaly;
    }
    
    /**
     * 브루트포스 공격 패턴인지 확인
     */
    public boolean isBruteForcePattern() {
        return failureCount != null && failureCount > 5 &&
               timeSinceLastAttempt != null && timeSinceLastAttempt < 1000 && // 1초 이내
               "bruteforce".equals(threatCategory);
    }
    
    /**
     * 크리덴셜 스터핑 패턴인지 확인
     */
    public boolean isCredentialStuffingPattern() {
        return "credential_stuffing".equals(threatCategory) &&
               contextData.containsKey("leaked_database_match");
    }
    
    /**
     * 불가능한 이동 패턴인지 확인
     */
    public boolean isImpossibleTravel() {
        if (contextData.containsKey("previous_location")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> prevLoc = (Map<String, Object>) contextData.get("previous_location");
            Double prevLat = (Double) prevLoc.get("latitude");
            Double prevLon = (Double) prevLoc.get("longitude");
            Long timeDiff = (Long) contextData.get("time_difference_ms");
            
            if (prevLat != null && prevLon != null && latitude != null && longitude != null && timeDiff != null) {
                double distance = calculateDistance(prevLat, prevLon, latitude, longitude);
                double speed = distance / (timeDiff / 3600000.0); // km/h
                return speed > 900; // 비행기 속도보다 빠름
            }
        }
        return false;
    }
    
    /**
     * 두 지점 간 거리 계산 (Haversine formula)
     */
    private double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // 지구 반경(km)
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
    
    /**
     * 장치 변경 감지
     */
    public boolean isDeviceChanged() {
        return contextData.containsKey("known_device") && 
               !(Boolean) contextData.get("known_device");
    }
    
    /**
     * 비정상 시간대 접속
     */
    public boolean isAbnormalTime() {
        if (timestamp != null && contextData.containsKey("normal_hours")) {
            int hour = timestamp.getHour();
            String normalHours = (String) contextData.get("normal_hours");
            // 예: "09-18" (오전 9시 - 오후 6시)
            if (normalHours != null && normalHours.contains("-")) {
                String[] parts = normalHours.split("-");
                int startHour = Integer.parseInt(parts[0]);
                int endHour = Integer.parseInt(parts[1]);
                return hour < startHour || hour > endHour;
            }
        }
        return false;
    }
}