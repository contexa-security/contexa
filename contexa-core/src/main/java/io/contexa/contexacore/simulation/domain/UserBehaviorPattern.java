package io.contexa.contexacore.simulation.domain;

import lombok.*;
import java.time.DayOfWeek;
import java.time.LocalTime;
import java.util.*;

/**
 * 사용자 행동 패턴 도메인 모델
 * 
 * 정상적인 사용자의 행동 패턴을 정의합니다.
 * AI가 이상 행동을 탐지하는 기준이 됩니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserBehaviorPattern {
    
    // 사용자 식별
    private String userId;
    private String username;
    private String role; // ADMIN, USER, DEVELOPER, MANAGER
    private String department;
    
    // 시간 패턴
    private LocalTime workStartTime;
    private LocalTime workEndTime;
    private Set<DayOfWeek> workingDays;
    private Set<String> holidays; // yyyy-MM-dd 형식
    private String timezone;
    
    // 위치 패턴
    @Builder.Default
    private List<LocationPattern> normalLocations = new ArrayList<>();
    @Builder.Default
    private Set<String> trustedNetworks = new HashSet<>(); // IP 대역
    @Builder.Default
    private Set<String> blockedCountries = new HashSet<>();
    
    // 장치 패턴
    @Builder.Default
    private Set<String> knownDevices = new HashSet<>(); // 장치 지문
    @Builder.Default
    private Set<String> trustedBrowsers = new HashSet<>();
    private Integer maxConcurrentDevices;
    
    // 접근 패턴
    @Builder.Default
    private List<String> frequentlyAccessedResources = new ArrayList<>();
    @Builder.Default
    private Map<String, Integer> resourceAccessFrequency = new HashMap<>();
    private Integer averageDailyRequests;
    private Integer peakHourRequests;
    
    // 인증 패턴
    private Integer averageLoginAttemptsBeforeSuccess;
    private Long averageSessionDuration; // 밀리초
    private String preferredMfaMethod;
    private Boolean usesPasswordManager;
    
    // 데이터 접근 패턴
    private Long averageDataVolumePerDay; // 바이트
    private Long maxDataVolumePerSession;
    @Builder.Default
    private Set<String> sensitiveDataCategories = new HashSet<>();
    
    // 행동 특성
    private Double averageTypingSpeed; // WPM
    private Double averageMouseSpeed;
    private String navigationPattern; // linear, random, focused
    private Integer averagePageViewsPerSession;
    
    // 위험 허용도
    private String riskTolerance; // LOW, MEDIUM, HIGH
    private Boolean requiresApprovalForHighRisk;
    private Integer maxFailedLoginsBeforeLock;
    
    // API 사용 패턴
    @Builder.Default
    private Map<String, ApiUsagePattern> apiUsagePatterns = new HashMap<>();
    
    // 협업 패턴
    @Builder.Default
    private Set<String> frequentCollaborators = new HashSet<>();
    @Builder.Default
    private Set<String> sharedResources = new HashSet<>();
    
    /**
     * 위치 패턴
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LocationPattern {
        private String locationName; // "Office", "Home", "Coffee Shop"
        private String country;
        private String city;
        private Double latitude;
        private Double longitude;
        private Integer radius; // 허용 반경(km)
        private Set<String> ipRanges;
        private Double usagePercentage; // 이 위치에서의 사용 비율
    }
    
    /**
     * API 사용 패턴
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ApiUsagePattern {
        private String apiEndpoint;
        private String httpMethod;
        private Integer averageCallsPerDay;
        private Integer maxCallsPerHour;
        private Long averageResponseSize;
        private Set<String> typicalParameters;
        private Boolean requiresApproval;
    }
    
    /**
     * 현재 활동이 정상 패턴인지 확인
     */
    public boolean isNormalActivity(LoginAttempt attempt) {
        // 시간 확인
        if (!isWithinWorkingHours(attempt.getTimestamp().toLocalTime())) {
            return false;
        }
        
        // 위치 확인
        if (!isFromTrustedLocation(attempt.getSourceIp(), attempt.getLatitude(), attempt.getLongitude())) {
            return false;
        }
        
        // 장치 확인
        if (!isKnownDevice(attempt.getDeviceFingerprint())) {
            return false;
        }
        
        return true;
    }
    
    /**
     * 근무 시간 내인지 확인
     */
    public boolean isWithinWorkingHours(LocalTime time) {
        if (workStartTime == null || workEndTime == null) {
            return true; // 제한 없음
        }
        
        return !time.isBefore(workStartTime) && !time.isAfter(workEndTime);
    }
    
    /**
     * 신뢰할 수 있는 위치인지 확인
     */
    public boolean isFromTrustedLocation(String ip, Double lat, Double lon) {
        // IP 대역 확인
        for (String trustedNetwork : trustedNetworks) {
            if (isIpInRange(ip, trustedNetwork)) {
                return true;
            }
        }
        
        // 위치 확인
        if (lat != null && lon != null) {
            for (LocationPattern location : normalLocations) {
                if (isWithinRadius(lat, lon, location)) {
                    return true;
                }
            }
        }
        
        return normalLocations.isEmpty() && trustedNetworks.isEmpty();
    }
    
    /**
     * 알려진 장치인지 확인
     */
    public boolean isKnownDevice(String deviceFingerprint) {
        if (knownDevices.isEmpty()) {
            return true; // 제한 없음
        }
        return knownDevices.contains(deviceFingerprint);
    }
    
    /**
     * IP가 특정 대역에 속하는지 확인
     */
    private boolean isIpInRange(String ip, String range) {
        // 간단한 구현 (실제로는 더 정교한 IP 범위 체크 필요)
        return ip != null && range != null && ip.startsWith(range.replace("*", ""));
    }
    
    /**
     * 특정 위치의 반경 내에 있는지 확인
     */
    private boolean isWithinRadius(Double lat, Double lon, LocationPattern location) {
        if (location.getLatitude() == null || location.getLongitude() == null) {
            return false;
        }
        
        double distance = calculateDistance(
            lat, lon, 
            location.getLatitude(), 
            location.getLongitude()
        );
        
        return distance <= (location.getRadius() != null ? location.getRadius() : 10);
    }
    
    /**
     * 두 지점 간 거리 계산
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
     * 리소스 접근이 정상적인지 확인
     */
    public boolean isNormalResourceAccess(String resource, Integer accessCount) {
        // 자주 접근하는 리소스인지 확인
        if (!frequentlyAccessedResources.contains(resource)) {
            return false;
        }
        
        // 접근 빈도가 정상 범위인지 확인
        Integer normalFrequency = resourceAccessFrequency.get(resource);
        if (normalFrequency != null && accessCount > normalFrequency * 3) {
            return false; // 평소보다 3배 이상 많음
        }
        
        return true;
    }
    
    /**
     * 데이터 접근량이 정상적인지 확인
     */
    public boolean isNormalDataVolume(Long dataVolume) {
        if (maxDataVolumePerSession == null) {
            return true;
        }
        return dataVolume <= maxDataVolumePerSession * 1.5; // 50% 여유
    }
}